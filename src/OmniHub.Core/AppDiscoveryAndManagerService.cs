using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Win32;
using OmniCore.Engine;

namespace OmniHub.Core;

public enum ManagedProductId
{
    LogicFlow = 0,
    AeonBrowser = 1
}

public enum ProductInstallState
{
    NotInstalled = 0,
    InstallerAvailable = 1,
    Installed = 2
}

public enum ManifestVerificationStatus
{
    Verified = 0,
    NetworkError = 1,
    InvalidSignature = 2,
    ProductMismatch = 3,
    UntrustedDownloadUrl = 4,
    InvalidChecksumFormat = 5
}

public sealed record DiscoveredProductStatus(
    ManagedProductId Product,
    string DisplayName,
    string ProductSlug,
    ProductInstallState State,
    string Version,
    string Channel,
    string? ExecutablePath,
    string? CliExecutablePath,
    string? InstallerPath,
    string? ExecutableSha256,
    long? ExecutableSizeBytes,
    bool IsRunning,
    int[] RunningProcessIds,
    string DiscoverySource);

public sealed record ProductUpdateCheckOutcome(
    ManagedProductId Product,
    string Channel,
    ManifestVerificationStatus VerificationStatus,
    bool UpdateAvailable,
    string InstalledVersion,
    string? RemoteVersion,
    VerifiedManifestData? Manifest,
    string Message);

public sealed record StagedUpdateArtifact(
    ManagedProductId Product,
    string Version,
    string StagedFilePath,
    string VerifiedSha256,
    long SizeBytes);

public sealed record AppLifecycleActionResult(
    bool Success,
    ManagedProductId Product,
    string Action,
    string Message,
    string? TargetPath = null,
    int? ProcessId = null);

public sealed record AppRepairReport(
    bool IntegrityValid,
    bool RepairTriggered,
    ManagedProductId Product,
    string? CheckedBinaryPath,
    string? ComputedSha256,
    string? ExpectedSha256,
    string Message);

public sealed class AppDiscoveryOptions
{
    public string? ProgramFilesOverride { get; init; }
    public string? LocalAppDataOverride { get; init; }
    public string? WorkspaceRootOverride { get; init; }
    public string? StagingRootOverride { get; init; }
    public string UpdateServerBaseUrl { get; init; } = OmniHubBrandConstants.ApiBaseUrl;
    public string? PublicKeyPemOverride { get; init; }
    public HttpClient? HttpClient { get; init; }
    public Func<string, string, string?>? RegistryReader { get; init; }
    public Func<string, int[]>? ProcessDetector { get; init; }
    public Func<ProcessStartInfo, int?>? ProcessLauncher { get; init; }
    public OmniHubSettingsService? SettingsService { get; init; }
    public ILogger<AppDiscoveryAndManagerService>? Logger { get; init; }
}

/// <summary>
/// Discovers, verifies, updates, repairs, and launches DelgadoLogic desktop applications
/// (LogicFlow and Aeon Browser) with fail-closed Ed25519 + SHA-256 verification.
/// </summary>
public sealed class AppDiscoveryAndManagerService : IDisposable
{
    private static readonly ConcurrentDictionary<string, (long Length, long LastWriteTicks, string Sha256)> HashCache = new(StringComparer.OrdinalIgnoreCase);

    private readonly AppDiscoveryOptions _options;
    private readonly ILogger<AppDiscoveryAndManagerService> _logger;
    private readonly HttpClient _http;
    private readonly bool _ownsHttp;
    private readonly OmniHubSettingsService _settings;

    public AppDiscoveryAndManagerService(AppDiscoveryOptions? options = null)
    {
        _options = options ?? new AppDiscoveryOptions();
        _logger = _options.Logger ?? NullLogger<AppDiscoveryAndManagerService>.Instance;
        _settings = _options.SettingsService ?? new OmniHubSettingsService();

        if (_options.HttpClient is not null)
        {
            _http = _options.HttpClient;
            _ownsHttp = false;
        }
        else
        {
            _http = new HttpClient
            {
                Timeout = TimeSpan.FromSeconds(30),
                DefaultRequestHeaders =
                {
                    { "User-Agent", $"DelgadoLogic-OmniHub/{OmniHubBrandConstants.Version} (Windows; x64)" },
                    { "Accept", "application/json" }
                }
            };
            _ownsHttp = true;
        }
    }

    public string StagingRoot => !string.IsNullOrWhiteSpace(_options.StagingRootOverride)
        ? _options.StagingRootOverride!
        : Path.Combine(EffectiveLocalAppData, "DelgadoLogic", "OmniHub", "Staging");

    private string EffectiveProgramFiles => !string.IsNullOrWhiteSpace(_options.ProgramFilesOverride)
        ? _options.ProgramFilesOverride!
        : Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);

    private string EffectiveLocalAppData => !string.IsNullOrWhiteSpace(_options.LocalAppDataOverride)
        ? _options.LocalAppDataOverride!
        : Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

    private string? EffectiveWorkspaceRoot => !string.IsNullOrWhiteSpace(_options.WorkspaceRootOverride)
        ? _options.WorkspaceRootOverride
        : TryResolveWorkspaceRoot();

    public static string GetProductSlug(ManagedProductId product) => product switch
    {
        ManagedProductId.LogicFlow => "logicflow",
        ManagedProductId.AeonBrowser => "aeon",
        _ => throw new ArgumentOutOfRangeException(nameof(product), product, "Unsupported product.")
    };

    public static string GetDisplayName(ManagedProductId product) => product switch
    {
        ManagedProductId.LogicFlow => "LogicFlow",
        ManagedProductId.AeonBrowser => "Aeon Browser",
        _ => product.ToString()
    };

    public string GetChannel(ManagedProductId product)
    {
        var s = _settings.Load();
        return product == ManagedProductId.LogicFlow
            ? OmniHubSettingsService.NormalizeChannel(s.LogicFlowChannel)
            : OmniHubSettingsService.NormalizeChannel(s.AeonChannel);
    }

    public void SetChannel(ManagedProductId product, string channel)
    {
        var normalized = OmniHubSettingsService.NormalizeChannel(channel);
        var s = _settings.Load();
        if (product == ManagedProductId.LogicFlow)
            s.LogicFlowChannel = normalized;
        else
            s.AeonChannel = normalized;
        _settings.Save(s);
    }

    public async Task<IReadOnlyList<DiscoveredProductStatus>> DiscoverAllAsync(CancellationToken ct = default)
    {
        var lf = await DiscoverProductAsync(ManagedProductId.LogicFlow, ct).ConfigureAwait(false);
        var aeon = await DiscoverProductAsync(ManagedProductId.AeonBrowser, ct).ConfigureAwait(false);
        return [lf, aeon];
    }

    public async Task<DiscoveredProductStatus> DiscoverProductAsync(ManagedProductId product, CancellationToken ct = default)
    {
        return product switch
        {
            ManagedProductId.LogicFlow => await DiscoverLogicFlowAsync(ct).ConfigureAwait(false),
            ManagedProductId.AeonBrowser => await DiscoverAeonBrowserAsync(ct).ConfigureAwait(false),
            _ => throw new ArgumentOutOfRangeException(nameof(product))
        };
    }

    /// <summary>
    /// Queries https://api.delgadologic.tech/v1/update/{product}/{channel}, verifies canonical sorted-JSON
    /// Ed25519 signature via OmniCore.Engine.AutoUpdateEngine, and enforces HTTPS + 64-hex SHA-256 fail-closed.
    /// </summary>
    public async Task<ProductUpdateCheckOutcome> CheckForUpdateAsync(
        ManagedProductId product,
        string? channelOverride = null,
        CancellationToken ct = default)
    {
        var discovered = await DiscoverProductAsync(product, ct).ConfigureAwait(false);
        var channel = string.IsNullOrWhiteSpace(channelOverride)
            ? discovered.Channel
            : OmniHubSettingsService.NormalizeChannel(channelOverride);
        var slug = GetProductSlug(product);
        var url = $"{_options.UpdateServerBaseUrl.TrimEnd('/')}/v1/update/{slug}/{channel}";

        try
        {
            using var response = await _http.GetAsync(url, ct).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                return new ProductUpdateCheckOutcome(
                    product,
                    channel,
                    ManifestVerificationStatus.NetworkError,
                    false,
                    discovered.Version,
                    null,
                    null,
                    $"Update server returned HTTP {(int)response.StatusCode}.");
            }

            var rawEnvelope = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            if (!AutoUpdateEngine.TryParseAndVerifyEnvelope(rawEnvelope, _options.PublicKeyPemOverride, out var manifest, out _) ||
                manifest is null)
            {
                _logger.LogError("[OmniHub.Update] Ed25519 signature verification failed for {Product}/{Channel}.", slug, channel);
                return new ProductUpdateCheckOutcome(
                    product,
                    channel,
                    ManifestVerificationStatus.InvalidSignature,
                    false,
                    discovered.Version,
                    null,
                    null,
                    "Ed25519 signature verification failed — tampered or untrusted update manifest rejected.");
            }

            if (!string.IsNullOrWhiteSpace(manifest.Product) &&
                !string.Equals(manifest.Product, slug, StringComparison.OrdinalIgnoreCase) &&
                !(product == ManagedProductId.AeonBrowser && string.Equals(manifest.Product, "aeonbrowser", StringComparison.OrdinalIgnoreCase)))
            {
                return new ProductUpdateCheckOutcome(
                    product,
                    channel,
                    ManifestVerificationStatus.ProductMismatch,
                    false,
                    discovered.Version,
                    manifest.Version,
                    null,
                    $"Manifest product '{manifest.Product}' does not match expected '{slug}'.");
            }

            bool isNewer = !string.Equals(manifest.Status, "no_update", StringComparison.OrdinalIgnoreCase) &&
                           (discovered.State == ProductInstallState.NotInstalled || IsNewerVersion(manifest.Version, discovered.Version));

            if (isNewer)
            {
                if (!AutoUpdateEngine.IsTrustedHttpsUrl(manifest.DownloadUrl))
                {
                    return new ProductUpdateCheckOutcome(
                        product,
                        channel,
                        ManifestVerificationStatus.UntrustedDownloadUrl,
                        false,
                        discovered.Version,
                        manifest.Version,
                        null,
                        "Manifest download_url rejected: HTTPS transport is strictly required.");
                }

                if (!AutoUpdateEngine.IsValidSha256Hex(manifest.Sha256))
                {
                    return new ProductUpdateCheckOutcome(
                        product,
                        channel,
                        ManifestVerificationStatus.InvalidChecksumFormat,
                        false,
                        discovered.Version,
                        manifest.Version,
                        null,
                        "Manifest sha256 rejected: valid 64-character hex digest is strictly required.");
                }
            }

            var msg = isNewer
                ? $"Verified {GetDisplayName(product)} v{manifest.Version} ({channel}) ready via Ed25519."
                : $"{GetDisplayName(product)} v{discovered.Version} is up to date on {channel}.";

            return new ProductUpdateCheckOutcome(
                product,
                channel,
                ManifestVerificationStatus.Verified,
                isNewer,
                discovered.Version,
                manifest.Version,
                manifest,
                msg);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[OmniHub.Update] Update check failed for {Product}/{Channel}.", slug, channel);
            return new ProductUpdateCheckOutcome(
                product,
                channel,
                ManifestVerificationStatus.NetworkError,
                false,
                discovered.Version,
                null,
                null,
                $"Could not reach update endpoint: {ex.Message}");
        }
    }

    /// <summary>
    /// Downloads an Ed25519-verified installer package into staging and verifies its SHA-256 before promotion.
    /// </summary>
    public async Task<StagedUpdateArtifact> DownloadAndStageUpdateAsync(
        ManagedProductId product,
        VerifiedManifestData manifest,
        IProgress<double>? progress = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(manifest);

        if (!AutoUpdateEngine.IsTrustedHttpsUrl(manifest.DownloadUrl))
            throw new SecurityException("Refusing to download update over non-HTTPS URL.");
        if (!AutoUpdateEngine.IsValidSha256Hex(manifest.Sha256))
            throw new SecurityException("Refusing to download update without a valid 64-char SHA-256 digest.");

        var slug = GetProductSlug(product);
        var safeVer = SanitizePathSegment(manifest.Version);
        var targetDir = Path.Combine(StagingRoot, slug, safeVer);
        Directory.CreateDirectory(targetDir);

        var uri = new Uri(manifest.DownloadUrl!);
        var fileName = Path.GetFileName(uri.LocalPath);
        if (string.IsNullOrWhiteSpace(fileName) || !fileName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
        {
            fileName = $"{GetDisplayName(product).Replace(" ", "")}Setup_{safeVer}.exe";
        }

        var finalPath = Path.Combine(targetDir, fileName);
        if (File.Exists(finalPath) && await AutoUpdateEngine.VerifyFileSha256Async(finalPath, manifest.Sha256, ct).ConfigureAwait(false))
        {
            progress?.Report(1.0);
            return new StagedUpdateArtifact(product, manifest.Version, finalPath, manifest.Sha256!.ToUpperInvariant(), new FileInfo(finalPath).Length);
        }

        var partPath = finalPath + ".part";
        try
        {
            using var response = await _http.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();

            var totalBytes = response.Content.Headers.ContentLength ?? manifest.SizeBytes ?? -1L;
            await using (var netStream = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false))
            await using (var fileStream = new FileStream(partPath, FileMode.Create, FileAccess.Write, FileShare.None, 81920, useAsync: true))
            {
                var buffer = new byte[81920];
                long downloaded = 0;
                int read;
                while ((read = await netStream.ReadAsync(buffer, ct).ConfigureAwait(false)) > 0)
                {
                    await fileStream.WriteAsync(buffer.AsMemory(0, read), ct).ConfigureAwait(false);
                    downloaded += read;
                    if (totalBytes > 0)
                        progress?.Report(Math.Clamp((double)downloaded / totalBytes, 0.0, 0.99));
                }
            }

            if (!await AutoUpdateEngine.VerifyFileSha256Async(partPath, manifest.Sha256, ct).ConfigureAwait(false))
            {
                File.Delete(partPath);
                throw new CryptographicException($"SHA-256 verification failed for downloaded {GetDisplayName(product)} installer.");
            }

            File.Move(partPath, finalPath, overwrite: true);
            progress?.Report(1.0);
            var fi = new FileInfo(finalPath);
            return new StagedUpdateArtifact(product, manifest.Version, finalPath, manifest.Sha256!.ToUpperInvariant(), fi.Length);
        }
        catch
        {
            try { if (File.Exists(partPath)) File.Delete(partPath); } catch { }
            throw;
        }
    }

    /// <summary>
    /// Installs or updates the target product using a verified staged package or local workspace setup artifact.
    /// </summary>
    public async Task<AppLifecycleActionResult> InstallOrUpdateAsync(
        ManagedProductId product,
        bool silent = true,
        IProgress<double>? progress = null,
        CancellationToken ct = default)
    {
        var check = await CheckForUpdateAsync(product, ct: ct).ConfigureAwait(false);
        string? installerToRun = null;

        if (check.VerificationStatus == ManifestVerificationStatus.Verified &&
            check.UpdateAvailable &&
            check.Manifest is not null)
        {
            var staged = await DownloadAndStageUpdateAsync(product, check.Manifest, progress, ct).ConfigureAwait(false);
            installerToRun = staged.StagedFilePath;
        }
        else
        {
            var discovered = await DiscoverProductAsync(product, ct).ConfigureAwait(false);
            if (!string.IsNullOrWhiteSpace(discovered.InstallerPath) && File.Exists(discovered.InstallerPath))
            {
                if (product == ManagedProductId.LogicFlow &&
                    new FileInfo(discovered.InstallerPath).Length == OmniHubBrandConstants.LogicFlowSetupSizeBytes &&
                    !await AutoUpdateEngine.VerifyFileSha256Async(discovered.InstallerPath, OmniHubBrandConstants.LogicFlowSetupSha256, ct).ConfigureAwait(false))
                {
                    return new AppLifecycleActionResult(
                        false,
                        product,
                        "Install",
                        "Local LogicFlowSetup.exe failed pinned SHA-256 verification.");
                }
                installerToRun = discovered.InstallerPath;
            }
        }

        if (string.IsNullOrWhiteSpace(installerToRun) || !File.Exists(installerToRun))
        {
            return new AppLifecycleActionResult(
                false,
                product,
                "Install",
                check.VerificationStatus == ManifestVerificationStatus.Verified && !check.UpdateAvailable
                    ? $"{GetDisplayName(product)} is already up to date (v{check.InstalledVersion})."
                    : $"No verified installer available ({check.Message}).");
        }

        var args = silent ? "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART" : "";
        var pid = StartProcess(installerToRun, args);
        return new AppLifecycleActionResult(
            pid.HasValue,
            product,
            "Install",
            pid.HasValue
                ? $"Launched verified installer '{Path.GetFileName(installerToRun)}' (PID {pid.Value})."
                : $"Failed to start installer '{installerToRun}'.",
            installerToRun,
            pid);
    }

    /// <summary>
    /// Verifies installed binary integrity (SHA-256 + non-zero PE check) and optionally launches repair installer.
    /// </summary>
    public async Task<AppRepairReport> RepairAsync(
        ManagedProductId product,
        string? expectedSha256 = null,
        bool launchInstallerOnFailure = true,
        bool silent = true,
        CancellationToken ct = default)
    {
        var discovered = await DiscoverProductAsync(product, ct).ConfigureAwait(false);
        var binaryToCheck = discovered.ExecutablePath ?? discovered.InstallerPath;

        if (string.IsNullOrWhiteSpace(binaryToCheck) || !File.Exists(binaryToCheck))
        {
            bool triggered = false;
            if (launchInstallerOnFailure && !string.IsNullOrWhiteSpace(discovered.InstallerPath) && File.Exists(discovered.InstallerPath))
            {
                triggered = StartProcess(discovered.InstallerPath, silent ? "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART" : "").HasValue;
            }

            return new AppRepairReport(
                false,
                triggered,
                product,
                binaryToCheck,
                null,
                expectedSha256,
                triggered
                    ? $"{GetDisplayName(product)} binary missing — repair installer launched."
                    : $"{GetDisplayName(product)} binary not found on disk.");
        }

        var computed = await ComputeFileSha256CachedAsync(binaryToCheck, ct).ConfigureAwait(false);
        var fi = new FileInfo(binaryToCheck);
        bool valid = fi.Length > 4096 && HasValidMzHeader(binaryToCheck);

        // If checking LogicFlowSetup.exe against canonical v1.0.0 baseline
        if (string.IsNullOrWhiteSpace(expectedSha256) &&
            product == ManagedProductId.LogicFlow &&
            string.Equals(Path.GetFileName(binaryToCheck), "LogicFlowSetup.exe", StringComparison.OrdinalIgnoreCase) &&
            fi.Length == OmniHubBrandConstants.LogicFlowSetupSizeBytes)
        {
            expectedSha256 = OmniHubBrandConstants.LogicFlowSetupSha256;
        }

        if (valid && !string.IsNullOrWhiteSpace(expectedSha256))
        {
            valid = await AutoUpdateEngine.VerifyFileSha256Async(binaryToCheck, expectedSha256, ct).ConfigureAwait(false);
        }

        bool repairLaunched = false;
        if (!valid && launchInstallerOnFailure && !string.IsNullOrWhiteSpace(discovered.InstallerPath) && File.Exists(discovered.InstallerPath))
        {
            repairLaunched = StartProcess(discovered.InstallerPath, silent ? "/VERYSILENT /SUPPRESSMSGBOXES /NORESTART" : "").HasValue;
        }

        return new AppRepairReport(
            valid,
            repairLaunched,
            product,
            binaryToCheck,
            computed,
            expectedSha256,
            valid
                ? $"{GetDisplayName(product)} binary verified intact (SHA-256: {computed?[..16]}…)."
                : repairLaunched
                    ? $"Integrity mismatch detected on {Path.GetFileName(binaryToCheck)} — repair installer started."
                    : $"Integrity verification failed for {Path.GetFileName(binaryToCheck)}.");
    }

    public async Task<AppLifecycleActionResult> LaunchProductAsync(
        ManagedProductId product,
        bool preferCli = false,
        string? arguments = null,
        CancellationToken ct = default)
    {
        var discovered = await DiscoverProductAsync(product, ct).ConfigureAwait(false);
        var target = preferCli && !string.IsNullOrWhiteSpace(discovered.CliExecutablePath)
            ? discovered.CliExecutablePath
            : discovered.ExecutablePath;

        if (string.IsNullOrWhiteSpace(target) || !File.Exists(target))
        {
            return new AppLifecycleActionResult(
                false,
                product,
                preferCli ? "LaunchCli" : "Launch",
                $"{GetDisplayName(product)} executable is not installed yet.");
        }

        var pid = StartProcess(target, arguments ?? "");
        return new AppLifecycleActionResult(
            pid.HasValue,
            product,
            preferCli ? "LaunchCli" : "Launch",
            pid.HasValue
                ? $"Launched {Path.GetFileName(target)} (PID {pid.Value})."
                : $"Failed to launch {Path.GetFileName(target)}.",
            target,
            pid);
    }

    // ─── Discovery Implementations ───────────────────────────────────────────

    private async Task<DiscoveredProductStatus> DiscoverLogicFlowAsync(CancellationToken ct)
    {
        var channel = GetChannel(ManagedProductId.LogicFlow);
        string? exePath = null;
        string? cliPath = null;
        string? installerPath = null;
        string? regVersion = null;
        string source = "NotInstalled";

        // 1. Standard Program Files location
        var pfDir = Path.Combine(EffectiveProgramFiles, "DelgadoLogic", "LogicFlow");
        var pfExe = Path.Combine(pfDir, "LogicFlow.exe");
        if (File.Exists(pfExe))
        {
            exePath = pfExe;
            var pfCli = Path.Combine(pfDir, "lf.exe");
            if (File.Exists(pfCli)) cliPath = pfCli;
            source = "ProgramFiles";
        }

        // 2. Registry Uninstall entries (HKLM & HKCU)
        foreach (var regKey in new[]
        {
            @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\LogicFlow",
            @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\LogicFlow_is1",
            @"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\LogicFlow"
        })
        {
            var installLoc = ReadRegistryString(regKey, "InstallLocation");
            regVersion ??= ReadRegistryString(regKey, "DisplayVersion");

            if (exePath is null && !string.IsNullOrWhiteSpace(installLoc))
            {
                var candidate = Path.Combine(installLoc.Trim('"'), "LogicFlow.exe");
                if (File.Exists(candidate))
                {
                    exePath = candidate;
                    var candCli = Path.Combine(installLoc.Trim('"'), "lf.exe");
                    if (File.Exists(candCli)) cliPath = candCli;
                    source = "Registry";
                }
            }
        }

        // 3. LocalAppData fallback
        if (exePath is null)
        {
            var localDir = Path.Combine(EffectiveLocalAppData, "Programs", "LogicFlow");
            var localExe = Path.Combine(localDir, "LogicFlow.exe");
            if (File.Exists(localExe))
            {
                exePath = localExe;
                var localCli = Path.Combine(localDir, "lf.exe");
                if (File.Exists(localCli)) cliPath = localCli;
                source = "LocalAppData";
            }
        }

        // 4. Workspace build & dist fallbacks
        var ws = EffectiveWorkspaceRoot;
        if (!string.IsNullOrWhiteSpace(ws))
        {
            var distSetup = Path.Combine(ws, "Products", "LogicFlow", "dist", "LogicFlowSetup.exe");
            if (File.Exists(distSetup))
                installerPath = distSetup;

            if (exePath is null)
            {
                foreach (var rel in new[]
                {
                    Path.Combine("Products", "LogicFlow", "src", "LogicFlow.Dashboard", "bin", "Release", "net8.0-windows", "win-x64", "LogicFlow.exe"),
                    Path.Combine("Products", "LogicFlow", "src", "LogicFlow.Dashboard", "bin", "Release", "net8.0-windows", "LogicFlow.exe")
                })
                {
                    var cand = Path.Combine(ws, rel);
                    if (File.Exists(cand))
                    {
                        exePath = cand;
                        source = "WorkspaceBuild";
                        break;
                    }
                }
            }

            if (cliPath is null)
            {
                foreach (var rel in new[]
                {
                    Path.Combine("Products", "LogicFlow", "src", "LogicFlow.CLI", "bin", "Release", "net8.0-windows", "win-x64", "lf.exe"),
                    Path.Combine("Products", "LogicFlow", "src", "LogicFlow.CLI", "bin", "Release", "net8.0-windows", "lf.exe")
                })
                {
                    var cand = Path.Combine(ws, rel);
                    if (File.Exists(cand))
                    {
                        cliPath = cand;
                        break;
                    }
                }
            }
        }

        // Also check OmniHub staging directory for downloaded installer
        installerPath ??= FindLatestStagedInstaller("logicflow");

        var pids = DetectRunningPids("LogicFlow", "LogicFlowAgent");
        string version = ResolveBinaryVersion(exePath) ?? regVersion ?? OmniHubBrandConstants.LogicFlowBaselineVersion;

        string? hash = null;
        long? sizeBytes = null;
        ProductInstallState state;

        if (!string.IsNullOrWhiteSpace(exePath) && File.Exists(exePath))
        {
            state = ProductInstallState.Installed;
            sizeBytes = new FileInfo(exePath).Length;
            hash = await ComputeFileSha256CachedAsync(exePath, ct).ConfigureAwait(false);
        }
        else if (!string.IsNullOrWhiteSpace(installerPath) && File.Exists(installerPath))
        {
            state = ProductInstallState.InstallerAvailable;
            source = "WorkspaceInstaller";
            sizeBytes = new FileInfo(installerPath).Length;
            hash = await ComputeFileSha256CachedAsync(installerPath, ct).ConfigureAwait(false);
        }
        else
        {
            state = ProductInstallState.NotInstalled;
        }

        return new DiscoveredProductStatus(
            ManagedProductId.LogicFlow,
            "LogicFlow",
            "logicflow",
            state,
            version,
            channel,
            exePath,
            cliPath,
            installerPath,
            hash,
            sizeBytes,
            pids.Length > 0,
            pids,
            source);
    }

    private async Task<DiscoveredProductStatus> DiscoverAeonBrowserAsync(CancellationToken ct)
    {
        var channel = GetChannel(ManagedProductId.AeonBrowser);
        string? exePath = null;
        string? installerPath = null;
        string? regVersion = null;
        string source = "NotInstalled";

        // 1. Program Files
        var pfExe = Path.Combine(EffectiveProgramFiles, "DelgadoLogic", "Aeon", "Aeon.exe");
        if (File.Exists(pfExe))
        {
            exePath = pfExe;
            source = "ProgramFiles";
        }

        // 2. LocalAppData\Aeon\Aeon.exe
        if (exePath is null)
        {
            var localExe = Path.Combine(EffectiveLocalAppData, "Aeon", "Aeon.exe");
            if (File.Exists(localExe))
            {
                exePath = localExe;
                source = "LocalAppData";
            }
        }

        // 3. Registry HKLM\SOFTWARE\DelgadoLogic\Aeon & HKCU
        foreach (var regKey in new[]
        {
            @"HKLM\SOFTWARE\DelgadoLogic\Aeon",
            @"HKCU\SOFTWARE\DelgadoLogic\Aeon"
        })
        {
            regVersion ??= ReadRegistryString(regKey, "Version") ?? ReadRegistryString(regKey, "DisplayVersion");
            if (exePath is null)
            {
                var regExe = ReadRegistryString(regKey, "ExecutablePath");
                var regDir = ReadRegistryString(regKey, "InstallPath") ?? ReadRegistryString(regKey, "InstallLocation");

                if (!string.IsNullOrWhiteSpace(regExe) && File.Exists(regExe.Trim('"')))
                {
                    exePath = regExe.Trim('"');
                    source = "Registry";
                }
                else if (!string.IsNullOrWhiteSpace(regDir))
                {
                    var cand = Path.Combine(regDir.Trim('"'), "Aeon.exe");
                    if (File.Exists(cand))
                    {
                        exePath = cand;
                        source = "Registry";
                    }
                }
            }
        }

        // 4. Workspace fallback: Products\AeonBrowser\publish\Pro\Aeon.exe
        var ws = EffectiveWorkspaceRoot;
        if (!string.IsNullOrWhiteSpace(ws))
        {
            var wsExe = Path.Combine(ws, "Products", "AeonBrowser", "publish", "Pro", "Aeon.exe");
            if (exePath is null && File.Exists(wsExe))
            {
                exePath = wsExe;
                source = "WorkspacePublish";
            }

            var wsInstaller = Path.Combine(ws, "Products", "AeonBrowser", "dist", "AeonSetup.exe");
            if (File.Exists(wsInstaller))
                installerPath = wsInstaller;
        }

        installerPath ??= FindLatestStagedInstaller("aeon");

        var pids = DetectRunningPids("Aeon");
        var version = ResolveBinaryVersion(exePath) ?? regVersion ?? OmniHubBrandConstants.AeonBaselineVersion;

        string? hash = null;
        long? sizeBytes = null;
        ProductInstallState state;

        if (!string.IsNullOrWhiteSpace(exePath) && File.Exists(exePath))
        {
            state = ProductInstallState.Installed;
            sizeBytes = new FileInfo(exePath).Length;
            hash = await ComputeFileSha256CachedAsync(exePath, ct).ConfigureAwait(false);
        }
        else if (!string.IsNullOrWhiteSpace(installerPath) && File.Exists(installerPath))
        {
            state = ProductInstallState.InstallerAvailable;
            source = "StagedInstaller";
            sizeBytes = new FileInfo(installerPath).Length;
            hash = await ComputeFileSha256CachedAsync(installerPath, ct).ConfigureAwait(false);
        }
        else
        {
            state = ProductInstallState.NotInstalled;
        }

        return new DiscoveredProductStatus(
            ManagedProductId.AeonBrowser,
            "Aeon Browser",
            "aeon",
            state,
            version,
            channel,
            exePath,
            null,
            installerPath,
            hash,
            sizeBytes,
            pids.Length > 0,
            pids,
            source);
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────

    public static async Task<string?> ComputeFileSha256CachedAsync(string filePath, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
            return null;

        var fi = new FileInfo(filePath);
        var fullPath = fi.FullName;
        var len = fi.Length;
        var ticks = fi.LastWriteTimeUtc.Ticks;

        if (HashCache.TryGetValue(fullPath, out var cached) &&
            cached.Length == len &&
            cached.LastWriteTicks == ticks)
        {
            return cached.Sha256;
        }

        await using var fs = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 81920, useAsync: true);
        var hashBytes = await SHA256.HashDataAsync(fs, ct).ConfigureAwait(false);
        var hex = Convert.ToHexString(hashBytes);
        HashCache[fullPath] = (len, ticks, hex);
        return hex;
    }

    private string? ReadRegistryString(string fullKeyPath, string valueName)
    {
        if (_options.RegistryReader is not null)
            return _options.RegistryReader(fullKeyPath, valueName);

        try
        {
            var slash = fullKeyPath.IndexOf('\\');
            if (slash <= 0) return null;
            var hive = fullKeyPath[..slash];
            var sub = fullKeyPath[(slash + 1)..];
            var root = hive.Equals("HKLM", StringComparison.OrdinalIgnoreCase)
                ? Registry.LocalMachine
                : Registry.CurrentUser;
            using var key = root.OpenSubKey(sub, writable: false);
            return key?.GetValue(valueName)?.ToString();
        }
        catch
        {
            return null;
        }
    }

    private int[] DetectRunningPids(params string[] processNames)
    {
        var list = new List<int>();
        foreach (var name in processNames)
        {
            try
            {
                if (_options.ProcessDetector is not null)
                {
                    list.AddRange(_options.ProcessDetector(name));
                    continue;
                }

                var procs = Process.GetProcessesByName(name);
                foreach (var p in procs)
                {
                    try { list.Add(p.Id); }
                    finally { p.Dispose(); }
                }
            }
            catch
            {
                // Ignore transient process table errors
            }
        }
        return list.Distinct().ToArray();
    }

    private int? StartProcess(string filePath, string arguments)
    {
        var psi = new ProcessStartInfo
        {
            FileName = filePath,
            Arguments = arguments,
            WorkingDirectory = Path.GetDirectoryName(filePath) ?? Environment.CurrentDirectory,
            UseShellExecute = false
        };

        if (_options.ProcessLauncher is not null)
            return _options.ProcessLauncher(psi);

        try
        {
            using var proc = Process.Start(psi);
            return proc?.Id;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[OmniHub] Failed to launch {File}.", filePath);
            return null;
        }
    }

    private string? FindLatestStagedInstaller(string slug)
    {
        try
        {
            var dir = Path.Combine(StagingRoot, slug);
            if (!Directory.Exists(dir)) return null;
            return Directory.EnumerateFiles(dir, "*.exe", SearchOption.AllDirectories)
                .OrderByDescending(File.GetLastWriteTimeUtc)
                .FirstOrDefault();
        }
        catch
        {
            return null;
        }
    }

    private static string? ResolveBinaryVersion(string? exePath)
    {
        if (string.IsNullOrWhiteSpace(exePath) || !File.Exists(exePath))
            return null;

        try
        {
            var info = FileVersionInfo.GetVersionInfo(exePath);
            var raw = !string.IsNullOrWhiteSpace(info.ProductVersion)
                ? info.ProductVersion
                : info.FileVersion;
            if (string.IsNullOrWhiteSpace(raw))
                return null;

            // Strip git commit suffix (+abcdef) if present
            var plusIdx = raw.IndexOf('+');
            if (plusIdx > 0)
                raw = raw[..plusIdx];

            raw = raw.Trim();
            if (raw is "0.0.0.0" or "0.0.0")
                return null;

            if (Version.TryParse(raw, out var parsed))
            {
                return parsed.Revision > 0
                    ? $"{parsed.Major}.{parsed.Minor}.{parsed.Build}.{parsed.Revision}"
                    : parsed.Build >= 0
                        ? $"{parsed.Major}.{parsed.Minor}.{parsed.Build}"
                        : $"{parsed.Major}.{parsed.Minor}.0";
            }
            return raw;
        }
        catch
        {
            return null;
        }
    }

    private static bool HasValidMzHeader(string filePath)
    {
        try
        {
            Span<byte> header = stackalloc byte[2];
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            if (fs.Read(header) < 2) return false;
            return header[0] == (byte)'M' && header[1] == (byte)'Z';
        }
        catch
        {
            return false;
        }
    }

    private static bool IsNewerVersion(string remoteVersion, string installedVersion)
    {
        var rClean = remoteVersion.Trim().TrimStart('v', 'V');
        var lClean = installedVersion.Trim().TrimStart('v', 'V');
        var rDash = rClean.IndexOf('-');
        var lDash = lClean.IndexOf('-');
        var rCore = rDash > 0 ? rClean[..rDash] : rClean;
        var lCore = lDash > 0 ? lClean[..lDash] : lClean;

        if (!Version.TryParse(rCore, out var rv) || !Version.TryParse(lCore, out var lv))
            return false;

        if (rv != lv)
            return rv > lv;

        // If numeric versions match, non-prerelease > prerelease, or newer beta > none if switching channel
        if (lDash > 0 && rDash < 0)
            return true;
        return false;
    }

    private static string SanitizePathSegment(string input)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var chars = input.Select(c => invalid.Contains(c) ? '_' : c).ToArray();
        var result = new string(chars).Trim('.');
        return string.IsNullOrWhiteSpace(result) ? "latest" : result;
    }

    internal static string? TryResolveWorkspaceRoot()
    {
        try
        {
            var dir = new DirectoryInfo(AppContext.BaseDirectory);
            while (dir is not null)
            {
                if (Directory.Exists(Path.Combine(dir.FullName, "Products", "LogicFlow")) ||
                    Directory.Exists(Path.Combine(dir.FullName, "MasterPlans")))
                {
                    return dir.FullName;
                }
                dir = dir.Parent;
            }
        }
        catch
        {
            // Ignore traversal errors
        }
        return null;
    }

    public void Dispose()
    {
        if (_ownsHttp)
            _http.Dispose();
    }
}

public sealed class SecurityException : Exception
{
    public SecurityException(string message) : base(message) { }
}
