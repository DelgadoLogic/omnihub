using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using OmniCore.Engine;
using OmniHub.Core;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

namespace OmniHub.Tests;

public sealed class AppDiscoveryAndUpdateTests : IDisposable
{
    private static readonly byte[] Ed25519SpkiPrefix =
    [
        0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00
    ];

    private readonly string _tempRoot;
    private readonly string _programFilesDir;
    private readonly string _localAppDataDir;
    private readonly string _workspaceDir;
    private readonly string _stagingDir;
    private readonly string _settingsDir;

    public AppDiscoveryAndUpdateTests()
    {
        _tempRoot = Path.Combine(Path.GetTempPath(), $"omnihub_app_tests_{Guid.NewGuid():N}");
        _programFilesDir = Path.Combine(_tempRoot, "ProgramFiles");
        _localAppDataDir = Path.Combine(_tempRoot, "LocalAppData");
        _workspaceDir = Path.Combine(_tempRoot, "Workspace");
        _stagingDir = Path.Combine(_tempRoot, "Staging");
        _settingsDir = Path.Combine(_tempRoot, "Settings");

        Directory.CreateDirectory(_programFilesDir);
        Directory.CreateDirectory(_localAppDataDir);
        Directory.CreateDirectory(_workspaceDir);
        Directory.CreateDirectory(_stagingDir);
        Directory.CreateDirectory(_settingsDir);
    }

    [Fact]
    public async Task CheckForUpdateAsync_ValidEd25519CanonicalSortedEnvelope_VerifiesStableAndBetaChannels()
    {
        var (privKey, pubPem) = GenerateEd25519KeyPair();
        var dummyHash = Convert.ToHexString(SHA256.HashData("installer-v1.2.0"u8));

        // Deliberately emit unsorted JSON keys to prove canonical sorted-JSON Ed25519 verification
        var stableEnvelope = CreateSignedEnvelope(privKey, new Dictionary<string, object?>
        {
            ["version"] = "1.2.0",
            ["status"] = "update_available",
            ["sha256"] = dummyHash,
            ["size_bytes"] = 1048576L,
            ["product"] = "logicflow",
            ["download_url"] = "https://releases.delgadologic.tech/logicflow/LogicFlowSetup_1.2.0.exe",
            ["channel"] = "stable",
            ["release_notes"] = "HyperStore throughput improvements"
        });

        var betaEnvelope = CreateSignedEnvelope(privKey, new Dictionary<string, object?>
        {
            ["status"] = "update_available",
            ["version"] = "0.23.0",
            ["product"] = "aeon",
            ["channel"] = "beta",
            ["download_url"] = "https://releases.delgadologic.tech/aeon/AeonSetup_0.23.0_beta.exe",
            ["sha256"] = dummyHash,
            ["size_bytes"] = 2097152L
        });

        using var http = CreateMockHttpClient(req =>
        {
            var path = req.RequestUri!.AbsolutePath;
            return path switch
            {
                "/v1/update/logicflow/stable" => JsonResponse(stableEnvelope),
                "/v1/update/aeon/beta" => JsonResponse(betaEnvelope),
                _ => new HttpResponseMessage(HttpStatusCode.NotFound)
            };
        });

        using var svc = CreateService(http, pubPem);

        var lfOutcome = await svc.CheckForUpdateAsync(ManagedProductId.LogicFlow, "stable");
        Assert.Equal(ManifestVerificationStatus.Verified, lfOutcome.VerificationStatus);
        Assert.True(lfOutcome.UpdateAvailable);
        Assert.Equal("1.2.0", lfOutcome.RemoteVersion);
        Assert.NotNull(lfOutcome.Manifest);
        Assert.Equal(dummyHash, lfOutcome.Manifest!.Sha256, ignoreCase: true);

        var aeonOutcome = await svc.CheckForUpdateAsync(ManagedProductId.AeonBrowser, "beta");
        Assert.Equal(ManifestVerificationStatus.Verified, aeonOutcome.VerificationStatus);
        Assert.True(aeonOutcome.UpdateAvailable);
        Assert.Equal("0.23.0", aeonOutcome.RemoteVersion);
        Assert.Equal("beta", aeonOutcome.Channel);
    }

    [Fact]
    public async Task CheckForUpdateAsync_TamperedVersionAfterSigning_RejectsWithInvalidSignature()
    {
        var (privKey, pubPem) = GenerateEd25519KeyPair();
        var dummyHash = Convert.ToHexString(SHA256.HashData("installer"u8));

        var signedEnvelope = CreateSignedEnvelope(privKey, new Dictionary<string, object?>
        {
            ["product"] = "logicflow",
            ["channel"] = "stable",
            ["version"] = "1.1.0",
            ["status"] = "update_available",
            ["download_url"] = "https://releases.delgadologic.tech/logicflow/LogicFlowSetup_1.1.0.exe",
            ["sha256"] = dummyHash
        });

        // Tamper with version field after Ed25519 signature was generated
        var tamperedEnvelope = signedEnvelope.Replace("\"1.1.0\"", "\"9.9.9\"", StringComparison.Ordinal);

        using var http = CreateMockHttpClient(_ => JsonResponse(tamperedEnvelope));
        using var svc = CreateService(http, pubPem);

        var outcome = await svc.CheckForUpdateAsync(ManagedProductId.LogicFlow);
        Assert.Equal(ManifestVerificationStatus.InvalidSignature, outcome.VerificationStatus);
        Assert.False(outcome.UpdateAvailable);
        Assert.Null(outcome.Manifest);
    }

    [Fact]
    public async Task CheckForUpdateAsync_SignedByUntrustedEd25519Key_RejectsWithInvalidSignature()
    {
        var (attackerPrivKey, _) = GenerateEd25519KeyPair();
        var (_, pinnedTrustedPubPem) = GenerateEd25519KeyPair();
        var dummyHash = Convert.ToHexString(SHA256.HashData("payload"u8));

        var attackerEnvelope = CreateSignedEnvelope(attackerPrivKey, new Dictionary<string, object?>
        {
            ["product"] = "aeon",
            ["channel"] = "stable",
            ["version"] = "0.99.0",
            ["status"] = "update_available",
            ["download_url"] = "https://evil.example.com/AeonSetup.exe",
            ["sha256"] = dummyHash
        });

        using var http = CreateMockHttpClient(_ => JsonResponse(attackerEnvelope));
        using var svc = CreateService(http, pinnedTrustedPubPem);

        var outcome = await svc.CheckForUpdateAsync(ManagedProductId.AeonBrowser);
        Assert.Equal(ManifestVerificationStatus.InvalidSignature, outcome.VerificationStatus);
        Assert.False(outcome.UpdateAvailable);
    }

    [Fact]
    public async Task CheckForUpdateAsync_HttpDowngradeDownloadUrl_RejectsWithUntrustedDownloadUrl()
    {
        var (privKey, pubPem) = GenerateEd25519KeyPair();
        var dummyHash = Convert.ToHexString(SHA256.HashData("payload"u8));

        var insecureEnvelope = CreateSignedEnvelope(privKey, new Dictionary<string, object?>
        {
            ["product"] = "logicflow",
            ["channel"] = "stable",
            ["version"] = "1.5.0",
            ["status"] = "update_available",
            ["download_url"] = "http://releases.delgadologic.tech/logicflow/LogicFlowSetup.exe",
            ["sha256"] = dummyHash
        });

        using var http = CreateMockHttpClient(_ => JsonResponse(insecureEnvelope));
        using var svc = CreateService(http, pubPem);

        var outcome = await svc.CheckForUpdateAsync(ManagedProductId.LogicFlow);
        Assert.Equal(ManifestVerificationStatus.UntrustedDownloadUrl, outcome.VerificationStatus);
        Assert.False(outcome.UpdateAvailable);
        Assert.Null(outcome.Manifest);
    }

    [Fact]
    public async Task CheckForUpdateAsync_MalformedSha256Digest_RejectsWithInvalidChecksumFormat()
    {
        var (privKey, pubPem) = GenerateEd25519KeyPair();

        var badHashEnvelope = CreateSignedEnvelope(privKey, new Dictionary<string, object?>
        {
            ["product"] = "logicflow",
            ["channel"] = "stable",
            ["version"] = "1.5.0",
            ["status"] = "update_available",
            ["download_url"] = "https://releases.delgadologic.tech/logicflow/LogicFlowSetup.exe",
            ["sha256"] = "not-a-64-char-hex-sha256"
        });

        using var http = CreateMockHttpClient(_ => JsonResponse(badHashEnvelope));
        using var svc = CreateService(http, pubPem);

        var outcome = await svc.CheckForUpdateAsync(ManagedProductId.LogicFlow);
        Assert.Equal(ManifestVerificationStatus.InvalidChecksumFormat, outcome.VerificationStatus);
        Assert.False(outcome.UpdateAvailable);
    }

    [Fact]
    public async Task CheckForUpdateAsync_ProductSlugMismatch_RejectsWithProductMismatch()
    {
        var (privKey, pubPem) = GenerateEd25519KeyPair();
        var dummyHash = Convert.ToHexString(SHA256.HashData("payload"u8));

        // Signed valid Aeon manifest replayed onto the LogicFlow endpoint
        var crossProductEnvelope = CreateSignedEnvelope(privKey, new Dictionary<string, object?>
        {
            ["product"] = "aeon",
            ["channel"] = "stable",
            ["version"] = "2.0.0",
            ["status"] = "update_available",
            ["download_url"] = "https://releases.delgadologic.tech/aeon/AeonSetup.exe",
            ["sha256"] = dummyHash
        });

        using var http = CreateMockHttpClient(_ => JsonResponse(crossProductEnvelope));
        using var svc = CreateService(http, pubPem);

        var outcome = await svc.CheckForUpdateAsync(ManagedProductId.LogicFlow);
        Assert.Equal(ManifestVerificationStatus.ProductMismatch, outcome.VerificationStatus);
        Assert.False(outcome.UpdateAvailable);
    }

    [Fact]
    public async Task DownloadAndStageUpdateAsync_ValidPayload_VerifiesSha256AndStagesInstaller()
    {
        var binaryBytes = CreateSyntheticPeBinary(65536, 0x42);
        var expectedSha = Convert.ToHexString(SHA256.HashData(binaryBytes));

        using var http = CreateMockHttpClient(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(binaryBytes)
        });
        using var svc = CreateService(http, null);

        var manifest = new VerifiedManifestData(
            Product: "logicflow",
            Channel: "stable",
            Version: "1.3.0",
            Status: "update_available",
            DownloadUrl: "https://releases.delgadologic.tech/logicflow/LogicFlowSetup_1.3.0.exe",
            ReleaseNotes: "Verified release",
            Sha256: expectedSha,
            SizeBytes: binaryBytes.Length,
            Tag: "v1.3.0",
            IsCritical: false,
            ReleasedAt: DateTimeOffset.UtcNow,
            Signature: "sig");

        double lastProgress = 0;
        var progress = new Progress<double>(p => lastProgress = p);

        var staged = await svc.DownloadAndStageUpdateAsync(ManagedProductId.LogicFlow, manifest, progress);
        Assert.True(File.Exists(staged.StagedFilePath));
        Assert.Equal(binaryBytes.Length, staged.SizeBytes);
        Assert.Equal(expectedSha, staged.VerifiedSha256, ignoreCase: true);
        Assert.False(File.Exists(staged.StagedFilePath + ".part"));
        Assert.True(lastProgress >= 0.0);
    }

    [Fact]
    public async Task DownloadAndStageUpdateAsync_CorruptedPayload_ThrowsCryptographicExceptionAndDeletesPartFile()
    {
        var expectedBytes = CreateSyntheticPeBinary(32768, 0x11);
        var corruptedBytes = CreateSyntheticPeBinary(32768, 0x99);
        var expectedSha = Convert.ToHexString(SHA256.HashData(expectedBytes));

        using var http = CreateMockHttpClient(_ => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(corruptedBytes)
        });
        using var svc = CreateService(http, null);

        var manifest = new VerifiedManifestData(
            Product: "aeon",
            Channel: "stable",
            Version: "0.24.0",
            Status: "update_available",
            DownloadUrl: "https://releases.delgadologic.tech/aeon/AeonSetup_0.24.0.exe",
            ReleaseNotes: "Test",
            Sha256: expectedSha,
            SizeBytes: expectedBytes.Length,
            Tag: null,
            IsCritical: false,
            ReleasedAt: DateTimeOffset.UtcNow,
            Signature: "sig");

        await Assert.ThrowsAsync<CryptographicException>(
            () => svc.DownloadAndStageUpdateAsync(ManagedProductId.AeonBrowser, manifest));

        var partFiles = Directory.Exists(_stagingDir)
            ? Directory.GetFiles(_stagingDir, "*.part", SearchOption.AllDirectories)
            : [];
        Assert.Empty(partFiles);
    }

    [Fact]
    public async Task DiscoverAllAsync_DetectsInstalledLogicFlowAndAeonBinaries_ComputesSha256AndPersistsChannels()
    {
        var lfDir = Path.Combine(_programFilesDir, "DelgadoLogic", "LogicFlow");
        Directory.CreateDirectory(lfDir);
        var lfExe = Path.Combine(lfDir, "LogicFlow.exe");
        var lfCli = Path.Combine(lfDir, "lf.exe");
        var lfBytes = CreateSyntheticPeBinary(16384, 0x3A);
        await File.WriteAllBytesAsync(lfExe, lfBytes);
        await File.WriteAllBytesAsync(lfCli, CreateSyntheticPeBinary(8192, 0x3B));

        var aeonDir = Path.Combine(_localAppDataDir, "Aeon");
        Directory.CreateDirectory(aeonDir);
        var aeonExe = Path.Combine(aeonDir, "Aeon.exe");
        var aeonBytes = CreateSyntheticPeBinary(24576, 0x7C);
        await File.WriteAllBytesAsync(aeonExe, aeonBytes);

        using var http = CreateMockHttpClient(_ => new HttpResponseMessage(HttpStatusCode.NotFound));
        using var svc = CreateService(
            http,
            null,
            processDetector: name => name == "Aeon" ? [4242] : []);

        svc.SetChannel(ManagedProductId.LogicFlow, "beta");
        svc.SetChannel(ManagedProductId.AeonBrowser, "stable");

        var all = await svc.DiscoverAllAsync();
        Assert.Equal(2, all.Count);

        var lf = all.Single(p => p.Product == ManagedProductId.LogicFlow);
        Assert.Equal(ProductInstallState.Installed, lf.State);
        Assert.Equal("beta", lf.Channel);
        Assert.Equal(lfExe, lf.ExecutablePath);
        Assert.Equal(lfCli, lf.CliExecutablePath);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(lfBytes)), lf.ExecutableSha256);
        Assert.False(lf.IsRunning);

        var aeon = all.Single(p => p.Product == ManagedProductId.AeonBrowser);
        Assert.Equal(ProductInstallState.Installed, aeon.State);
        Assert.Equal("stable", aeon.Channel);
        Assert.Equal(aeonExe, aeon.ExecutablePath);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(aeonBytes)), aeon.ExecutableSha256);
        Assert.True(aeon.IsRunning);
        Assert.Contains(4242, aeon.RunningProcessIds);
    }

    [Fact]
    public async Task RepairAndLaunchAsync_VerifiesMzBinaryIntegrity_TriggersRepairOnMismatch_AndLaunchesGuiOrCli()
    {
        var lfDir = Path.Combine(_programFilesDir, "DelgadoLogic", "LogicFlow");
        Directory.CreateDirectory(lfDir);
        var lfExe = Path.Combine(lfDir, "LogicFlow.exe");
        var lfCli = Path.Combine(lfDir, "lf.exe");
        var lfBytes = CreateSyntheticPeBinary(16384, 0x55);
        await File.WriteAllBytesAsync(lfExe, lfBytes);
        await File.WriteAllBytesAsync(lfCli, CreateSyntheticPeBinary(8192, 0x56));

        var distDir = Path.Combine(_workspaceDir, "Products", "LogicFlow", "dist");
        Directory.CreateDirectory(distDir);
        var setupExe = Path.Combine(distDir, "LogicFlowSetup.exe");
        await File.WriteAllBytesAsync(setupExe, CreateSyntheticPeBinary(16384, 0x57));

        var launched = new List<(string FileName, string Arguments)>();
        using var http = CreateMockHttpClient(_ => new HttpResponseMessage(HttpStatusCode.NotFound));
        using var svc = CreateService(
            http,
            null,
            processLauncher: psi =>
            {
                launched.Add((psi.FileName, psi.Arguments));
                return 9001;
            });

        // 1. Intact binary passes repair check without launching setup
        var realSha = Convert.ToHexString(SHA256.HashData(lfBytes));
        var intactReport = await svc.RepairAsync(ManagedProductId.LogicFlow, expectedSha256: realSha, launchInstallerOnFailure: true);
        Assert.True(intactReport.IntegrityValid);
        Assert.False(intactReport.RepairTriggered);
        Assert.Empty(launched);

        // 2. Mismatched expected SHA-256 triggers silent repair installer
        var mismatchReport = await svc.RepairAsync(
            ManagedProductId.LogicFlow,
            expectedSha256: new string('A', 64),
            launchInstallerOnFailure: true,
            silent: true);
        Assert.False(mismatchReport.IntegrityValid);
        Assert.True(mismatchReport.RepairTriggered);
        Assert.Single(launched);
        Assert.Equal(setupExe, launched[0].FileName);
        Assert.Contains("/VERYSILENT", launched[0].Arguments, StringComparison.Ordinal);

        // 3. Launch GUI vs Launch CLI
        var guiLaunch = await svc.LaunchProductAsync(ManagedProductId.LogicFlow, preferCli: false);
        Assert.True(guiLaunch.Success);
        Assert.Equal(lfExe, guiLaunch.TargetPath);

        var cliLaunch = await svc.LaunchProductAsync(ManagedProductId.LogicFlow, preferCli: true, arguments: "sys status --json");
        Assert.True(cliLaunch.Success);
        Assert.Equal(lfCli, cliLaunch.TargetPath);
        Assert.Equal("sys status --json", launched.Last().Arguments);
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────

    private AppDiscoveryAndManagerService CreateService(
        HttpClient http,
        string? pubKeyPem,
        Func<string, int[]>? processDetector = null,
        Func<ProcessStartInfoCompat, int?>? _ = null,
        Func<System.Diagnostics.ProcessStartInfo, int?>? processLauncher = null)
    {
        var settings = new OmniHubSettingsService(_settingsDir, (_, _) => { });
        return new AppDiscoveryAndManagerService(new AppDiscoveryOptions
        {
            ProgramFilesOverride = _programFilesDir,
            LocalAppDataOverride = _localAppDataDir,
            WorkspaceRootOverride = _workspaceDir,
            StagingRootOverride = _stagingDir,
            UpdateServerBaseUrl = "https://api.delgadologic.tech",
            PublicKeyPemOverride = pubKeyPem,
            HttpClient = http,
            RegistryReader = (_, _) => null,
            ProcessDetector = processDetector ?? (_ => []),
            ProcessLauncher = processLauncher ?? (_ => 1234),
            SettingsService = settings
        });
    }

    private sealed record ProcessStartInfoCompat;

    private static (Ed25519PrivateKeyParameters PrivateKey, string PublicKeyPem) GenerateEd25519KeyPair()
    {
        var gen = new Ed25519KeyPairGenerator();
        gen.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        var kp = gen.GenerateKeyPair();
        var priv = (Ed25519PrivateKeyParameters)kp.Private;
        var pub = (Ed25519PublicKeyParameters)kp.Public;

        var spki = new byte[44];
        Buffer.BlockCopy(Ed25519SpkiPrefix, 0, spki, 0, 12);
        Buffer.BlockCopy(pub.GetEncoded(), 0, spki, 12, 32);

        var pem = $"-----BEGIN PUBLIC KEY-----\n{Convert.ToBase64String(spki)}\n-----END PUBLIC KEY-----";
        return (priv, pem);
    }

    private static string CreateSignedEnvelope(Ed25519PrivateKeyParameters privKey, Dictionary<string, object?> manifestFields)
    {
        var rawManifestJson = JsonSerializer.Serialize(manifestFields);
        using var doc = JsonDocument.Parse(rawManifestJson);
        var canonical = AutoUpdateEngine.BuildCanonicalManifestJson(doc.RootElement);
        var canonicalBytes = Encoding.UTF8.GetBytes(canonical);

        var signer = new Ed25519Signer();
        signer.Init(true, privKey);
        signer.BlockUpdate(canonicalBytes, 0, canonicalBytes.Length);
        var sigB64 = Convert.ToBase64String(signer.GenerateSignature());

        return JsonSerializer.Serialize(new
        {
            manifest = manifestFields,
            signature = sigB64
        });
    }

    private static byte[] CreateSyntheticPeBinary(int length, byte seed)
    {
        var bytes = new byte[length];
        bytes[0] = 0x4D; // 'M'
        bytes[1] = 0x5A; // 'Z'
        for (int i = 2; i < length; i++)
        {
            bytes[i] = (byte)((i * 31 + seed) & 0xFF);
        }
        return bytes;
    }

    private static HttpResponseMessage JsonResponse(string json) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(json, Encoding.UTF8, "application/json")
    };

    private static HttpClient CreateMockHttpClient(Func<HttpRequestMessage, HttpResponseMessage> responder) =>
        new(new DelegateHttpMessageHandler(responder));

    private sealed class DelegateHttpMessageHandler(Func<HttpRequestMessage, HttpResponseMessage> responder) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(responder(request));
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_tempRoot))
                Directory.Delete(_tempRoot, recursive: true);
        }
        catch
        {
        }
    }
}
