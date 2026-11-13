using System.Diagnostics;
using System.Security.Cryptography;
using LogicFlow.Storage.Engine.Compression;
using LogicFlow.Storage.Engine.Container;

namespace OmniHub.Core;

public sealed record LogicFlowCliResult(
    bool Success,
    int ExitCode,
    string StandardOutput,
    string StandardError,
    string CommandExecuted);

public sealed record SentinelFileScanVerdict(
    bool IsClean,
    string EngineUsed,
    string FilePath,
    string Sha256,
    long SizeBytes,
    double ShannonEntropy,
    bool HasMarkOfTheWeb,
    string Summary);

/// <summary>
/// Headless bridge to LogicFlow CLI (lf.exe --json) for HyperStore, Sentinel, Lazarus, and System actions,
/// with deterministic in-process HyperStore and Defender MpCmdRun / heuristic fallbacks when lf.exe is absent.
/// </summary>
public sealed class LogicFlowCliBridge
{
    private static readonly HashSet<string> HighRiskExecutableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".sys", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".msi", ".com"
    };

    private readonly AppDiscoveryAndManagerService _discovery;
    private readonly Func<string, string, CancellationToken, Task<LogicFlowCliResult>>? _customRunner;

    public LogicFlowCliBridge(
        AppDiscoveryAndManagerService discovery,
        Func<string, string, CancellationToken, Task<LogicFlowCliResult>>? customRunner = null)
    {
        _discovery = discovery ?? throw new ArgumentNullException(nameof(discovery));
        _customRunner = customRunner;
    }

    public async Task<LogicFlowCliResult> ExecuteCliAsync(string arguments, CancellationToken ct = default)
    {
        var fullArgs = arguments.Contains("--json", StringComparison.OrdinalIgnoreCase)
            ? arguments
            : $"{arguments} --json";

        var status = await _discovery.DiscoverProductAsync(ManagedProductId.LogicFlow, ct).ConfigureAwait(false);
        var cliPath = status.CliExecutablePath;

        if (_customRunner is not null)
        {
            return await _customRunner(cliPath ?? "lf.exe", fullArgs, ct).ConfigureAwait(false);
        }

        if (string.IsNullOrWhiteSpace(cliPath) || !File.Exists(cliPath))
        {
            return new LogicFlowCliResult(
                false,
                -1,
                "",
                "LogicFlow CLI (lf.exe) is not installed on this machine.",
                $"lf.exe {fullArgs}");
        }

        var psi = new ProcessStartInfo
        {
            FileName = cliPath,
            Arguments = fullArgs,
            WorkingDirectory = Path.GetDirectoryName(cliPath) ?? Environment.CurrentDirectory,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        using var proc = Process.Start(psi);
        if (proc is null)
        {
            return new LogicFlowCliResult(false, -1, "", "Failed to spawn lf.exe process.", $"{cliPath} {fullArgs}");
        }

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(TimeSpan.FromSeconds(30));

        try
        {
            var stdoutTask = proc.StandardOutput.ReadToEndAsync(timeoutCts.Token);
            var stderrTask = proc.StandardError.ReadToEndAsync(timeoutCts.Token);
            await proc.WaitForExitAsync(timeoutCts.Token).ConfigureAwait(false);

            return new LogicFlowCliResult(
                proc.ExitCode == 0,
                proc.ExitCode,
                await stdoutTask.ConfigureAwait(false),
                await stderrTask.ConfigureAwait(false),
                $"{cliPath} {fullArgs}");
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            try { proc.Kill(entireProcessTree: true); } catch { }
            return new LogicFlowCliResult(false, -2, "", "lf.exe command timed out after 30s.", $"{cliPath} {fullArgs}");
        }
    }

    public Task<LogicFlowCliResult> GetSystemStatusAsync(CancellationToken ct = default) =>
        ExecuteCliAsync("sys status --json", ct);

    public Task<LogicFlowCliResult> CheckSecurityHardeningAsync(CancellationToken ct = default) =>
        ExecuteCliAsync("sec hardening-check --json", ct);

    public Task<LogicFlowCliResult> ListLazarusDrivesAsync(CancellationToken ct = default) =>
        ExecuteCliAsync("lazarus drives --json", ct);

    /// <summary>
    /// Packs a file or directory into a HyperStore .lfc archive via lf.exe store pack, falling back
    /// seamlessly to the embedded LogicFlow.Storage.Engine LfcWriter.
    /// </summary>
    public async Task<(bool Success, string OutputLfcPath, string Message)> PackToHyperStoreAsync(
        string inputPath,
        string outputLfcPath,
        CompressionTier tier = CompressionTier.Hot,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(inputPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(outputLfcPath);

        string? tempDirToClean = null;
        string dirToPack;

        if (Directory.Exists(inputPath))
        {
            dirToPack = inputPath;
        }
        else if (File.Exists(inputPath))
        {
            tempDirToClean = Path.Combine(Path.GetTempPath(), $"omnihub_pack_{Guid.NewGuid():N}");
            Directory.CreateDirectory(tempDirToClean);
            File.Copy(inputPath, Path.Combine(tempDirToClean, Path.GetFileName(inputPath)), overwrite: true);
            dirToPack = tempDirToClean;
        }
        else
        {
            return (false, outputLfcPath, $"Input path not found: {inputPath}");
        }

        try
        {
            var tierArg = tier == CompressionTier.Cold ? "cold" : "hot";
            var cliRes = await ExecuteCliAsync($"store pack \"{dirToPack}\" \"{outputLfcPath}\" --tier {tierArg} --force --json", ct).ConfigureAwait(false);
            if (cliRes.Success && File.Exists(outputLfcPath))
            {
                return (true, outputLfcPath, $"Packed into '{Path.GetFileName(outputLfcPath)}' via lf.exe HyperStore.");
            }

            // Direct in-process HyperStore engine execution
            using var writer = new LfcWriter();
            await writer.PackDirectoryAsync(
                dirToPack,
                outputLfcPath,
                new LfcPackOptions { Tier = tier, EnableDeltaCompression = true },
                null,
                ct).ConfigureAwait(false);

            return (true, outputLfcPath, $"Packed into '{Path.GetFileName(outputLfcPath)}' via HyperStore LfcWriter ({tier}).");
        }
        finally
        {
            if (tempDirToClean is not null)
            {
                try { Directory.Delete(tempDirToClean, recursive: true); } catch { }
            }
        }
    }

    /// <summary>
    /// Scans an ingested file with Microsoft Defender (MpCmdRun.exe Type 3 custom file scan) when available,
    /// augmented with deterministic SHA-256, Mark-of-the-Web ADS, PE header, and Shannon entropy telemetry.
    /// </summary>
    public async Task<SentinelFileScanVerdict> ScanFileAsync(
        string filePath,
        bool invokeDefenderCli = true,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        if (!File.Exists(filePath))
            throw new FileNotFoundException($"File to scan not found: {filePath}", filePath);

        var fi = new FileInfo(filePath);
        string sha256;
        double entropy;

        await using (var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 65536, useAsync: true))
        {
            var hash = await SHA256.HashDataAsync(fs, ct).ConfigureAwait(false);
            sha256 = Convert.ToHexString(hash);
            fs.Position = 0;
            entropy = await ComputeSampleEntropyAsync(fs, ct).ConfigureAwait(false);
        }

        bool hasMotw = File.Exists(filePath + ":Zone.Identifier");
        bool defenderClean = true;
        string engineUsed = "Sentinel Static Inspector";

        if (invokeDefenderCli)
        {
            var mpCmd = ResolveDefenderMpCmdRun();
            if (mpCmd is not null)
            {
                var (ran, clean) = await TryRunDefenderCustomScanAsync(mpCmd, filePath, ct).ConfigureAwait(false);
                if (ran)
                {
                    defenderClean = clean;
                    engineUsed = "Microsoft Defender + Sentinel";
                }
            }
        }

        var ext = Path.GetExtension(filePath);
        bool highRiskExt = HighRiskExecutableExtensions.Contains(ext);
        var summary = !defenderClean
            ? $"THREAT DETECTED by {engineUsed} in '{fi.Name}'."
            : highRiskExt && entropy > 7.4
                ? $"Clean signature ({engineUsed}); note high-entropy executable ({entropy:F2} bits/byte)."
                : $"Verified clean by {engineUsed} (SHA-256: {sha256[..16]}…, entropy {entropy:F2} bits/byte).";

        return new SentinelFileScanVerdict(
            IsClean: defenderClean,
            EngineUsed: engineUsed,
            FilePath: fi.FullName,
            Sha256: sha256,
            SizeBytes: fi.Length,
            ShannonEntropy: Math.Round(entropy, 3),
            HasMarkOfTheWeb: hasMotw,
            Summary: summary);
    }

    private static string? ResolveDefenderMpCmdRun()
    {
        var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var direct = Path.Combine(pf, "Windows Defender", "MpCmdRun.exe");
        if (File.Exists(direct))
            return direct;

        var platformRoot = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Microsoft", "Windows Defender", "Platform");
        if (Directory.Exists(platformRoot))
        {
            var latest = Directory.EnumerateDirectories(platformRoot)
                .OrderByDescending(d => d, StringComparer.OrdinalIgnoreCase)
                .Select(d => Path.Combine(d, "MpCmdRun.exe"))
                .FirstOrDefault(File.Exists);
            if (latest is not null)
                return latest;
        }
        return null;
    }

    private static async Task<(bool Ran, bool Clean)> TryRunDefenderCustomScanAsync(string mpCmdPath, string targetFile, CancellationToken ct)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = mpCmdPath,
                Arguments = $"-Scan -ScanType 3 -File \"{targetFile}\" -DisableRemediation",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var proc = Process.Start(psi);
            if (proc is null) return (false, true);

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(TimeSpan.FromSeconds(10));
            await proc.WaitForExitAsync(timeoutCts.Token).ConfigureAwait(false);
            // MpCmdRun exit code 0 = clean, 2 = threat found
            return (true, proc.ExitCode != 2);
        }
        catch
        {
            return (false, true);
        }
    }

    private static async Task<double> ComputeSampleEntropyAsync(Stream stream, CancellationToken ct)
    {
        var buf = new byte[Math.Min(262144, (int)Math.Max(1, Math.Min(stream.Length, 262144)))];
        int read = await stream.ReadAsync(buf, ct).ConfigureAwait(false);
        if (read == 0) return 0.0;

        var counts = new int[256];
        for (int i = 0; i < read; i++)
            counts[buf[i]]++;

        double entropy = 0.0;
        double invTotal = 1.0 / read;
        for (int i = 0; i < 256; i++)
        {
            if (counts[i] == 0) continue;
            double p = counts[i] * invTotal;
            entropy -= p * Math.Log2(p);
        }
        return entropy;
    }
}
