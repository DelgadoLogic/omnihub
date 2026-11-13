using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace OmniHub.Core;

public sealed record CanonicalModelSpec(
    string FileName,
    string DisplayName,
    string ParameterSummary,
    string Modalities,
    string ContextWindow,
    string LicenseName,
    long EstimatedFootprintBytes,
    string? PinnedSha256Hex,
    string TargetTierDescription);

public sealed record ModelVaultEntry(
    string FileName,
    string DisplayName,
    bool IsCanonical,
    string ParameterSummary,
    string LicenseName,
    bool ExistsInSharedVault,
    string SharedVaultFilePath,
    long SizeBytes,
    bool HasValidGgufHeader,
    int? GgufFormatVersion,
    string? Sha256Hex,
    bool? PinnedChecksumMatches,
    uint HardLinkCount,
    IReadOnlyList<string> LinkedExternalPaths,
    IReadOnlyList<string> UnlinkedDuplicatePaths);

public sealed record ModelDeduplicationReport(
    string ActiveVaultRoot,
    bool UsedNonElevatedFallback,
    int ModelsInspected,
    int HardLinksCreated,
    int AlreadyHardLinkedCount,
    int CrossVolumeCopiesCreated,
    long BytesSavedThisRun,
    long TotalActiveHardLinkSavingsBytes,
    IReadOnlyList<string> ActionsLog);

public sealed class SharedModelVaultOptions
{
    public string? VaultRootOverride { get; init; }
    public IReadOnlyList<string>? ExternalScanDirectoriesOverride { get; init; }
    public string? WorkspaceRootOverride { get; init; }
    public ILogger<SharedModelVaultService>? Logger { get; init; }
}

/// <summary>
/// Manages the shared local GGUF AI model vault (%ProgramData%\DelgadoLogic\Models with graceful
/// %LOCALAPPDATA%\DelgadoLogic\Models fallback), streaming SHA-256 verification, and atomic Win32
/// CreateHardLinkW NTFS deduplication across LogicFlow and Aeon Browser model directories.
/// </summary>
public sealed class SharedModelVaultService
{
    private const int ERROR_NOT_SAME_DEVICE = 17;

    public static readonly IReadOnlyList<CanonicalModelSpec> CanonicalCatalog =
    [
        new CanonicalModelSpec(
            FileName: "gemma-4-E2B-it-Q4_K_M.gguf",
            DisplayName: "Gemma 4 E2B Instruct (Q4_K_M)",
            ParameterSummary: "~2.1B params",
            Modalities: "Text, Image, Audio",
            ContextWindow: "128K",
            LicenseName: "Apache-2.0",
            EstimatedFootprintBytes: 1_524_713_472L,
            PinnedSha256Hex: "923C4C86177D2EE173A7F5B4FA3D0AC65F5962AB15E6D6A5BC250AEC4FD7BF7E",
            TargetTierDescription: "8 GB RAM laptops & LogicFlow Guardian hybrid local sidecar"),

        new CanonicalModelSpec(
            FileName: "gemma-4-E4B-it-Q4_K_M.gguf",
            DisplayName: "Gemma 4 E4B Instruct (Q4_K_M)",
            ParameterSummary: "~4.3B params",
            Modalities: "Text, Image, Audio",
            ContextWindow: "128K",
            LicenseName: "Apache-2.0",
            EstimatedFootprintBytes: 3_027_951_616L,
            PinnedSha256Hex: null,
            TargetTierDescription: "16 GB RAM Windows 11 desktops — Default OmniBrain & Aeon Agent"),

        new CanonicalModelSpec(
            FileName: "bge-small-en-v1.5-q8_0.gguf",
            DisplayName: "BGE-Small English v1.5 Embeddings (Q8_0)",
            ParameterSummary: "33M params (384-dim)",
            Modalities: "Semantic Embeddings",
            ContextWindow: "512",
            LicenseName: "MIT",
            EstimatedFootprintBytes: 37_748_736L,
            PinnedSha256Hex: null,
            TargetTierDescription: "Fast semantic vector indexing across OmniHub & Aeon memory")
    ];

    [StructLayout(LayoutKind.Sequential)]
    private struct BY_HANDLE_FILE_INFORMATION
    {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateHardLinkW(
        string lpFileName,
        string lpExistingFileName,
        IntPtr lpSecurityAttributes);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(
        Microsoft.Win32.SafeHandles.SafeFileHandle hFile,
        out BY_HANDLE_FILE_INFORMATION lpFileInformation);

    private readonly SharedModelVaultOptions _options;
    private readonly ILogger<SharedModelVaultService> _logger;
    private readonly string _activeVaultRoot;
    private readonly bool _usedNonElevatedFallback;

    public SharedModelVaultService(SharedModelVaultOptions? options = null)
    {
        _options = options ?? new SharedModelVaultOptions();
        _logger = _options.Logger ?? NullLogger<SharedModelVaultService>.Instance;
        (_activeVaultRoot, _usedNonElevatedFallback) = ResolveWritableVaultRoot(_options.VaultRootOverride);
    }

    public string ActiveVaultRoot => _activeVaultRoot;
    public bool UsedNonElevatedFallback => _usedNonElevatedFallback;

    public IReadOnlyList<string> GetExternalScanDirectories()
    {
        if (_options.ExternalScanDirectoriesOverride is { Count: > 0 })
            return _options.ExternalScanDirectoriesOverride;

        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var dirs = new List<string>
        {
            Path.Combine(localAppData, "LogicFlow", "Models"),
            Path.Combine(localAppData, "LogicFlow", "AI"),
            Path.Combine(localAppData, "Aeon", "models")
        };

        var ws = !string.IsNullOrWhiteSpace(_options.WorkspaceRootOverride)
            ? _options.WorkspaceRootOverride
            : AppDiscoveryAndManagerService.TryResolveWorkspaceRoot();

        if (!string.IsNullOrWhiteSpace(ws))
        {
            dirs.Add(Path.Combine(ws, "Products", "AeonBrowser", "models"));
            dirs.Add(Path.Combine(ws, "Products", "LogicFlow", "models"));
        }

        // Exclude ActiveVaultRoot itself if overlapping
        return dirs
            .Select(Path.GetFullPath)
            .Where(d => !string.Equals(d.TrimEnd('\\'), _activeVaultRoot.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    /// <summary>
    /// Scans the shared vault and all external LogicFlow/Aeon model directories, optionally computing streaming SHA-256 digests.
    /// </summary>
    public async Task<IReadOnlyList<ModelVaultEntry>> ScanCatalogAsync(
        bool computeSha256 = true,
        CancellationToken ct = default)
    {
        Directory.CreateDirectory(_activeVaultRoot);
        var externalDirs = GetExternalScanDirectories();

        // Collect all external .gguf files grouped by filename
        var externalByFileName = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var extDir in externalDirs)
        {
            if (!Directory.Exists(extDir))
                continue;

            foreach (var gguf in Directory.EnumerateFiles(extDir, "*.gguf", SearchOption.AllDirectories))
            {
                var fn = Path.GetFileName(gguf);
                if (!externalByFileName.TryGetValue(fn, out var list))
                {
                    list = [];
                    externalByFileName[fn] = list;
                }
                list.Add(Path.GetFullPath(gguf));
            }
        }

        // Collect all filenames to report (canonical catalog + any extra discovered .gguf files)
        var allFileNames = new List<string>(CanonicalCatalog.Select(c => c.FileName));
        foreach (var vaultGguf in Directory.EnumerateFiles(_activeVaultRoot, "*.gguf", SearchOption.TopDirectoryOnly))
        {
            var fn = Path.GetFileName(vaultGguf);
            if (!allFileNames.Contains(fn, StringComparer.OrdinalIgnoreCase))
                allFileNames.Add(fn);
        }
        foreach (var extFn in externalByFileName.Keys)
        {
            if (!allFileNames.Contains(extFn, StringComparer.OrdinalIgnoreCase))
                allFileNames.Add(extFn);
        }

        var entries = new List<ModelVaultEntry>(allFileNames.Count);
        foreach (var fileName in allFileNames)
        {
            ct.ThrowIfCancellationRequested();
            var spec = CanonicalCatalog.FirstOrDefault(c => string.Equals(c.FileName, fileName, StringComparison.OrdinalIgnoreCase));
            var vaultFilePath = Path.Combine(_activeVaultRoot, fileName);
            bool inVault = File.Exists(vaultFilePath);

            long sizeBytes = 0;
            bool validGguf = false;
            int? ggufVer = null;
            string? shaHex = null;
            bool? pinnedMatch = null;
            uint linkCount = 0;

            if (inVault)
            {
                var fi = new FileInfo(vaultFilePath);
                sizeBytes = fi.Length;
                (validGguf, ggufVer) = InspectGgufHeader(vaultFilePath);
                if (TryGetFileNodeInfo(vaultFilePath, out var nodeInfo))
                    linkCount = nodeInfo.NumberOfLinks;
                else
                    linkCount = 1;

                if (computeSha256)
                {
                    shaHex = await ComputeStreamingSha256Async(vaultFilePath, ct).ConfigureAwait(false);
                    if (!string.IsNullOrWhiteSpace(spec?.PinnedSha256Hex))
                    {
                        pinnedMatch = string.Equals(shaHex, spec.PinnedSha256Hex, StringComparison.OrdinalIgnoreCase);
                    }
                }
            }

            var linkedExternal = new List<string>();
            var unlinkedDuplicates = new List<string>();

            if (externalByFileName.TryGetValue(fileName, out var extFiles))
            {
                foreach (var extPath in extFiles)
                {
                    if (!File.Exists(extPath))
                        continue;

                    if (inVault && AreSamePhysicalFile(vaultFilePath, extPath))
                    {
                        linkedExternal.Add(extPath);
                    }
                    else
                    {
                        unlinkedDuplicates.Add(extPath);
                        if (!inVault && sizeBytes == 0)
                        {
                            sizeBytes = new FileInfo(extPath).Length;
                            (validGguf, ggufVer) = InspectGgufHeader(extPath);
                            if (computeSha256)
                                shaHex = await ComputeStreamingSha256Async(extPath, ct).ConfigureAwait(false);
                        }
                    }
                }
            }

            entries.Add(new ModelVaultEntry(
                FileName: fileName,
                DisplayName: spec?.DisplayName ?? Path.GetFileNameWithoutExtension(fileName),
                IsCanonical: spec is not null,
                ParameterSummary: spec?.ParameterSummary ?? "Custom GGUF",
                LicenseName: spec?.LicenseName ?? "Custom",
                ExistsInSharedVault: inVault,
                SharedVaultFilePath: vaultFilePath,
                SizeBytes: sizeBytes > 0 ? sizeBytes : (spec?.EstimatedFootprintBytes ?? 0),
                HasValidGgufHeader: validGguf,
                GgufFormatVersion: ggufVer,
                Sha256Hex: shaHex,
                PinnedChecksumMatches: pinnedMatch,
                HardLinkCount: linkCount,
                LinkedExternalPaths: linkedExternal,
                UnlinkedDuplicatePaths: unlinkedDuplicates));
        }

        return entries;
    }

    /// <summary>
    /// Scans LogicFlow and Aeon model directories, ingests missing .gguf weights into the shared vault,
    /// and replaces identical duplicate copies with atomic Win32 NTFS hard links (CreateHardLinkW)
    /// while calculating exact physical disk space saved.
    /// </summary>
    public async Task<ModelDeduplicationReport> DeduplicateAndLinkAllAsync(CancellationToken ct = default)
    {
        Directory.CreateDirectory(_activeVaultRoot);

        int modelsInspected = 0;
        int hardLinksCreated = 0;
        int alreadyLinked = 0;
        int crossVolumeCopies = 0;
        long bytesSavedThisRun = 0;
        var actions = new List<string>();

        var externalDirs = GetExternalScanDirectories();
        var hashMemo = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var extDir in externalDirs)
        {
            if (!Directory.Exists(extDir))
                continue;

            foreach (var extPathRaw in Directory.EnumerateFiles(extDir, "*.gguf", SearchOption.AllDirectories))
            {
                ct.ThrowIfCancellationRequested();
                var extPath = Path.GetFullPath(extPathRaw);
                if (extPath.Contains(".omnihub_link_", StringComparison.OrdinalIgnoreCase))
                    continue;

                var extFi = new FileInfo(extPath);
                if (!extFi.Exists || extFi.Length == 0)
                    continue;

                modelsInspected++;
                var fileName = extFi.Name;
                var vaultPath = Path.Combine(_activeVaultRoot, fileName);

                // Case 1: Vault does not yet contain this model — ingest into shared vault via hard link (or cross-volume copy)
                if (!File.Exists(vaultPath))
                {
                    var (linked, crossVolume) = await IngestIntoVaultAsync(extPath, vaultPath, ct).ConfigureAwait(false);
                    if (linked)
                    {
                        hardLinksCreated++;
                        actions.Add($"Ingested '{fileName}' into shared vault via NTFS hard link from '{extPath}'.");
                    }
                    else if (crossVolume)
                    {
                        crossVolumeCopies++;
                        actions.Add($"Copied '{fileName}' into shared vault across volumes from '{extPath}'.");
                    }
                    continue;
                }

                // Case 2: Already hard-linked to the exact same NTFS physical file record
                if (AreSamePhysicalFile(vaultPath, extPath))
                {
                    alreadyLinked++;
                    continue;
                }

                // Case 3: Vault and external path are separate inodes — verify size + SHA-256 equality before linking
                var vaultFi = new FileInfo(vaultPath);
                if (vaultFi.Length != extFi.Length)
                {
                    actions.Add($"Skipped '{extPath}': size ({extFi.Length} B) differs from shared vault ({vaultFi.Length} B).");
                    continue;
                }

                var vaultHash = await GetOrComputeSha256Async(vaultPath, hashMemo, ct).ConfigureAwait(false);
                var extHash = await GetOrComputeSha256Async(extPath, hashMemo, ct).ConfigureAwait(false);

                if (!string.Equals(vaultHash, extHash, StringComparison.OrdinalIgnoreCase))
                {
                    actions.Add($"Skipped '{extPath}': SHA-256 differs from shared vault copy.");
                    continue;
                }

                // Atomic NTFS hard-link replacement: create temp hard link next to extPath, then atomic overwrite move
                var (replacedWithLink, crossVolError) = ReplaceDuplicateWithHardLink(vaultPath, extPath);
                if (replacedWithLink)
                {
                    hardLinksCreated++;
                    bytesSavedThisRun += extFi.Length;
                    actions.Add($"Deduplicated '{extPath}' -> NTFS hard link to shared vault (saved {OmniHubBrandConstants.FormatBytes(extFi.Length)}).");
                }
                else if (crossVolError)
                {
                    actions.Add($"Kept separate copy at '{extPath}': resides on a different volume from shared vault.");
                }
            }
        }

        // Compute total active physical savings across all shared vault hard-linked inodes
        long totalActiveSavings = 0;
        var seenInodes = new HashSet<(uint Vol, uint High, uint Low)>();
        var externalRootSet = externalDirs;

        foreach (var vaultFile in Directory.EnumerateFiles(_activeVaultRoot, "*.gguf", SearchOption.TopDirectoryOnly))
        {
            if (!TryGetFileNodeInfo(vaultFile, out var info))
                continue;

            var key = (info.VolumeSerialNumber, info.FileIndexHigh, info.FileIndexLow);
            if (!seenInodes.Add(key))
                continue;

            if (info.NumberOfLinks > 1)
            {
                var len = new FileInfo(vaultFile).Length;
                totalActiveSavings += (long)(info.NumberOfLinks - 1) * len;
            }
        }

        return new ModelDeduplicationReport(
            ActiveVaultRoot: _activeVaultRoot,
            UsedNonElevatedFallback: _usedNonElevatedFallback,
            ModelsInspected: modelsInspected,
            HardLinksCreated: hardLinksCreated,
            AlreadyHardLinkedCount: alreadyLinked,
            CrossVolumeCopiesCreated: crossVolumeCopies,
            BytesSavedThisRun: bytesSavedThisRun,
            TotalActiveHardLinkSavingsBytes: Math.Max(totalActiveSavings, bytesSavedThisRun),
            ActionsLog: actions);
    }

    /// <summary>
    /// Links a shared vault model into a target consumer directory (e.g., LogicFlow or Aeon models folder)
    /// using CreateHardLinkW, with safe cross-volume copy fallback.
    /// </summary>
    public async Task<(bool Success, bool IsHardLink, string Message)> ProvisionModelToDirectoryAsync(
        string fileName,
        string destinationDirectory,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(fileName);
        ArgumentException.ThrowIfNullOrWhiteSpace(destinationDirectory);

        var safeName = Path.GetFileName(fileName);
        var vaultPath = Path.Combine(_activeVaultRoot, safeName);
        if (!File.Exists(vaultPath))
            return (false, false, $"Model '{safeName}' is not present in the shared vault.");

        Directory.CreateDirectory(destinationDirectory);
        var destPath = Path.Combine(destinationDirectory, safeName);

        if (File.Exists(destPath))
        {
            if (AreSamePhysicalFile(vaultPath, destPath))
                return (true, true, $"'{safeName}' is already hard-linked in '{destinationDirectory}'.");

            var (replaced, _) = ReplaceDuplicateWithHardLink(vaultPath, destPath);
            if (replaced)
                return (true, true, $"Linked '{safeName}' into '{destinationDirectory}' via NTFS hard link.");
        }
        else
        {
            if (CreateHardLinkW(destPath, vaultPath, IntPtr.Zero))
                return (true, true, $"Provisioned '{safeName}' into '{destinationDirectory}' via zero-copy NTFS hard link.");
        }

        int win32Err = Marshal.GetLastWin32Error();
        if (win32Err == ERROR_NOT_SAME_DEVICE)
        {
            var tmp = destPath + ".tmp";
            await CopyFileStreamingAsync(vaultPath, tmp, ct).ConfigureAwait(false);
            File.Move(tmp, destPath, overwrite: true);
            return (true, false, $"Copied '{safeName}' across volumes into '{destinationDirectory}'.");
        }

        return (false, false, $"Failed to link '{safeName}' (Win32 error {win32Err}: {new Win32Exception(win32Err).Message}).");
    }

    public static async Task<string> ComputeStreamingSha256Async(string filePath, CancellationToken ct = default)
    {
        await using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 81920, useAsync: true);
        var digest = await SHA256.HashDataAsync(fs, ct).ConfigureAwait(false);
        return Convert.ToHexString(digest);
    }

    public static (bool IsValid, int? FormatVersion) InspectGgufHeader(string filePath)
    {
        try
        {
            Span<byte> header = stackalloc byte[8];
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            if (fs.Read(header) < 8)
                return (false, null);

            bool magicOk = header[0] == 0x47 && // 'G'
                           header[1] == 0x47 && // 'G'
                           header[2] == 0x55 && // 'U'
                           header[3] == 0x46;   // 'F'
            if (!magicOk)
                return (false, null);

            int version = BitConverter.ToInt32(header[4..8]);
            return (version is >= 1 and <= 4, version);
        }
        catch
        {
            return (false, null);
        }
    }

    public static bool AreSamePhysicalFile(string pathA, string pathB)
    {
        if (!TryGetFileNodeInfo(pathA, out var infoA) || !TryGetFileNodeInfo(pathB, out var infoB))
            return false;

        return infoA.VolumeSerialNumber == infoB.VolumeSerialNumber &&
               infoA.FileIndexHigh == infoB.FileIndexHigh &&
               infoA.FileIndexLow == infoB.FileIndexLow;
    }

    public static uint GetHardLinkCount(string filePath) =>
        TryGetFileNodeInfo(filePath, out var info) ? info.NumberOfLinks : 0u;

    // ─── Internals ───────────────────────────────────────────────────────────

    private async Task<(bool HardLinked, bool CrossVolumeCopied)> IngestIntoVaultAsync(
        string sourcePath,
        string vaultDestPath,
        CancellationToken ct)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(vaultDestPath)!);

        if (CreateHardLinkW(vaultDestPath, sourcePath, IntPtr.Zero))
        {
            return (true, false);
        }

        int err = Marshal.GetLastWin32Error();
        if (err == ERROR_NOT_SAME_DEVICE)
        {
            var tmp = vaultDestPath + ".tmp";
            try
            {
                await CopyFileStreamingAsync(sourcePath, tmp, ct).ConfigureAwait(false);
                var srcSha = await ComputeStreamingSha256Async(sourcePath, ct).ConfigureAwait(false);
                var dstSha = await ComputeStreamingSha256Async(tmp, ct).ConfigureAwait(false);
                if (!string.Equals(srcSha, dstSha, StringComparison.OrdinalIgnoreCase))
                {
                    File.Delete(tmp);
                    throw new CryptographicException("Cross-volume GGUF copy failed SHA-256 verification.");
                }
                File.Move(tmp, vaultDestPath, overwrite: true);
                return (false, true);
            }
            catch
            {
                try { if (File.Exists(tmp)) File.Delete(tmp); } catch { }
                throw;
            }
        }

        _logger.LogWarning("[OmniHub.ModelVault] CreateHardLinkW failed ({Error}) ingesting {Source}.", err, sourcePath);
        return (false, false);
    }

    private (bool Replaced, bool IsCrossVolume) ReplaceDuplicateWithHardLink(string vaultPath, string duplicateAppPath)
    {
        var dir = Path.GetDirectoryName(duplicateAppPath)!;
        var tempLinkPath = Path.Combine(dir, $".omnihub_link_{Guid.NewGuid():N}.gguf");

        try
        {
            if (!CreateHardLinkW(tempLinkPath, vaultPath, IntPtr.Zero))
            {
                int err = Marshal.GetLastWin32Error();
                return (false, err == ERROR_NOT_SAME_DEVICE);
            }

            File.Move(tempLinkPath, duplicateAppPath, overwrite: true);
            return (true, false);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "[OmniHub.ModelVault] Failed atomic hard-link swap at {Path}.", duplicateAppPath);
            try { if (File.Exists(tempLinkPath)) File.Delete(tempLinkPath); } catch { }
            return (false, false);
        }
    }

    private static async Task<string> GetOrComputeSha256Async(
        string path,
        Dictionary<string, string> memo,
        CancellationToken ct)
    {
        if (memo.TryGetValue(path, out var existing))
            return existing;

        var computed = await ComputeStreamingSha256Async(path, ct).ConfigureAwait(false);
        memo[path] = computed;
        return computed;
    }

    private static async Task CopyFileStreamingAsync(string source, string destination, CancellationToken ct)
    {
        await using var src = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.Read, 131072, useAsync: true);
        await using var dst = new FileStream(destination, FileMode.Create, FileAccess.Write, FileShare.None, 131072, useAsync: true);
        await src.CopyToAsync(dst, 131072, ct).ConfigureAwait(false);
    }

    private static bool TryGetFileNodeInfo(string filePath, out BY_HANDLE_FILE_INFORMATION info)
    {
        info = default;
        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
            return false;

        try
        {
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            return GetFileInformationByHandle(fs.SafeFileHandle, out info);
        }
        catch
        {
            return false;
        }
    }

    private static (string VaultPath, bool UsedFallback) ResolveWritableVaultRoot(string? overrideRoot)
    {
        if (!string.IsNullOrWhiteSpace(overrideRoot))
        {
            var full = Path.GetFullPath(overrideRoot);
            Directory.CreateDirectory(full);
            return (full, false);
        }

        var programDataVault = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "DelgadoLogic",
            "Models");

        if (TryProbeWriteDirectory(programDataVault))
            return (programDataVault, false);

        var localFallbackVault = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "DelgadoLogic",
            "Models");
        Directory.CreateDirectory(localFallbackVault);
        return (localFallbackVault, true);
    }

    private static bool TryProbeWriteDirectory(string directory)
    {
        try
        {
            Directory.CreateDirectory(directory);
            var probeFile = Path.Combine(directory, $".probe_{Guid.NewGuid():N}");
            using (File.Create(probeFile, 1, FileOptions.DeleteOnClose))
            {
            }
            return true;
        }
        catch
        {
            return false;
        }
    }
}
