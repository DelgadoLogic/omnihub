using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using LogicFlow.Storage.Engine.Compression;
using LogicFlow.Storage.Engine.Container;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace OmniHub.Core;

public sealed record VaultSnapshotRecord
{
    public string SnapshotId { get; init; } = "";
    public string ArchiveFileName { get; init; } = "";
    public string ArchivePath { get; init; } = "";
    public DateTimeOffset CreatedAtUtc { get; init; }
    public string TriggerReason { get; init; } = "Manual";
    public int FileCount { get; init; }
    public int UniqueChunks { get; init; }
    public long RawBytes { get; init; }
    public long CompressedBytes { get; init; }
    public double CompressionRatio { get; init; }
    public string ContentTreeSha256 { get; init; } = "";
    public string ArchiveSha256 { get; init; } = "";
    public bool WasDeduplicated { get; init; }
}

public sealed record VaultFileItem(
    string RelativePath,
    string FullPath,
    string Category,
    long SizeBytes,
    DateTimeOffset LastModifiedUtc);

public sealed record VaultRestoreResult(
    bool Success,
    string SnapshotId,
    string TargetDirectory,
    int FilesRestored,
    long BytesRestored,
    string Message);

public sealed record VaultFileChangeNotification(
    string ChangeType,
    string RelativePath,
    DateTimeOffset OccurredAtUtc);

/// <summary>
/// Manages %USERPROFILE%\DelgadoLogic Cloud with real-time debounced FileSystemWatcher monitoring
/// and content-addressed Zstd .lfc snapshots powered by LogicFlow.Storage.Engine (LfcWriter / LfcReader).
/// </summary>
public sealed class CloudVaultSyncService : IDisposable
{
    public const string DefaultVaultFolderName = "DelgadoLogic Cloud";
    public const string SnapshotsDirName = ".snapshots";
    private const string SnapshotIndexFileName = "index.json";

    public static readonly IReadOnlyList<string> StandardSubdirectories =
    [
        "Dropzone",
        "Sessions",
        "Clips",
        "Archives"
    ];

    private static readonly JsonSerializerOptions IndexJsonOpts = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true
    };

    private readonly string _vaultRoot;
    private readonly string _snapshotsDir;
    private readonly string _indexFilePath;
    private readonly TimeSpan _debounceDelay;
    private readonly ILogger<CloudVaultSyncService> _logger;
    private readonly SemaphoreSlim _snapshotLock = new(1, 1);
    private readonly object _watcherGate = new();

    private FileSystemWatcher? _watcher;
    private CancellationTokenSource? _debounceCts;
    private string _pendingTriggerReason = "FileSystemChange";
    private volatile bool _suppressWatcher;
    private bool _disposed;

    public event EventHandler<VaultSnapshotRecord>? SnapshotCreated;
    public event EventHandler<VaultFileChangeNotification>? VaultChanged;

    public CloudVaultSyncService(
        string? vaultRootOverride = null,
        TimeSpan? debounceDelay = null,
        ILogger<CloudVaultSyncService>? logger = null)
    {
        _vaultRoot = Path.GetFullPath(
            !string.IsNullOrWhiteSpace(vaultRootOverride)
                ? vaultRootOverride!
                : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), DefaultVaultFolderName));

        _snapshotsDir = Path.Combine(_vaultRoot, SnapshotsDirName);
        _indexFilePath = Path.Combine(_snapshotsDir, SnapshotIndexFileName);
        _debounceDelay = debounceDelay ?? TimeSpan.FromMilliseconds(400);
        _logger = logger ?? NullLogger<CloudVaultSyncService>.Instance;
    }

    public string VaultRootPath => _vaultRoot;
    public string DropzonePath => Path.Combine(_vaultRoot, "Dropzone");
    public string SessionsPath => Path.Combine(_vaultRoot, "Sessions");
    public string ClipsPath => Path.Combine(_vaultRoot, "Clips");
    public string ArchivesPath => Path.Combine(_vaultRoot, "Archives");
    public string SnapshotsDirectory => _snapshotsDir;
    public bool IsWatching => _watcher is { EnableRaisingEvents: true };

    /// <summary>
    /// Ensures %USERPROFILE%\DelgadoLogic Cloud and all standard subdirectories + hidden .snapshots exist.
    /// </summary>
    public void InitializeVault()
    {
        Directory.CreateDirectory(_vaultRoot);
        foreach (var sub in StandardSubdirectories)
        {
            Directory.CreateDirectory(Path.Combine(_vaultRoot, sub));
        }

        var snapDirInfo = Directory.CreateDirectory(_snapshotsDir);
        try
        {
            if ((snapDirInfo.Attributes & FileAttributes.Hidden) == 0)
            {
                snapDirInfo.Attributes |= FileAttributes.Hidden;
            }
        }
        catch
        {
            // Ignore attribute errors on restricted filesystems
        }
    }

    public void StartWatching()
    {
        InitializeVault();

        lock (_watcherGate)
        {
            if (_watcher is not null)
            {
                _watcher.EnableRaisingEvents = true;
                return;
            }

            _watcher = new FileSystemWatcher(_vaultRoot)
            {
                IncludeSubdirectories = true,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.DirectoryName | NotifyFilters.LastWrite | NotifyFilters.Size,
                InternalBufferSize = 65536
            };

            _watcher.Created += (_, e) => OnFileSystemEvent("Created", e.FullPath);
            _watcher.Changed += (_, e) => OnFileSystemEvent("Changed", e.FullPath);
            _watcher.Renamed += (_, e) => OnFileSystemEvent("Renamed", e.FullPath);
            _watcher.EnableRaisingEvents = true;
        }
    }

    public void StopWatching()
    {
        lock (_watcherGate)
        {
            _debounceCts?.Cancel();
            _debounceCts?.Dispose();
            _debounceCts = null;

            if (_watcher is not null)
            {
                _watcher.EnableRaisingEvents = false;
                _watcher.Dispose();
                _watcher = null;
            }
        }
    }

    /// <summary>
    /// Enumerates all live user files across Dropzone, Sessions, Clips, Archives, and root (excluding .snapshots).
    /// </summary>
    public IReadOnlyList<VaultFileItem> ListVaultFiles()
    {
        InitializeVault();
        var items = new List<VaultFileItem>();

        foreach (var file in EnumerateTrackedVaultFiles())
        {
            try
            {
                var fi = new FileInfo(file);
                if (!fi.Exists) continue;
                var rel = Path.GetRelativePath(_vaultRoot, fi.FullName);
                var firstSep = rel.IndexOfAny([Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar]);
                var category = firstSep > 0 ? rel[..firstSep] : "Root";

                items.Add(new VaultFileItem(
                    rel,
                    fi.FullName,
                    category,
                    fi.Length,
                    new DateTimeOffset(fi.LastWriteTimeUtc, TimeSpan.Zero)));
            }
            catch
            {
                // File may have been transiently removed
            }
        }

        return items
            .OrderByDescending(i => i.LastModifiedUtc)
            .ThenBy(i => i.RelativePath, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    /// <summary>
    /// Lists all recorded .lfc snapshots in reverse chronological order, reconciling with .snapshots on disk.
    /// </summary>
    public IReadOnlyList<VaultSnapshotRecord> ListSnapshots()
    {
        InitializeVault();
        var records = LoadIndexSafe()
            .Where(r => !string.IsNullOrWhiteSpace(r.ArchivePath) && File.Exists(r.ArchivePath))
            .OrderByDescending(r => r.CreatedAtUtc)
            .ToList();

        // Reconcile any orphaned .lfc files in .snapshots that aren't in index.json
        var knownPaths = new HashSet<string>(records.Select(r => Path.GetFullPath(r.ArchivePath)), StringComparer.OrdinalIgnoreCase);
        using var reader = new LfcReader();

        foreach (var lfcFile in Directory.EnumerateFiles(_snapshotsDir, "*.lfc", SearchOption.TopDirectoryOnly))
        {
            var full = Path.GetFullPath(lfcFile);
            if (knownPaths.Contains(full))
                continue;

            try
            {
                var info = reader.InspectArchive(full);
                var fi = new FileInfo(full);
                using var fs = File.OpenRead(full);
                var sha = Convert.ToHexString(SHA256.HashData(fs));

                records.Add(new VaultSnapshotRecord
                {
                    SnapshotId = Path.GetFileNameWithoutExtension(full),
                    ArchiveFileName = fi.Name,
                    ArchivePath = full,
                    CreatedAtUtc = new DateTimeOffset(fi.CreationTimeUtc, TimeSpan.Zero),
                    TriggerReason = "Discovered",
                    FileCount = info.TotalFiles,
                    UniqueChunks = info.TotalUniqueChunks,
                    RawBytes = info.TotalRawBytes,
                    CompressedBytes = fi.Length,
                    CompressionRatio = info.SpaceReductionRatio,
                    ContentTreeSha256 = sha,
                    ArchiveSha256 = sha
                });
            }
            catch
            {
                // Ignore corrupt or incomplete non-indexed file
            }
        }

        return records.OrderByDescending(r => r.CreatedAtUtc).ToArray();
    }

    /// <summary>
    /// Creates a content-addressed Zstd-compressed .lfc snapshot of the vault in .snapshots\.
    /// Deduplicates automatically if the vault's content tree hash matches an existing snapshot.
    /// </summary>
    public async Task<VaultSnapshotRecord> CreateSnapshotAsync(
        string triggerReason = "Manual",
        CompressionTier tier = CompressionTier.Hot,
        bool forceEvenIfUnchanged = false,
        CancellationToken ct = default)
    {
        InitializeVault();
        await _snapshotLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await WaitForTransientLocksAsync(ct).ConfigureAwait(false);

            var contentTreeHash = await ComputeVaultContentTreeSha256Async(ct).ConfigureAwait(false);
            var existingIndex = LoadIndexSafe();

            if (!forceEvenIfUnchanged)
            {
                var duplicate = existingIndex
                    .OrderByDescending(r => r.CreatedAtUtc)
                    .FirstOrDefault(r =>
                        string.Equals(r.ContentTreeSha256, contentTreeHash, StringComparison.OrdinalIgnoreCase) &&
                        File.Exists(r.ArchivePath));

                if (duplicate is not null)
                {
                    return duplicate with { WasDeduplicated = true };
                }
            }

            var now = DateTimeOffset.UtcNow;
            var shortHash = contentTreeHash[..12].ToLowerInvariant();
            var snapshotId = $"{now:yyyyMMdd_HHmmssfff}_{shortHash}";
            var finalFileName = $"{snapshotId}.lfc";
            var finalArchivePath = Path.Combine(_snapshotsDir, finalFileName);
            var tempArchivePath = finalArchivePath + ".tmp";

            bool prevSuppress = _suppressWatcher;
            _suppressWatcher = true;
            try
            {
                using var writer = new LfcWriter();
                var packOptions = new LfcPackOptions
                {
                    Tier = tier,
                    EnableDeltaCompression = true,
                    TrainDictionary = false,
                    ExcludedPaths = [_snapshotsDir]
                };

                await writer.PackDirectoryAsync(_vaultRoot, tempArchivePath, packOptions, null, ct).ConfigureAwait(false);

                using var reader = new LfcReader();
                var info = reader.InspectArchive(tempArchivePath);

                string archiveSha;
                await using (var fs = new FileStream(tempArchivePath, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, useAsync: true))
                {
                    archiveSha = Convert.ToHexString(await SHA256.HashDataAsync(fs, ct).ConfigureAwait(false));
                }

                File.Move(tempArchivePath, finalArchivePath, overwrite: true);
                var archiveFi = new FileInfo(finalArchivePath);

                var record = new VaultSnapshotRecord
                {
                    SnapshotId = snapshotId,
                    ArchiveFileName = finalFileName,
                    ArchivePath = finalArchivePath,
                    CreatedAtUtc = now,
                    TriggerReason = triggerReason,
                    FileCount = info.TotalFiles,
                    UniqueChunks = info.TotalUniqueChunks,
                    RawBytes = info.TotalRawBytes,
                    CompressedBytes = archiveFi.Length,
                    CompressionRatio = archiveFi.Length > 0 && info.TotalRawBytes > 0
                        ? Math.Round((double)info.TotalRawBytes / archiveFi.Length, 2)
                        : 1.0,
                    ContentTreeSha256 = contentTreeHash,
                    ArchiveSha256 = archiveSha,
                    WasDeduplicated = false
                };

                existingIndex.RemoveAll(r => string.Equals(r.SnapshotId, snapshotId, StringComparison.OrdinalIgnoreCase));
                existingIndex.Add(record);
                SaveIndexSafe(existingIndex);

                SnapshotCreated?.Invoke(this, record);
                return record;
            }
            finally
            {
                try { if (File.Exists(tempArchivePath)) File.Delete(tempArchivePath); } catch { }
                _suppressWatcher = prevSuppress;
            }
        }
        finally
        {
            _snapshotLock.Release();
        }
    }

    /// <summary>
    /// Restores a .lfc snapshot with end-to-end BLAKE3 chunk &amp; file hash verification via LfcReader.
    /// </summary>
    public async Task<VaultRestoreResult> RestoreSnapshotAsync(
        string snapshotId,
        string? targetDirectory = null,
        bool cleanExtraneousFiles = true,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(snapshotId);
        InitializeVault();

        var snapshot = ListSnapshots()
            .FirstOrDefault(s => string.Equals(s.SnapshotId, snapshotId, StringComparison.OrdinalIgnoreCase));

        if (snapshot is null || !File.Exists(snapshot.ArchivePath))
        {
            return new VaultRestoreResult(false, snapshotId, targetDirectory ?? _vaultRoot, 0, 0, $"Snapshot '{snapshotId}' not found.");
        }

        var destRoot = Path.GetFullPath(string.IsNullOrWhiteSpace(targetDirectory) ? _vaultRoot : targetDirectory!);
        bool restoringInPlace = string.Equals(
            destRoot.TrimEnd(Path.DirectorySeparatorChar),
            _vaultRoot.TrimEnd(Path.DirectorySeparatorChar),
            StringComparison.OrdinalIgnoreCase);

        await _snapshotLock.WaitAsync(ct).ConfigureAwait(false);
        bool prevSuppress = _suppressWatcher;
        _suppressWatcher = true;
        try
        {
            using var reader = new LfcReader();
            var archiveInfo = reader.InspectArchive(snapshot.ArchivePath);

            Directory.CreateDirectory(destRoot);
            await reader.UnpackArchiveAsync(
                snapshot.ArchivePath,
                destRoot,
                new LfcUnpackOptions { Overwrite = true, VerifyHashes = true },
                null,
                ct).ConfigureAwait(false);

            if (restoringInPlace && cleanExtraneousFiles && archiveInfo.Manifest is not null)
            {
                var expectedFiles = new HashSet<string>(
                    archiveInfo.Manifest.Files.Select(f => NormalizeRelPath(f.RelativePath)),
                    StringComparer.OrdinalIgnoreCase);

                foreach (var liveFile in EnumerateTrackedVaultFiles())
                {
                    var rel = NormalizeRelPath(Path.GetRelativePath(_vaultRoot, liveFile));
                    if (!expectedFiles.Contains(rel))
                    {
                        try
                        {
                            File.SetAttributes(liveFile, FileAttributes.Normal);
                            File.Delete(liveFile);
                        }
                        catch (Exception ex)
                        {
                            _logger.LogWarning(ex, "[OmniHub.CloudVault] Could not remove extraneous file {File} during restore.", liveFile);
                        }
                    }
                }

                // Ensure standard directories remain present even if empty in the snapshot
                foreach (var sub in StandardSubdirectories)
                {
                    Directory.CreateDirectory(Path.Combine(_vaultRoot, sub));
                }
            }

            return new VaultRestoreResult(
                true,
                snapshot.SnapshotId,
                destRoot,
                archiveInfo.TotalFiles,
                archiveInfo.TotalRawBytes,
                $"Restored {archiveInfo.TotalFiles} {(archiveInfo.TotalFiles == 1 ? "file" : "files")} ({OmniHubBrandConstants.FormatBytes(archiveInfo.TotalRawBytes)}) from snapshot {snapshot.SnapshotId}.");
        }
        finally
        {
            _suppressWatcher = prevSuppress;
            _snapshotLock.Release();
        }
    }

    /// <summary>
    /// Packs an external folder or file directory into %USERPROFILE%\DelgadoLogic Cloud\Archives\{name}.lfc.
    /// </summary>
    public async Task<string> PackExternalDirectoryToVaultAsync(
        string sourceDirectory,
        string? archiveName = null,
        CompressionTier tier = CompressionTier.Hot,
        CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sourceDirectory);
        if (!Directory.Exists(sourceDirectory))
            throw new DirectoryNotFoundException($"Directory not found: {sourceDirectory}");

        InitializeVault();
        var baseName = string.IsNullOrWhiteSpace(archiveName)
            ? $"{new DirectoryInfo(sourceDirectory).Name}_{DateTimeOffset.UtcNow:yyyyMMdd_HHmmss}"
            : Path.GetFileNameWithoutExtension(archiveName);

        var safeName = string.Concat(baseName.Select(c => Path.GetInvalidFileNameChars().Contains(c) ? '_' : c));
        var outputLfcPath = Path.Combine(ArchivesPath, $"{safeName}.lfc");

        using var writer = new LfcWriter();
        await writer.PackDirectoryAsync(
            sourceDirectory,
            outputLfcPath,
            new LfcPackOptions { Tier = tier, EnableDeltaCompression = true },
            null,
            ct).ConfigureAwait(false);

        return outputLfcPath;
    }

    // ─── Internals ───────────────────────────────────────────────────────────

    private void OnFileSystemEvent(string changeType, string fullPath)
    {
        if (_suppressWatcher || _disposed || string.IsNullOrWhiteSpace(fullPath))
            return;

        if (IsIgnoredPath(fullPath))
            return;

        string relPath;
        try
        {
            relPath = Path.GetRelativePath(_vaultRoot, fullPath);
        }
        catch
        {
            return;
        }

        VaultChanged?.Invoke(this, new VaultFileChangeNotification(changeType, relPath, DateTimeOffset.UtcNow));

        lock (_watcherGate)
        {
            if (_disposed) return;
            _pendingTriggerReason = $"{changeType}: {relPath}";
            _debounceCts?.Cancel();
            _debounceCts?.Dispose();
            _debounceCts = new CancellationTokenSource();
            var token = _debounceCts.Token;

            _ = Task.Run(async () =>
            {
                try
                {
                    await Task.Delay(_debounceDelay, token).ConfigureAwait(false);
                    if (token.IsCancellationRequested || _suppressWatcher || _disposed)
                        return;

                    string reason;
                    lock (_watcherGate) { reason = _pendingTriggerReason; }
                    await CreateSnapshotAsync(reason, CompressionTier.Hot, forceEvenIfUnchanged: false, token).ConfigureAwait(false);
                }
                catch (OperationCanceledException)
                {
                    // Superseded by newer file event
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "[OmniHub.CloudVault] Debounced auto-snapshot skipped due to transient error.");
                }
            }, CancellationToken.None);
        }
    }

    private bool IsIgnoredPath(string fullPath)
    {
        var normalized = Path.GetFullPath(fullPath);
        if (LfcWriter.IsExcludedByPathBoundary(normalized, [_snapshotsDir]))
            return true;

        var fileName = Path.GetFileName(normalized);
        if (string.IsNullOrEmpty(fileName))
            return true;

        return fileName.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase) ||
               fileName.EndsWith(".part", StringComparison.OrdinalIgnoreCase) ||
               fileName.StartsWith(".omnihub_", StringComparison.OrdinalIgnoreCase);
    }

    private IEnumerable<string> EnumerateTrackedVaultFiles()
    {
        if (!Directory.Exists(_vaultRoot))
            yield break;

        foreach (var file in Directory.EnumerateFiles(_vaultRoot, "*", SearchOption.AllDirectories))
        {
            if (!IsIgnoredPath(file))
                yield return file;
        }
    }

    private async Task<string> ComputeVaultContentTreeSha256Async(CancellationToken ct)
    {
        var files = EnumerateTrackedVaultFiles()
            .Select(f => (FullPath: f, RelPath: NormalizeRelPath(Path.GetRelativePath(_vaultRoot, f))))
            .OrderBy(x => x.RelPath, StringComparer.Ordinal)
            .ToArray();

        using var treeHasher = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        if (files.Length == 0)
        {
            treeHasher.AppendData("EMPTY_VAULT_V1"u8);
            return Convert.ToHexString(treeHasher.GetHashAndReset());
        }

        foreach (var (fullPath, relPath) in files)
        {
            ct.ThrowIfCancellationRequested();
            await using var fs = new FileStream(fullPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite, 65536, useAsync: true);
            var fileHash = await SHA256.HashDataAsync(fs, ct).ConfigureAwait(false);
            var line = $"{relPath}|{fs.Length}|{Convert.ToHexString(fileHash)}\n";
            treeHasher.AppendData(Encoding.UTF8.GetBytes(line));
        }

        return Convert.ToHexString(treeHasher.GetHashAndReset());
    }

    private async Task WaitForTransientLocksAsync(CancellationToken ct)
    {
        foreach (var file in EnumerateTrackedVaultFiles())
        {
            for (int attempt = 0; attempt < 5; attempt++)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read);
                    break;
                }
                catch (IOException) when (attempt < 4)
                {
                    await Task.Delay(40, ct).ConfigureAwait(false);
                }
                catch
                {
                    break;
                }
            }
        }
    }

    private List<VaultSnapshotRecord> LoadIndexSafe()
    {
        try
        {
            if (File.Exists(_indexFilePath))
            {
                var json = File.ReadAllText(_indexFilePath);
                return JsonSerializer.Deserialize<List<VaultSnapshotRecord>>(json, IndexJsonOpts) ?? [];
            }
        }
        catch
        {
            // Ignore corrupt index; ListSnapshots reconciles from .lfc files on disk
        }
        return [];
    }

    private void SaveIndexSafe(List<VaultSnapshotRecord> records)
    {
        Directory.CreateDirectory(_snapshotsDir);
        var ordered = records.OrderByDescending(r => r.CreatedAtUtc).ToList();
        var tmp = _indexFilePath + ".tmp";
        File.WriteAllText(tmp, JsonSerializer.Serialize(ordered, IndexJsonOpts));
        File.Move(tmp, _indexFilePath, overwrite: true);
    }

    private static string NormalizeRelPath(string relPath) =>
        relPath.Replace('/', '\\').TrimStart('\\');

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        StopWatching();
        _snapshotLock.Dispose();
    }
}
