using System.Security.Cryptography;
using System.Text;
using LogicFlow.Storage.Engine.Compression;
using LogicFlow.Storage.Engine.Container;
using OmniHub.Core;

namespace OmniHub.Tests;

public sealed class CloudVaultSyncTests : IDisposable
{
    private readonly string _tempRoot;
    private readonly string _vaultRoot;

    public CloudVaultSyncTests()
    {
        _tempRoot = Path.Combine(Path.GetTempPath(), $"omnihub_vault_tests_{Guid.NewGuid():N}");
        _vaultRoot = Path.Combine(_tempRoot, "DelgadoLogic Cloud");
        Directory.CreateDirectory(_tempRoot);
    }

    [Fact]
    public void InitializeVault_CreatesStandardSubdirectoriesAndHiddenSnapshotsFolder()
    {
        using var vault = new CloudVaultSyncService(_vaultRoot);
        vault.InitializeVault();

        Assert.True(Directory.Exists(vault.VaultRootPath));
        Assert.True(Directory.Exists(vault.DropzonePath));
        Assert.True(Directory.Exists(vault.SessionsPath));
        Assert.True(Directory.Exists(vault.ClipsPath));
        Assert.True(Directory.Exists(vault.ArchivesPath));
        Assert.True(Directory.Exists(vault.SnapshotsDirectory));

        var snapDirInfo = new DirectoryInfo(vault.SnapshotsDirectory);
        Assert.True((snapDirInfo.Attributes & FileAttributes.Hidden) != 0);
    }

    [Fact]
    public async Task CreateSnapshotAsync_PacksRealZstdLfcArchive_InspectableByLfcReader()
    {
        using var vault = new CloudVaultSyncService(_vaultRoot);
        vault.InitializeVault();

        var docPath = Path.Combine(vault.DropzonePath, "architecture.md");
        var clipPath = Path.Combine(vault.ClipsPath, "research_note.md");
        var docContent = string.Concat(Enumerable.Repeat("# DelgadoLogic Sovereign Storage Architecture\n", 120));
        await File.WriteAllTextAsync(docPath, docContent, Encoding.UTF8);
        await File.WriteAllTextAsync(clipPath, "---\ntitle: \"Clip\"\n---\nBody payload.", Encoding.UTF8);

        var snapshot = await vault.CreateSnapshotAsync("UnitTestManual", CompressionTier.Hot);

        Assert.False(snapshot.WasDeduplicated);
        Assert.True(File.Exists(snapshot.ArchivePath));
        Assert.Equal(2, snapshot.FileCount);
        Assert.True(snapshot.RawBytes > 0);
        Assert.True(snapshot.CompressedBytes > 0);
        Assert.Equal(64, snapshot.ContentTreeSha256.Length);
        Assert.Equal(64, snapshot.ArchiveSha256.Length);

        // Verify directly with LogicFlow.Storage.Engine.Container.LfcReader
        using var reader = new LfcReader();
        var info = reader.InspectArchive(snapshot.ArchivePath);
        Assert.Equal(2, info.TotalFiles);
        Assert.True(info.TotalUniqueChunks >= 1);
    }

    [Fact]
    public async Task CreateSnapshotAsync_UnchangedVaultContent_DeduplicatesContentAddressedSnapshot()
    {
        using var vault = new CloudVaultSyncService(_vaultRoot);
        vault.InitializeVault();

        await File.WriteAllTextAsync(Path.Combine(vault.DropzonePath, "report.txt"), "Deterministic vault payload v1");

        var first = await vault.CreateSnapshotAsync("FirstPass");
        var second = await vault.CreateSnapshotAsync("SecondPassUnchanged");

        Assert.False(first.WasDeduplicated);
        Assert.True(second.WasDeduplicated);
        Assert.Equal(first.SnapshotId, second.SnapshotId);
        Assert.Equal(first.ArchivePath, second.ArchivePath);
        Assert.Single(vault.ListSnapshots());
    }

    [Fact]
    public async Task CreateSnapshotAsync_ModifiedVaultContent_CreatesDistinctSnapshotArchive()
    {
        using var vault = new CloudVaultSyncService(_vaultRoot);
        vault.InitializeVault();

        var target = Path.Combine(vault.DropzonePath, "state.json");
        await File.WriteAllTextAsync(target, "{\"revision\":1}");
        var snap1 = await vault.CreateSnapshotAsync("Rev1");

        await Task.Delay(15);
        await File.WriteAllTextAsync(target, "{\"revision\":2,\"updated\":true}");
        var snap2 = await vault.CreateSnapshotAsync("Rev2");

        Assert.NotEqual(snap1.SnapshotId, snap2.SnapshotId);
        Assert.NotEqual(snap1.ContentTreeSha256, snap2.ContentTreeSha256);
        Assert.Equal(2, vault.ListSnapshots().Count);
    }

    [Fact]
    public async Task RestoreSnapshotAsync_RestoresByteIdenticalFiles_RemovesExtraneousFiles_AndPreservesSnapshots()
    {
        using var vault = new CloudVaultSyncService(_vaultRoot);
        vault.InitializeVault();

        var fileA = Path.Combine(vault.DropzonePath, "alpha.bin");
        var fileB = Path.Combine(vault.ClipsPath, "beta.md");

        var originalBytesA = RandomNumberGenerator.GetBytes(98_304);
        var originalBytesB = Encoding.UTF8.GetBytes("# Beta Original Clip\nVerified content.");
        var shaA = Convert.ToHexString(SHA256.HashData(originalBytesA));
        var shaB = Convert.ToHexString(SHA256.HashData(originalBytesB));

        await File.WriteAllBytesAsync(fileA, originalBytesA);
        await File.WriteAllBytesAsync(fileB, originalBytesB);

        var baseline = await vault.CreateSnapshotAsync("BaselineV1");

        // Mutate fileA, delete fileB, and create an extraneous fileC
        await File.WriteAllBytesAsync(fileA, RandomNumberGenerator.GetBytes(1024));
        File.Delete(fileB);
        var extraneousFileC = Path.Combine(vault.DropzonePath, "unwanted_intruder.tmpdata");
        await File.WriteAllTextAsync(extraneousFileC, "should be cleaned during in-place restore");

        var restoreResult = await vault.RestoreSnapshotAsync(baseline.SnapshotId, cleanExtraneousFiles: true);

        Assert.True(restoreResult.Success);
        Assert.Equal(2, restoreResult.FilesRestored);
        Assert.True(File.Exists(fileA));
        Assert.True(File.Exists(fileB));
        Assert.False(File.Exists(extraneousFileC));

        // Verify byte-for-byte SHA-256 identity
        Assert.Equal(shaA, Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(fileA))));
        Assert.Equal(shaB, Convert.ToHexString(SHA256.HashData(await File.ReadAllBytesAsync(fileB))));

        // Hidden .snapshots archive must remain untouched
        Assert.True(File.Exists(baseline.ArchivePath));
    }

    [Fact]
    public async Task StartWatching_DebouncedFileSystemWatcher_AutomaticallyCreatesLfcSnapshotOnFileDrop()
    {
        using var vault = new CloudVaultSyncService(_vaultRoot, debounceDelay: TimeSpan.FromMilliseconds(120));
        var tcs = new TaskCompletionSource<VaultSnapshotRecord>(TaskCreationOptions.RunContinuationsAsynchronously);
        vault.SnapshotCreated += (_, rec) => tcs.TrySetResult(rec);

        vault.StartWatching();
        Assert.True(vault.IsWatching);

        var droppedFile = Path.Combine(vault.DropzonePath, "live_drop.txt");
        await File.WriteAllTextAsync(droppedFile, "Triggered automatically via real FileSystemWatcher!");

        var createdSnapshot = await tcs.Task.WaitAsync(TimeSpan.FromSeconds(8));
        Assert.NotNull(createdSnapshot);
        Assert.True(File.Exists(createdSnapshot.ArchivePath));
        Assert.True(createdSnapshot.FileCount >= 1);

        vault.StopWatching();
        Assert.False(vault.IsWatching);
    }

    [Fact]
    public async Task PackExternalDirectoryToVaultAsync_CreatesVerifiedHyperStoreArchiveInArchivesFolder()
    {
        using var vault = new CloudVaultSyncService(_vaultRoot);
        var externalSource = Path.Combine(_tempRoot, "ExternalProject");
        Directory.CreateDirectory(Path.Combine(externalSource, "src"));
        await File.WriteAllTextAsync(Path.Combine(externalSource, "README.md"), "# External Project");
        await File.WriteAllTextAsync(Path.Combine(externalSource, "src", "main.cs"), "Console.WriteLine(\"Hello\");");

        var outputLfc = await vault.PackExternalDirectoryToVaultAsync(externalSource, "external_backup", CompressionTier.Hot);

        Assert.True(File.Exists(outputLfc));
        Assert.StartsWith(vault.ArchivesPath, outputLfc, StringComparison.OrdinalIgnoreCase);

        using var reader = new LfcReader();
        var inspect = reader.InspectArchive(outputLfc);
        Assert.Equal(2, inspect.TotalFiles);
    }

    [Fact]
    public async Task ListSnapshots_ReconcilesOrphanedLfcArchiveWhenIndexJsonMissing()
    {
        using var vault = new CloudVaultSyncService(_vaultRoot);
        vault.InitializeVault();
        await File.WriteAllTextAsync(Path.Combine(vault.DropzonePath, "reconcile.txt"), "Reconcile index test");

        var snap = await vault.CreateSnapshotAsync("BeforeIndexDelete");
        var indexJson = Path.Combine(vault.SnapshotsDirectory, "index.json");
        Assert.True(File.Exists(indexJson));
        File.Delete(indexJson);

        var discovered = vault.ListSnapshots();
        Assert.Single(discovered);
        Assert.Equal(snap.ArchivePath, discovered[0].ArchivePath);
        Assert.Equal(1, discovered[0].FileCount);
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
