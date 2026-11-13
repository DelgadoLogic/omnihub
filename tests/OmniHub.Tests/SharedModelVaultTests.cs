using System.Security.Cryptography;
using OmniHub.Core;

namespace OmniHub.Tests;

public sealed class SharedModelVaultTests : IDisposable
{
    private const int MultiMegabyteGgufSize = 2_621_440; // 2.50 MB

    private readonly string _tempRoot;
    private readonly string _vaultRoot;
    private readonly string _logicFlowModelsDir;
    private readonly string _aeonModelsDir;

    public SharedModelVaultTests()
    {
        _tempRoot = Path.Combine(Path.GetTempPath(), $"omnihub_models_tests_{Guid.NewGuid():N}");
        _vaultRoot = Path.Combine(_tempRoot, "ProgramDataModels");
        _logicFlowModelsDir = Path.Combine(_tempRoot, "LogicFlow", "Models");
        _aeonModelsDir = Path.Combine(_tempRoot, "Aeon", "models");

        Directory.CreateDirectory(_vaultRoot);
        Directory.CreateDirectory(_logicFlowModelsDir);
        Directory.CreateDirectory(_aeonModelsDir);
    }

    [Fact]
    public async Task InspectGgufHeader_ValidGgufV3AndInvalidPayloads_DetectsMagicAndVersionAccurately()
    {
        var validGguf = Path.Combine(_tempRoot, "valid_v3.gguf");
        await WriteSyntheticGgufV3Async(validGguf, 4096, seed: 7);

        var (isValid, ver) = SharedModelVaultService.InspectGgufHeader(validGguf);
        Assert.True(isValid);
        Assert.Equal(3, ver);

        var invalidFile = Path.Combine(_tempRoot, "not_gguf.gguf");
        await File.WriteAllBytesAsync(invalidFile, "NOT_A_GGUF_HEADER"u8.ToArray());

        var (badValid, badVer) = SharedModelVaultService.InspectGgufHeader(invalidFile);
        Assert.False(badValid);
        Assert.Null(badVer);
    }

    [Fact]
    public async Task ComputeStreamingSha256Async_MultiMegabyteGguf_MatchesCryptographicDigest()
    {
        var ggufPath = Path.Combine(_tempRoot, "stream_hash_test.gguf");
        var expectedHex = await WriteSyntheticGgufV3Async(ggufPath, MultiMegabyteGgufSize, seed: 0x2A);

        var actualHex = await SharedModelVaultService.ComputeStreamingSha256Async(ggufPath);
        Assert.Equal(expectedHex, actualHex);
    }

    [Fact]
    public async Task DeduplicateAndLinkAllAsync_MultiMegabyteDuplicateGgufAcrossLogicFlowAndAeon_CreatesNtfsHardLinksAndCalculatesExactBytesSaved()
    {
        const string modelFileName = "gemma-4-E4B-it-Q4_K_M.gguf";
        var lfCopy = Path.Combine(_logicFlowModelsDir, modelFileName);
        var aeonCopy = Path.Combine(_aeonModelsDir, modelFileName);

        // Write two separate physical 2.5 MB GGUF v3 files with identical weights
        var shaLf = await WriteSyntheticGgufV3Async(lfCopy, MultiMegabyteGgufSize, seed: 0x5C);
        var shaAeon = await WriteSyntheticGgufV3Async(aeonCopy, MultiMegabyteGgufSize, seed: 0x5C);
        Assert.Equal(shaLf, shaAeon);
        Assert.False(SharedModelVaultService.AreSamePhysicalFile(lfCopy, aeonCopy));

        var svc = CreateVaultService();
        var report = await svc.DeduplicateAndLinkAllAsync();

        var sharedVaultFile = Path.Combine(_vaultRoot, modelFileName);
        Assert.True(File.Exists(sharedVaultFile));
        Assert.Equal(2, report.ModelsInspected);
        Assert.Equal(2, report.HardLinksCreated); // 1 ingest link into vault + 1 duplicate replacement link

        // All 3 paths (Vault, LogicFlow, Aeon) now point to the exact same NTFS physical MFT record!
        Assert.True(SharedModelVaultService.AreSamePhysicalFile(sharedVaultFile, lfCopy));
        Assert.True(SharedModelVaultService.AreSamePhysicalFile(sharedVaultFile, aeonCopy));
        Assert.True(SharedModelVaultService.GetHardLinkCount(sharedVaultFile) >= 3u);

        // Replacing Aeon's duplicate physical file saved 2.5 MB this run; active savings across 3 links = 2 * 2.5 MB = 5.0 MB
        Assert.Equal(MultiMegabyteGgufSize, report.BytesSavedThisRun);
        Assert.Equal(MultiMegabyteGgufSize * 2L, report.TotalActiveHardLinkSavingsBytes);

        // Content SHA-256 remains bit-identical
        Assert.Equal(shaLf, await SharedModelVaultService.ComputeStreamingSha256Async(sharedVaultFile));
        Assert.Equal(shaLf, await SharedModelVaultService.ComputeStreamingSha256Async(aeonCopy));
    }

    [Fact]
    public async Task DeduplicateAndLinkAllAsync_SecondInvocation_IsIdempotentWithZeroNewLinksAndPreservesActiveSavings()
    {
        const string modelFileName = "bge-small-en-v1.5-q8_0.gguf";
        var lfCopy = Path.Combine(_logicFlowModelsDir, modelFileName);
        var aeonCopy = Path.Combine(_aeonModelsDir, modelFileName);

        await WriteSyntheticGgufV3Async(lfCopy, MultiMegabyteGgufSize, seed: 0x91);
        await WriteSyntheticGgufV3Async(aeonCopy, MultiMegabyteGgufSize, seed: 0x91);

        var svc = CreateVaultService();
        var firstRun = await svc.DeduplicateAndLinkAllAsync();
        Assert.Equal(2, firstRun.HardLinksCreated);

        var secondRun = await svc.DeduplicateAndLinkAllAsync();
        Assert.Equal(0, secondRun.HardLinksCreated);
        Assert.Equal(2, secondRun.AlreadyHardLinkedCount);
        Assert.Equal(0L, secondRun.BytesSavedThisRun);
        Assert.Equal(MultiMegabyteGgufSize * 2L, secondRun.TotalActiveHardLinkSavingsBytes);
    }

    [Fact]
    public async Task DeduplicateAndLinkAllAsync_SameFileNameWithDifferentWeightsSha256_NeverOverwritesOrCorrupts()
    {
        const string customModel = "custom-finetune-q4.gguf";
        var lfCopy = Path.Combine(_logicFlowModelsDir, customModel);
        var aeonDivergentCopy = Path.Combine(_aeonModelsDir, customModel);

        // Same byte length, different tensor weights -> different SHA-256
        var shaLf = await WriteSyntheticGgufV3Async(lfCopy, 524_288, seed: 0x10);
        var shaAeon = await WriteSyntheticGgufV3Async(aeonDivergentCopy, 524_288, seed: 0x20);
        Assert.NotEqual(shaLf, shaAeon);

        var svc = CreateVaultService();
        var report = await svc.DeduplicateAndLinkAllAsync();

        var vaultCopy = Path.Combine(_vaultRoot, customModel);
        Assert.True(SharedModelVaultService.AreSamePhysicalFile(vaultCopy, lfCopy));
        Assert.False(SharedModelVaultService.AreSamePhysicalFile(vaultCopy, aeonDivergentCopy));

        // Aeon's distinct file must remain completely intact with its original SHA-256
        Assert.Equal(shaAeon, await SharedModelVaultService.ComputeStreamingSha256Async(aeonDivergentCopy));
        Assert.Contains(report.ActionsLog, msg => msg.Contains("SHA-256 differs", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task ProvisionModelToDirectoryAsync_ZeroCopyLinksSharedVaultModelIntoConsumerFolder()
    {
        const string modelName = "gemma-4-E2B-it-Q4_K_M.gguf";
        var vaultModelPath = Path.Combine(_vaultRoot, modelName);
        var expectedSha = await WriteSyntheticGgufV3Async(vaultModelPath, 1_048_576, seed: 0x33);

        var svc = CreateVaultService();
        var consumerDir = Path.Combine(_tempRoot, "NewConsumerApp", "models");

        var (success, isHardLink, _) = await svc.ProvisionModelToDirectoryAsync(modelName, consumerDir);
        Assert.True(success);
        Assert.True(isHardLink);

        var provisionedFile = Path.Combine(consumerDir, modelName);
        Assert.True(File.Exists(provisionedFile));
        Assert.True(SharedModelVaultService.AreSamePhysicalFile(vaultModelPath, provisionedFile));
        Assert.Equal(expectedSha, await SharedModelVaultService.ComputeStreamingSha256Async(provisionedFile));
    }

    [Fact]
    public async Task ScanCatalogAsync_ReportsCanonicalCatalogEntries_PinnedChecksumMatch_AndLinkCounts()
    {
        const string e4bName = "gemma-4-E4B-it-Q4_K_M.gguf";
        var vaultE4b = Path.Combine(_vaultRoot, e4bName);
        var sha = await WriteSyntheticGgufV3Async(vaultE4b, 262_144, seed: 0x77);

        var svc = CreateVaultService();
        await svc.ProvisionModelToDirectoryAsync(e4bName, _aeonModelsDir);

        var catalog = await svc.ScanCatalogAsync(computeSha256: true);
        Assert.True(catalog.Count >= 3);

        var e4bEntry = Assert.Single(catalog, c => c.FileName == e4bName);
        Assert.True(e4bEntry.IsCanonical);
        Assert.True(e4bEntry.ExistsInSharedVault);
        Assert.True(e4bEntry.HasValidGgufHeader);
        Assert.Equal(3, e4bEntry.GgufFormatVersion);
        Assert.Equal(sha, e4bEntry.Sha256Hex);
        Assert.True(e4bEntry.HardLinkCount >= 2u);
        Assert.Single(e4bEntry.LinkedExternalPaths);

        // E2B has a pinned production SHA-256; verify synthetic weights report PinnedChecksumMatches == false
        var vaultE2b = Path.Combine(_vaultRoot, "gemma-4-E2B-it-Q4_K_M.gguf");
        await WriteSyntheticGgufV3Async(vaultE2b, 65_536, seed: 0x01);
        var rescanned = await svc.ScanCatalogAsync(computeSha256: true);
        var e2bEntry = Assert.Single(rescanned, c => c.FileName == "gemma-4-E2B-it-Q4_K_M.gguf");
        Assert.False(e2bEntry.PinnedChecksumMatches);
    }

    [Fact]
    public void DpapiProtector_RoundTripsBytesAndUtf8Strings_AndRejectsTamperedCiphertext()
    {
        const string secretSession = """{"cookies":[{"name":"sid","value":"secret-token-value-12345"}]}""";
        var encrypted = DpapiProtector.ProtectString(secretSession);

        Assert.NotEmpty(encrypted);
        var restored = DpapiProtector.UnprotectString(encrypted);
        Assert.Equal(secretSession, restored);

        // Corrupt ciphertext and verify CryptographicException fail-closed
        encrypted[^1] ^= 0xFF;
        encrypted[^2] ^= 0xAA;
        Assert.Throws<CryptographicException>(() => DpapiProtector.UnprotectString(encrypted));
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────

    private SharedModelVaultService CreateVaultService() => new(new SharedModelVaultOptions
    {
        VaultRootOverride = _vaultRoot,
        ExternalScanDirectoriesOverride = [_logicFlowModelsDir, _aeonModelsDir],
        WorkspaceRootOverride = Path.Combine(_tempRoot, "EmptyWs")
    });

    private static async Task<string> WriteSyntheticGgufV3Async(string path, int totalBytes, byte seed)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var buffer = new byte[totalBytes];
        // GGUF magic ('G', 'G', 'U', 'F') + little-endian uint32 version 3
        buffer[0] = 0x47;
        buffer[1] = 0x47;
        buffer[2] = 0x55;
        buffer[3] = 0x46;
        buffer[4] = 0x03;
        buffer[5] = 0x00;
        buffer[6] = 0x00;
        buffer[7] = 0x00;

        uint state = (uint)(0x9E3779B9u ^ seed);
        for (int i = 8; i < totalBytes; i++)
        {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            buffer[i] = (byte)(state & 0xFF);
        }

        await File.WriteAllBytesAsync(path, buffer);
        return Convert.ToHexString(SHA256.HashData(buffer));
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
