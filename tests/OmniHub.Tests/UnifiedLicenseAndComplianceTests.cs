using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using DelgadoLogic.Core;
using Microsoft.Extensions.Logging.Abstractions;
using OmniHub.Core;
using OmniLicense;
using OmniPulse;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

namespace OmniHub.Tests;

public sealed class UnifiedLicenseAndComplianceTests : IDisposable
{
    private const string TestMachineHwid = "HWID_MACHINE_UNIT_TEST_001";
    private const string TestSharedDeviceId = "SHARED_DEVICE_ID_UNIT_TEST_002";

    private readonly string _tempRoot;
    private readonly string _licenseDir;
    private readonly string _pulseDir;
    private readonly string _sharedIdentityDir;
    private readonly RSA _rsaKeyPair;
    private readonly Ed25519PrivateKeyParameters _edPriv;
    private readonly Ed25519PublicKeyParameters _edPub;
    private readonly RsaLicenseValidator _testValidator;

    public UnifiedLicenseAndComplianceTests()
    {
        _tempRoot = Path.Combine(Path.GetTempPath(), $"omnihub_lic_tests_{Guid.NewGuid():N}");
        _licenseDir = Path.Combine(_tempRoot, "Licenses");
        _pulseDir = Path.Combine(_tempRoot, "Pulse");
        _sharedIdentityDir = Path.Combine(_tempRoot, "SharedIdentity");

        Directory.CreateDirectory(_licenseDir);
        Directory.CreateDirectory(_pulseDir);
        Directory.CreateDirectory(_sharedIdentityDir);

        DelgadoLogicIdentity.OverrideSharedRootForTesting = _sharedIdentityDir;

        _rsaKeyPair = RSA.Create(2048);

        var edGen = new Ed25519KeyPairGenerator();
        edGen.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        var kp = edGen.GenerateKeyPair();
        _edPriv = (Ed25519PrivateKeyParameters)kp.Private;
        _edPub = (Ed25519PublicKeyParameters)kp.Public;

        using var rsaPubOnly = RSA.Create();
        rsaPubOnly.ImportSubjectPublicKeyInfo(_rsaKeyPair.ExportSubjectPublicKeyInfo(), out _);
        var clonedRsaPub = RSA.Create();
        clonedRsaPub.ImportSubjectPublicKeyInfo(rsaPubOnly.ExportSubjectPublicKeyInfo(), out _);

        _testValidator = RsaLicenseValidator.CreateForTesting(
            NullLogger<RsaLicenseValidator>.Instance,
            clonedRsaPub,
            _edPub);
    }

    [Fact]
    public async Task GetCurrentSnapshot_ValidRsa2048ProToken_ActivatesProWith3Devices()
    {
        var licPath = Path.Combine(_licenseDir, "license.lic");
        var token = CreateRsaSignedToken(new LicenseClaims
        {
            Email = "customer@delgadologic.tech",
            BoundHwid = TestMachineHwid,
            Tier = LicenseTier.Pro,
            IssuedAt = DateTimeOffset.UtcNow.AddDays(-2),
            ExpiresAt = DateTimeOffset.UtcNow.AddYears(1),
            OrderId = "ORD-PRO-2026-001",
            SeatCount = 3,
            DeviceLimit = 3
        });

        await File.WriteAllTextAsync(licPath, JsonSerializer.Serialize(token));
        var svc = CreateLicenseService([licPath]);

        var snap = svc.GetCurrentSnapshot();
        Assert.True(snap.IsTokenCryptographicallyValid);
        Assert.True(snap.IsPaid);
        Assert.Equal(OmniHubEditionKind.Pro, snap.EditionKind);
        Assert.Equal("Pro", snap.EditionDisplayName);
        Assert.Equal(3, snap.SeatLimit);
        Assert.Equal("RSA-2048", snap.SignatureAlgorithm);
        Assert.Equal("ORD-PRO-2026-001", snap.OrderId);
        Assert.False(OmniHubBrandConstants.ContainsProhibitedCopy(snap.StatusMessage, out _));
    }

    [Fact]
    public async Task GetCurrentSnapshot_ValidEd25519EnterpriseToken_ActivatesTeam10PackWith10Seats()
    {
        var licPath = Path.Combine(_licenseDir, "license_token.json");
        var token = CreateEd25519SignedToken(new LicenseClaims
        {
            Email = "it-admin@delgadologic.tech",
            BoundHwid = TestMachineHwid,
            Tier = LicenseTier.Enterprise,
            IssuedAt = DateTimeOffset.UtcNow.AddDays(-1),
            ExpiresAt = DateTimeOffset.UtcNow.AddYears(1),
            OrderId = "ORD-TEAM10-2026",
            SeatCount = 10,
            DeviceLimit = 10
        });

        await File.WriteAllTextAsync(licPath, JsonSerializer.Serialize(token));
        var svc = CreateLicenseService([licPath]);

        var snap = svc.GetCurrentSnapshot();
        Assert.True(snap.IsTokenCryptographicallyValid);
        Assert.True(snap.IsPaid);
        Assert.Equal(OmniHubEditionKind.Team10Pack, snap.EditionKind);
        Assert.Equal("Team 10-Pack", snap.EditionDisplayName);
        Assert.Equal(10, snap.SeatLimit);
        Assert.Equal("Ed25519", snap.SignatureAlgorithm);
    }

    [Fact]
    public async Task ImportOfflineTokenAsync_Base64ArmoredEd25519LicFile_PersistsAndActivatesUnifiedLicense()
    {
        var token = CreateEd25519SignedToken(new LicenseClaims
        {
            Email = "offline@delgadologic.tech",
            BoundHwid = TestMachineHwid,
            Tier = LicenseTier.Pro,
            IssuedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(365),
            OrderId = "ORD-OFFLINE-77",
            SeatCount = 3
        });

        var base64Armored = Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(token)));
        var externalLicFile = Path.Combine(_tempRoot, "downloaded_offline.lic");
        await File.WriteAllTextAsync(externalLicFile, base64Armored);

        var targetWritePath = Path.Combine(_licenseDir, "persisted_license.lic");
        var svc = CreateLicenseService([targetWritePath], primaryWritePath: targetWritePath);

        var importRes = await svc.ImportOfflineTokenAsync(externalLicFile);
        Assert.True(importRes.Success);
        Assert.Equal(targetWritePath, importRes.PersistedPath);
        Assert.True(File.Exists(targetWritePath));
        Assert.Equal(OmniHubEditionKind.Pro, importRes.Snapshot.EditionKind);
    }

    [Fact]
    public async Task GetCurrentSnapshot_ExpiredToken_FailsClosedToFreeEdition()
    {
        var licPath = Path.Combine(_licenseDir, "expired.lic");
        var expiredToken = CreateEd25519SignedToken(new LicenseClaims
        {
            Email = "expired@delgadologic.tech",
            BoundHwid = TestMachineHwid,
            Tier = LicenseTier.Pro,
            IssuedAt = DateTimeOffset.UtcNow.AddYears(-2),
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(-1),
            OrderId = "ORD-EXP"
        });

        await File.WriteAllTextAsync(licPath, JsonSerializer.Serialize(expiredToken));
        var svc = CreateLicenseService([licPath]);

        var snap = svc.GetCurrentSnapshot();
        Assert.False(snap.IsTokenCryptographicallyValid);
        Assert.False(snap.IsPaid);
        Assert.Equal(OmniHubEditionKind.Free, snap.EditionKind);
        Assert.Contains("Expired", snap.StatusMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task GetCurrentSnapshot_TamperedPayloadSignature_FailsClosedToFreeEdition()
    {
        var licPath = Path.Combine(_licenseDir, "tampered.lic");
        var validToken = CreateRsaSignedToken(new LicenseClaims
        {
            Email = "user@delgadologic.tech",
            BoundHwid = TestMachineHwid,
            Tier = LicenseTier.Community,
            IssuedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(90),
            OrderId = "ORD-1"
        });

        // Escalate Community -> Enterprise without re-signing
        var tamperedPayload = validToken.Payload.Replace("Community", "Enterprise", StringComparison.Ordinal);
        var forgedToken = validToken with { Payload = tamperedPayload };
        await File.WriteAllTextAsync(licPath, JsonSerializer.Serialize(forgedToken));

        var svc = CreateLicenseService([licPath]);
        var snap = svc.GetCurrentSnapshot();
        Assert.False(snap.IsTokenCryptographicallyValid);
        Assert.False(snap.IsPaid);
        Assert.Equal(OmniHubEditionKind.Free, snap.EditionKind);
    }

    [Fact]
    public async Task GetCurrentSnapshot_MismatchedHardwareId_FailsClosedToFreeEdition()
    {
        var licPath = Path.Combine(_licenseDir, "other_pc.lic");
        var otherPcToken = CreateEd25519SignedToken(new LicenseClaims
        {
            Email = "user@delgadologic.tech",
            BoundHwid = "DIFFERENT_MACHINE_HWID_99999",
            Tier = LicenseTier.Pro,
            IssuedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(180),
            OrderId = "ORD-OTHER"
        });

        await File.WriteAllTextAsync(licPath, JsonSerializer.Serialize(otherPcToken));
        var svc = CreateLicenseService([licPath]);

        var snap = svc.GetCurrentSnapshot();
        Assert.False(snap.IsTokenCryptographicallyValid);
        Assert.Equal(OmniHubEditionKind.Free, snap.EditionKind);
        Assert.Contains("HWID mismatch", snap.StatusMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task GetCurrentSnapshot_BoundToSharedDelgadoLogicDeviceId_SucceedsAcrossApps()
    {
        var licPath = Path.Combine(_licenseDir, "shared_id.lic");
        var token = CreateEd25519SignedToken(new LicenseClaims
        {
            Email = "crossapp@delgadologic.tech",
            BoundHwid = TestSharedDeviceId,
            Tier = LicenseTier.Pro,
            IssuedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(365),
            OrderId = "ORD-CROSSAPP"
        });

        await File.WriteAllTextAsync(licPath, JsonSerializer.Serialize(token));
        var svc = CreateLicenseService([licPath]);

        var snap = svc.GetCurrentSnapshot();
        Assert.True(snap.IsTokenCryptographicallyValid);
        Assert.Equal(OmniHubEditionKind.Pro, snap.EditionKind);
        Assert.Equal(TestSharedDeviceId, snap.BoundHwid);
    }

    [Theory]
    [InlineData(LicenseTier.FounderPass)]
    [InlineData(LicenseTier.SovereignSuite)]
    [InlineData(LicenseTier.Family)]
    public async Task RetiredSkuSanitization_LegacyFounderPassSovereignSuiteAndFamilyTokens_MapStrictlyToProWithZeroRetiredSkuCopy(
        LicenseTier legacyTier)
    {
        var licPath = Path.Combine(_licenseDir, $"legacy_{legacyTier}.lic");
        var token = CreateEd25519SignedToken(new LicenseClaims
        {
            Email = "legacy@delgadologic.tech",
            BoundHwid = TestMachineHwid,
            Tier = legacyTier,
            IssuedAt = DateTimeOffset.UtcNow.AddDays(-30),
            ExpiresAt = DateTimeOffset.UtcNow.AddDays(300),
            OrderId = $"ORD-LEGACY-{legacyTier}",
            SeatCount = 3,
            DeviceLimit = 3
        });

        await File.WriteAllTextAsync(licPath, JsonSerializer.Serialize(token));
        var svc = CreateLicenseService([licPath]);

        var snap = svc.GetCurrentSnapshot();
        Assert.True(snap.IsTokenCryptographicallyValid);
        Assert.True(snap.IsPaid);
        Assert.Equal(OmniHubEditionKind.Pro, snap.EditionKind);
        Assert.Equal("Pro", snap.EditionDisplayName);

        Assert.False(OmniHubBrandConstants.ContainsProhibitedCopy(snap.EditionDisplayName, out var v1), v1);
        Assert.False(OmniHubBrandConstants.ContainsProhibitedCopy(snap.StatusMessage, out var v2), v2);
    }

    [Fact]
    public void ConsentStoreIntegration_DefaultIsConsentLevelNoneFree_AndCommunityActivatesWhenStandardPseudonymousAccepted()
    {
        var consent = new ConsentStore(_pulseDir, (_, _) => null);

        // Default first-run state MUST be ConsentLevel.None (telemetry OFF by default) and Free edition
        Assert.Equal(ConsentLevel.None, consent.Current.Level);
        Assert.Equal(ConsentLevel.None, consent.EffectiveLevel());
        Assert.False(consent.CommunityConditionAccepted());

        var svc = CreateLicenseService([Path.Combine(_licenseDir, "none.lic")], consentStore: consent);
        var defaultSnap = svc.GetCurrentSnapshot();
        Assert.Equal(OmniHubEditionKind.Free, defaultSnap.EditionKind);
        Assert.Equal("Free", defaultSnap.EditionDisplayName);

        // Opting into Community with Standard pseudonymous diagnostics activates Community ($0, 1 device)
        var appliedLevel = consent.Apply(
            EditionChoice.Community,
            PrivacyRegion.UnitedStates,
            wantsStandard: true,
            wantsExtended: false,
            eulaVersion: "1.0",
            eulaSha256: new string('B', 64));

        Assert.Equal(ConsentLevel.Standard, appliedLevel);
        Assert.True(consent.CommunityConditionAccepted());
        Assert.False(string.IsNullOrWhiteSpace(consent.Current.InstallId));

        var communitySnap = svc.GetCurrentSnapshot();
        Assert.Equal(OmniHubEditionKind.Community, communitySnap.EditionKind);
        Assert.Equal("Community", communitySnap.EditionDisplayName);
        Assert.Equal(1, communitySnap.SeatLimit);
        Assert.False(OmniHubBrandConstants.ContainsProhibitedCopy(communitySnap.StatusMessage, out var violation), violation);
    }

    [Fact]
    public async Task ActivateCloudOrderAsync_ValidSignedServerToken_VerifiesSignatureLocallyAndPersists()
    {
        var liveDeviceId = DelgadoLogicIdentity.LoadOrCreate(allowDiskPersistence: false).DeviceId;
        var signedToken = CreateEd25519SignedToken(new LicenseClaims
        {
            Email = "cloudbuyer@delgadologic.tech",
            BoundHwid = liveDeviceId,
            Tier = LicenseTier.Pro,
            IssuedAt = DateTimeOffset.UtcNow,
            ExpiresAt = DateTimeOffset.UtcNow.AddYears(1),
            OrderId = "PAYPAL-ORDER-8842",
            SeatCount = 3,
            DeviceLimit = 3
        });

        var cloudResponseJson = JsonSerializer.Serialize(new
        {
            success = true,
            token = new
            {
                payload = signedToken.Payload,
                signature = signedToken.Signature,
                alg = signedToken.Alg,
                kid = signedToken.Kid
            },
            tier = "Pro",
            seats = 3,
            expiresAt = DateTimeOffset.UtcNow.AddYears(1).ToString("O"),
            activationId = "ACT-8842"
        });

        using var mockHttp = new HttpClient(new StaticJsonHandler(HttpStatusCode.OK, cloudResponseJson));
        var writePath = Path.Combine(_licenseDir, "cloud_activated.lic");
        var svc = new UnifiedLicenseHubService(new UnifiedLicenseOptions
        {
            LicenseSearchPathsOverride = [writePath],
            PrimaryWritePathOverride = writePath,
            FallbackWritePathOverride = writePath,
            CloudBridgeAppDataOverride = Path.Combine(_tempRoot, "CloudBridge"),
            MachineHwidOverride = TestMachineHwid,
            SharedDeviceIdOverride = liveDeviceId,
            ValidatorOverride = _testValidator,
            ConsentStore = new ConsentStore(_pulseDir, (_, _) => null),
            HttpClient = mockHttp
        });

        var result = await svc.ActivateCloudOrderAsync("PAYPAL-ORDER-8842", "cloudbuyer@delgadologic.tech");
        Assert.True(result.Success);
        Assert.True(File.Exists(writePath));
        Assert.Equal(OmniHubEditionKind.Pro, result.Snapshot.EditionKind);
        Assert.Equal("PAYPAL-ORDER-8842", result.Snapshot.OrderId);
    }

    [Fact]
    public async Task FactsMdCompliance_BrandConstantsAndAllXamlUiFiles_MatchCorporateAddressAgeRefundAndZeroProhibitedCopy()
    {
        Assert.Equal("Delgado Creative Enterprises LLC d/b/a DelgadoLogic", OmniHubBrandConstants.LegalEntity);
        Assert.Equal("6218 Georgia Avenue NW, Ste 1-698, Washington, DC 20011, USA", OmniHubBrandConstants.PostalAddress);
        Assert.Equal(16, OmniHubBrandConstants.MinimumAge);
        Assert.Equal(60, OmniHubBrandConstants.RefundGuaranteeDays);
        Assert.Contains("60-day no-questions-asked money-back guarantee", OmniHubBrandConstants.RefundPolicyNotice, StringComparison.Ordinal);
        Assert.Contains("pseudonymous", OmniHubBrandConstants.TelemetryDisclosureSummary, StringComparison.OrdinalIgnoreCase);
        Assert.False(OmniHubBrandConstants.ContainsProhibitedCopy(OmniHubBrandConstants.TelemetryDisclosureSummary, out var brandViolation), brandViolation);

        // Verify ContainsProhibitedCopy catches retired SKUs and prohibited telemetry slogans
        Assert.True(OmniHubBrandConstants.ContainsProhibitedCopy("Upgrade to FounderPass today", out _));
        Assert.True(OmniHubBrandConstants.ContainsProhibitedCopy("Includes Sovereign Suite", out _));
        Assert.True(OmniHubBrandConstants.ContainsProhibitedCopy("Anonymous telemetry enabled", out _));
        Assert.True(OmniHubBrandConstants.ContainsProhibitedCopy("100% zero-telemetry desktop", out _));

        // Scan actual OmniHub XAML & README files on disk to enforce zero retired SKUs / zero prohibited telemetry claims
        var omniHubRoot = FindOmniHubProjectRoot();
        var uiFiles = Directory.GetFiles(Path.Combine(omniHubRoot, "src", "OmniHub.App"), "*.xaml", SearchOption.AllDirectories)
            .Append(Path.Combine(omniHubRoot, "README.md"))
            .ToArray();

        Assert.True(uiFiles.Length >= 4);
        foreach (var file in uiFiles)
        {
            var text = await File.ReadAllTextAsync(file);
            Assert.False(
                OmniHubBrandConstants.ContainsProhibitedCopy(text, out var fileViolation),
                $"FACTS.md compliance violation in {Path.GetFileName(file)}: {fileViolation}");
        }

        var mainWindowXaml = await File.ReadAllTextAsync(Path.Combine(omniHubRoot, "src", "OmniHub.App", "MainWindow.xaml"));
        Assert.Contains("6218 Georgia Avenue NW, Ste 1-698, Washington, DC 20011, USA", mainWindowXaml, StringComparison.Ordinal);
        Assert.Contains("60-day no-questions-asked money-back guarantee", mainWindowXaml, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("16+", mainWindowXaml, StringComparison.Ordinal);
        Assert.Contains("pseudonymous", mainWindowXaml, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void QuickLauncherSearchService_FuzzySubsequenceAcronymAndMultiTokenQueries_RankExpectedCommandsFirst()
    {
        var search = new QuickLauncherSearchService();
        var catalog = new[]
        {
            new QuickLauncherItem("app.lf", "Launch LogicFlow", "Open LogicFlow v1.0 Dashboard", QuickCommandCategory.Apps, "APP", ["logicflow", "dashboard"]),
            new QuickLauncherItem("app.aeon", "Launch Aeon Browser", "Open Aeon Browser v0.22.0", QuickCommandCategory.Apps, "APP", ["aeon", "browser"]),
            new QuickLauncherItem("vault.snap", "Restore Snapshot 20261113_a1b2c3", "4 files • Zstd .lfc container", QuickCommandCategory.CloudVault, "LFC SNAPSHOT", ["restore", "lfc", "snapshot"]),
            new QuickLauncherItem("handoff.auth", "Export Aeon auth.json Session", "Pull Playwright storageState & DPAPI-encrypt", QuickCommandCategory.AeonHandoff, "HANDOFF", ["aeon", "playwright", "dpapi", "cookies"]),
            new QuickLauncherItem("ai.dedup", "Deduplicate Shared GGUF Models", "NTFS CreateHardLinkW across Gemma 4 weights", QuickCommandCategory.AiModelVault, "GGUF VAULT", ["gemma", "gguf", "hardlink"])
        };

        // Empty query returns full catalog in order
        var all = search.Search(catalog, "");
        Assert.Equal(5, all.Count);

        // Multi-token query narrows strictly to matching item
        var dpapiMatch = search.Search(catalog, "aeon dpapi");
        Assert.Single(dpapiMatch);
        Assert.Equal("handoff.auth", dpapiMatch[0].Item.Id);

        // Keyword + extension query ranks .lfc snapshot command #1
        var lfcMatch = search.Search(catalog, "restore lfc");
        Assert.NotEmpty(lfcMatch);
        Assert.Equal("vault.snap", lfcMatch[0].Item.Id);

        // Fuzzy subsequence query ("llf" -> Launch LogicFlow)
        var fuzzy = search.Search(catalog, "llf");
        Assert.NotEmpty(fuzzy);
        Assert.Equal("app.lf", fuzzy[0].Item.Id);
    }

    // ─── Helpers ─────────────────────────────────────────────────────────────

    private UnifiedLicenseHubService CreateLicenseService(
        IReadOnlyList<string> searchPaths,
        string? primaryWritePath = null,
        ConsentStore? consentStore = null)
    {
        return new UnifiedLicenseHubService(new UnifiedLicenseOptions
        {
            LicenseSearchPathsOverride = searchPaths,
            PrimaryWritePathOverride = primaryWritePath ?? searchPaths[0],
            FallbackWritePathOverride = primaryWritePath ?? searchPaths[0],
            MachineHwidOverride = TestMachineHwid,
            SharedDeviceIdOverride = TestSharedDeviceId,
            ValidatorOverride = _testValidator,
            ConsentStore = consentStore ?? new ConsentStore(_pulseDir, (_, _) => null)
        });
    }

    private LicenseToken CreateRsaSignedToken(LicenseClaims claims)
    {
        var payload = JsonSerializer.Serialize(claims);
        var sig = _rsaKeyPair.SignData(Encoding.UTF8.GetBytes(payload), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return new LicenseToken(payload, Convert.ToBase64String(sig), "RSA-2048", "test-rsa-v1");
    }

    private LicenseToken CreateEd25519SignedToken(LicenseClaims claims)
    {
        var payload = JsonSerializer.Serialize(claims);
        var payloadBytes = Encoding.UTF8.GetBytes(payload);
        var signer = new Ed25519Signer();
        signer.Init(true, _edPriv);
        signer.BlockUpdate(payloadBytes, 0, payloadBytes.Length);
        var sig = signer.GenerateSignature();
        return new LicenseToken(payload, Convert.ToBase64String(sig), "Ed25519", "test-ed25519-v1");
    }

    private static string FindOmniHubProjectRoot()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            if (File.Exists(Path.Combine(dir.FullName, "OmniHub.sln")))
                return dir.FullName;
            dir = dir.Parent;
        }
        throw new DirectoryNotFoundException("Could not locate OmniHub.sln from test base directory.");
    }

    private sealed class StaticJsonHandler(HttpStatusCode statusCode, string json) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(statusCode)
            {
                Content = new StringContent(json, Encoding.UTF8, "application/json")
            });
    }

    public void Dispose()
    {
        DelgadoLogicIdentity.OverrideSharedRootForTesting = null;
        _rsaKeyPair.Dispose();

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
