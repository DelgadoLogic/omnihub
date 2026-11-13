using System.Text;
using System.Text.Json;
using DelgadoLogic.Core;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using OmniLicense;
using OmniPulse;

namespace OmniHub.Core;

/// <summary>
/// Canonical user-facing editions across DelgadoLogic v1.x (FACTS.md).
/// Legacy/retired enum values (FounderPass, SovereignSuite, Family) are never exposed here.
/// </summary>
public enum OmniHubEditionKind
{
    Free = 0,
    Community = 1,
    Pro = 2,
    Team10Pack = 3
}

public sealed record UnifiedLicenseSnapshot(
    OmniHubEditionKind EditionKind,
    string EditionDisplayName,
    bool IsPaid,
    bool IsTokenCryptographicallyValid,
    string MachineHwid,
    string SharedDeviceId,
    string? BoundHwid,
    int SeatLimit,
    string? LicensedEmail,
    string? OrderId,
    string? SignatureAlgorithm,
    DateTimeOffset? IssuedAt,
    DateTimeOffset? ExpiresAt,
    string? SourceLicensePath,
    string StatusMessage);

public sealed record LicenseImportResult(
    bool Success,
    string Message,
    string? PersistedPath,
    UnifiedLicenseSnapshot Snapshot);

public sealed class UnifiedLicenseOptions
{
    public IReadOnlyList<string>? LicenseSearchPathsOverride { get; init; }
    public string? PrimaryWritePathOverride { get; init; }
    public string? FallbackWritePathOverride { get; init; }
    public string? CloudBridgeAppDataOverride { get; init; }
    public string? MachineHwidOverride { get; init; }
    public string? SharedDeviceIdOverride { get; init; }
    public RsaLicenseValidator? ValidatorOverride { get; init; }
    public ConsentStore? ConsentStore { get; init; }
    public HttpClient? HttpClient { get; init; }
    public ILogger<UnifiedLicenseHubService>? Logger { get; init; }
}

/// <summary>
/// Reads, validates, and activates unified cryptographic licenses across LogicFlow and Aeon Browser.
/// Supports dual Ed25519 + RSA-2048 signatures and strictly sanitizes retired SKU names per FACTS.md.
/// </summary>
public sealed class UnifiedLicenseHubService
{
    private static readonly JsonSerializerOptions CaseInsensitiveJson = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = true
    };

    private readonly UnifiedLicenseOptions _options;
    private readonly ILogger<UnifiedLicenseHubService> _logger;
    private readonly RsaLicenseValidator _validator;
    private readonly ConsentStore _consentStore;

    public UnifiedLicenseHubService(UnifiedLicenseOptions? options = null)
    {
        _options = options ?? new UnifiedLicenseOptions();
        _logger = _options.Logger ?? NullLogger<UnifiedLicenseHubService>.Instance;
        _validator = _options.ValidatorOverride
            ?? new RsaLicenseValidator(NullLogger<RsaLicenseValidator>.Instance);
        _consentStore = _options.ConsentStore ?? new ConsentStore();
    }

    public IReadOnlyList<string> GetLicenseSearchPaths()
    {
        if (_options.LicenseSearchPathsOverride is { Count: > 0 })
            return _options.LicenseSearchPathsOverride;

        var programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

        return
        [
            Path.Combine(programData, "DelgadoLogic", "license.lic"),
            Path.Combine(programData, "DelgadoLogic", "license_token.json"),
            Path.Combine(appData, "DelgadoLogic", "license.lic"),
            Path.Combine(appData, "DelgadoLogic", "LogicFlow", "License", "license_token.json"),
            Path.Combine(appData, "DelgadoLogic", "Shared", "License", "license_token.json")
        ];
    }

    public string GetMachineHwid() =>
        !string.IsNullOrWhiteSpace(_options.MachineHwidOverride)
            ? _options.MachineHwidOverride!
            : new HwidGenerator().GenerateHwid();

    public string GetSharedDeviceId() =>
        !string.IsNullOrWhiteSpace(_options.SharedDeviceIdOverride)
            ? _options.SharedDeviceIdOverride!
            : DelgadoLogicIdentity.LoadOrCreate(allowDiskPersistence: false).DeviceId;

    /// <summary>
    /// Evaluates all configured license paths fail-closed and returns a sanitized, FACTS.md-compliant snapshot.
    /// </summary>
    public UnifiedLicenseSnapshot GetCurrentSnapshot()
    {
        var hwid = GetMachineHwid();
        var sharedDeviceId = GetSharedDeviceId();
        string? lastFailureReason = null;
        string? lastFailurePath = null;

        foreach (var path in GetLicenseSearchPaths())
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                continue;

            try
            {
                var raw = File.ReadAllText(path);
                if (!TryParseTokenEnvelope(raw, out var token, out var parseErr) || token is null)
                {
                    lastFailureReason = parseErr ?? "Malformed license file";
                    lastFailurePath = path;
                    continue;
                }

                var validation = _validator.Validate(token, [hwid, sharedDeviceId]);
                if (!validation.IsValid)
                {
                    lastFailureReason = SanitizeStatusMessage(validation.Message);
                    lastFailurePath = path;
                    continue;
                }

                var claims = JsonSerializer.Deserialize<LicenseClaims>(token.Payload, CaseInsensitiveJson);
                if (claims is null)
                {
                    lastFailureReason = "Corrupt license claims";
                    lastFailurePath = path;
                    continue;
                }

                var (editionKind, displayName, seatLimit) = MapSanitizedEdition(validation.Tier, claims);
                var algDisplay = InferSignatureAlgorithm(token);

                return new UnifiedLicenseSnapshot(
                    EditionKind: editionKind,
                    EditionDisplayName: displayName,
                    IsPaid: editionKind is OmniHubEditionKind.Pro or OmniHubEditionKind.Team10Pack,
                    IsTokenCryptographicallyValid: true,
                    MachineHwid: hwid,
                    SharedDeviceId: sharedDeviceId,
                    BoundHwid: claims.BoundHwid,
                    SeatLimit: seatLimit,
                    LicensedEmail: string.IsNullOrWhiteSpace(claims.Email) ? null : claims.Email,
                    OrderId: string.IsNullOrWhiteSpace(claims.OrderId) ? null : claims.OrderId,
                    SignatureAlgorithm: algDisplay,
                    IssuedAt: claims.IssuedAt == default ? null : claims.IssuedAt,
                    ExpiresAt: claims.ExpiresAt == default ? null : claims.ExpiresAt,
                    SourceLicensePath: path,
                    StatusMessage: $"Active {displayName} license verified via {algDisplay} ({seatLimit} {(seatLimit == 1 ? "device" : "devices")}).");
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[OmniHub.License] Error reading license file at {Path}.", path);
                lastFailureReason = "Unreadable license file";
                lastFailurePath = path;
            }
        }

        // No valid signed paid token — resolve Community vs Free via OmniPulse.ConsentStore
        bool communityAccepted = _consentStore.CommunityConditionAccepted();
        var fallbackEdition = TierPolicy.Resolve(null, communityAccepted);
        var kind = fallbackEdition == Edition.Community ? OmniHubEditionKind.Community : OmniHubEditionKind.Free;
        var name = kind == OmniHubEditionKind.Community ? "Community" : "Free";
        var seats = kind == OmniHubEditionKind.Community ? PriceSheet.CommunityDevices : PriceSheet.FreeDevices;

        var status = lastFailureReason is not null
            ? $"License rejected ({lastFailureReason}) — running on {name} edition."
            : kind == OmniHubEditionKind.Community
                ? "Community edition active ($0 personal non-commercial, Standard pseudonymous diagnostics enabled)."
                : "Free edition active ($0 read-only diagnostics, telemetry disabled).";

        return new UnifiedLicenseSnapshot(
            EditionKind: kind,
            EditionDisplayName: name,
            IsPaid: false,
            IsTokenCryptographicallyValid: false,
            MachineHwid: hwid,
            SharedDeviceId: sharedDeviceId,
            BoundHwid: null,
            SeatLimit: seats,
            LicensedEmail: null,
            OrderId: null,
            SignatureAlgorithm: null,
            IssuedAt: null,
            ExpiresAt: null,
            SourceLicensePath: lastFailurePath,
            StatusMessage: status);
    }

    /// <summary>
    /// Validates an offline .lic / JSON / Base64 license token fail-closed and writes it to the unified store.
    /// </summary>
    public async Task<LicenseImportResult> ImportOfflineTokenAsync(
        string rawTokenOrFilePath,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(rawTokenOrFilePath))
        {
            return new LicenseImportResult(false, "License input is empty.", null, GetCurrentSnapshot());
        }

        string rawContent = rawTokenOrFilePath.Trim();
        if (!rawContent.StartsWith('{') && File.Exists(rawContent))
        {
            rawContent = await File.ReadAllTextAsync(rawContent, ct).ConfigureAwait(false);
        }

        if (!TryParseTokenEnvelope(rawContent, out var token, out var parseError) || token is null)
        {
            return new LicenseImportResult(false, parseError ?? "Invalid license token format.", null, GetCurrentSnapshot());
        }

        var hwid = GetMachineHwid();
        var sharedDeviceId = GetSharedDeviceId();
        var validation = _validator.Validate(token, [hwid, sharedDeviceId]);
        if (!validation.IsValid)
        {
            return new LicenseImportResult(
                false,
                $"License verification failed: {SanitizeStatusMessage(validation.Message)}",
                null,
                GetCurrentSnapshot());
        }

        var persistedPath = await PersistVerifiedTokenAsync(token, ct).ConfigureAwait(false);
        var updatedSnapshot = GetCurrentSnapshot();
        return new LicenseImportResult(
            true,
            $"Activated {updatedSnapshot.EditionDisplayName} license across LogicFlow and Aeon Browser.",
            persistedPath,
            updatedSnapshot);
    }

    /// <summary>
    /// Activates an online order ID via DelgadoLogic.Core.CloudLicenseBridge and syncs to the unified store.
    /// </summary>
    public async Task<LicenseImportResult> ActivateCloudOrderAsync(
        string orderId,
        string? email = null,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(orderId))
        {
            return new LicenseImportResult(false, "Order ID is required.", null, GetCurrentSnapshot());
        }

        var bridgeDir = !string.IsNullOrWhiteSpace(_options.CloudBridgeAppDataOverride)
            ? _options.CloudBridgeAppDataOverride!
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "DelgadoLogic", "Shared");

        await using var bridge = new CloudLicenseBridge(_logger, bridgeDir, _options.HttpClient);
        var result = await bridge.ActivateAsync(orderId.Trim(), email?.Trim(), ct).ConfigureAwait(false);
        if (!result.Success || result.Token is null)
        {
            return new LicenseImportResult(
                false,
                SanitizeStatusMessage(result.Message),
                null,
                GetCurrentSnapshot());
        }

        var omniToken = new LicenseToken(
            result.Token.Payload,
            result.Token.Signature,
            result.Token.Alg,
            result.Token.Kid);

        // Verify signature locally as well (fail-closed zero-trust against transport)
        var validation = _validator.Validate(omniToken, [GetMachineHwid(), GetSharedDeviceId()]);
        if (!validation.IsValid)
        {
            return new LicenseImportResult(
                false,
                $"Cloud response failed local cryptographic signature check: {SanitizeStatusMessage(validation.Message)}",
                null,
                GetCurrentSnapshot());
        }

        var persistedPath = await PersistVerifiedTokenAsync(omniToken, ct).ConfigureAwait(false);
        var snapshot = GetCurrentSnapshot();
        return new LicenseImportResult(
            true,
            $"Cloud activation succeeded — {snapshot.EditionDisplayName} active.",
            persistedPath,
            snapshot);
    }

    /// <summary>
    /// Maps any LicenseTier + LicenseClaims strictly into canonical FACTS.md editions
    /// (Free, Community, Pro, Team 10-Pack) — never exposing retired SKUs.
    /// </summary>
    public static (OmniHubEditionKind Kind, string DisplayName, int SeatLimit) MapSanitizedEdition(
        LicenseTier tier,
        LicenseClaims? claims = null)
    {
        var canonicalEdition = tier.ToEdition();
        if (canonicalEdition == Edition.Pro)
        {
            int rawSeats = claims?.DeviceLimit ?? claims?.SeatCount ?? 0;
            if (tier == LicenseTier.Enterprise || rawSeats >= PriceSheet.Team10PackSeats)
            {
                return (OmniHubEditionKind.Team10Pack, "Team 10-Pack", Math.Max(rawSeats, PriceSheet.Team10PackSeats));
            }

            int proSeats = rawSeats >= PriceSheet.ProDevices ? rawSeats : PriceSheet.ProDevices;
            return (OmniHubEditionKind.Pro, "Pro", proSeats);
        }

        if (canonicalEdition == Edition.Community)
        {
            return (OmniHubEditionKind.Community, "Community", PriceSheet.CommunityDevices);
        }

        return (OmniHubEditionKind.Free, "Free", PriceSheet.FreeDevices);
    }

    public static bool TryParseTokenEnvelope(string rawInput, out LicenseToken? token, out string? error)
    {
        token = null;
        error = null;

        if (string.IsNullOrWhiteSpace(rawInput))
        {
            error = "Empty license payload.";
            return false;
        }

        var trimmed = rawInput.Trim();

        // Support Base64-armored .lic files
        if (!trimmed.StartsWith('{'))
        {
            try
            {
                var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(trimmed)).Trim();
                if (decoded.StartsWith('{'))
                    trimmed = decoded;
            }
            catch
            {
                error = "License data is neither JSON nor valid Base64.";
                return false;
            }
        }

        try
        {
            using var doc = JsonDocument.Parse(trimmed);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                error = "License JSON root must be an object.";
                return false;
            }

            string? payload = GetJsonString(root, "Payload", "payload");
            string? signature = GetJsonString(root, "Signature", "signature");
            string? alg = GetJsonString(root, "Alg", "alg");
            string? kid = GetJsonString(root, "Kid", "kid");

            if (string.IsNullOrWhiteSpace(payload) || string.IsNullOrWhiteSpace(signature))
            {
                error = "License JSON missing required Payload or Signature fields.";
                return false;
            }

            token = new LicenseToken(payload, signature, alg, kid);
            return true;
        }
        catch (JsonException)
        {
            error = "Malformed JSON in license token.";
            return false;
        }
    }

    private async Task<string> PersistVerifiedTokenAsync(LicenseToken token, CancellationToken ct)
    {
        var primary = !string.IsNullOrWhiteSpace(_options.PrimaryWritePathOverride)
            ? _options.PrimaryWritePathOverride!
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "DelgadoLogic", "license.lic");

        var fallback = !string.IsNullOrWhiteSpace(_options.FallbackWritePathOverride)
            ? _options.FallbackWritePathOverride!
            : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "DelgadoLogic", "license.lic");

        var json = JsonSerializer.Serialize(token, CaseInsensitiveJson);

        foreach (var candidate in new[] { primary, fallback })
        {
            try
            {
                var dir = Path.GetDirectoryName(candidate);
                if (!string.IsNullOrEmpty(dir))
                    Directory.CreateDirectory(dir);

                var tmp = candidate + ".tmp";
                await File.WriteAllTextAsync(tmp, json, ct).ConfigureAwait(false);
                File.Move(tmp, candidate, overwrite: true);
                return candidate;
            }
            catch (UnauthorizedAccessException)
            {
                // Non-elevated process cannot write %ProgramData% — fall through to %APPDATA%
            }
            catch (IOException) when (candidate == primary && primary != fallback)
            {
                // Fall through to per-user store
            }
        }

        throw new IOException("Unable to persist license token to either machine or user store.");
    }

    private static string InferSignatureAlgorithm(LicenseToken token)
    {
        if (!string.IsNullOrWhiteSpace(token.Alg))
        {
            var a = token.Alg.Trim();
            if (a.Equals("Ed25519", StringComparison.OrdinalIgnoreCase)) return "Ed25519";
            if (a.Contains("RSA", StringComparison.OrdinalIgnoreCase) || a.Equals("RS256", StringComparison.OrdinalIgnoreCase))
                return "RSA-2048";
        }

        try
        {
            var len = Convert.FromBase64String(token.Signature).Length;
            return len == 64 ? "Ed25519" : len == 256 ? "RSA-2048" : "Verified";
        }
        catch
        {
            return "Verified";
        }
    }

    private static string SanitizeStatusMessage(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return "Validation failed";

        var sanitized = raw
            .Replace("FounderPass", "Pro", StringComparison.OrdinalIgnoreCase)
            .Replace("Founder Pass", "Pro", StringComparison.OrdinalIgnoreCase)
            .Replace("SovereignSuite", "Pro", StringComparison.OrdinalIgnoreCase)
            .Replace("Sovereign Suite", "Pro", StringComparison.OrdinalIgnoreCase)
            .Replace("Family License", "Pro", StringComparison.OrdinalIgnoreCase);

        return sanitized;
    }

    private static string? GetJsonString(JsonElement obj, params string[] names)
    {
        foreach (var name in names)
        {
            if (obj.TryGetProperty(name, out var prop) && prop.ValueKind == JsonValueKind.String)
                return prop.GetString();
        }
        return null;
    }
}
