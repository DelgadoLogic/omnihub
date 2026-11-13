using OmniLicense;

namespace OmniHub.Core;

/// <summary>
/// Canonical corporate, legal, commercial, and privacy constants aligned 100% with LogicFlow FACTS.md.
/// Never duplicate or deviate from these values in UI copy, metadata, or IPC payloads.
/// </summary>
public static class OmniHubBrandConstants
{
    public const string Brand = PriceSheet.Brand; // "DelgadoLogic"
    public const string ProductName = "OmniHub";
    public const string FullProductTitle = "DelgadoLogic OmniHub";
    public const string Version = "1.0.0";

    // Corporate & Jurisdiction (District of Columbia LLC)
    public const string LegalEntity = PriceSheet.LegalEntity; // "Delgado Creative Enterprises LLC d/b/a DelgadoLogic"
    public const string Jurisdiction = "District of Columbia Limited Liability Company";
    public const string GoverningLaw = "Laws of the District of Columbia, United States of America";
    public const string PostalAddress = "6218 Georgia Avenue NW, Ste 1-698, Washington, DC 20011, USA";

    // Support & Role Mailboxes
    public const string SupportEmail = PriceSheet.SupportEmail; // "support@delgadologic.tech"
    public const string PrivacyEmail = "privacy@delgadologic.tech";
    public const string LegalEmail = "legal@delgadologic.tech";
    public const string SecurityEmail = "security@delgadologic.tech";
    public const string BillingEmail = "billing@delgadologic.tech";
    public const string SupportHours = "Monday–Friday, 9:00 AM – 5:00 PM EST";

    // Age & Commercial Guarantee
    public const int MinimumAge = 16;
    public const string MinimumAgeNotice = "16+ years of age required to purchase, download, install, or use DelgadoLogic software.";
    public const int RefundGuaranteeDays = PriceSheet.RefundDays; // 60
    public const string RefundPolicyNotice = "60-day no-questions-asked money-back guarantee";

    // Canonical Sovereign Endpoints & Pipes
    public const string ApiBaseUrl = "https://api.delgadologic.tech";
    public const string SiteBaseUrl = PriceSheet.SiteBase;
    public const string DefaultOmniHubPipeName = "delgadologic-omnihub";
    public const string DefaultAeonAgentPipeName = "aeon-agent";

    // Canonical Product Baseline Versions & Hashes (FACTS.md)
    public const string LogicFlowBaselineVersion = "1.0.0";
    public const string LogicFlowSetupSha256 = "7FC3FAC70FBA7964C9A87038A160FB6D20E59D85F37623E7E2CFB02B8B487F74";
    public const long LogicFlowSetupSizeBytes = 174_744_576L;
    public const string AeonBaselineVersion = "0.22.0";

    // Canonical Telemetry Disclosure (strictly pseudonymous — never "anonymous" and never blanket "no-telemetry")
    public const string TelemetryDisclosureSummary =
        "Diagnostic telemetry is OFF by default (ConsentLevel.None). Free: telemetry disabled; " +
        "Community: requires Standard pseudonymous diagnostic sharing; Pro & Team 10-Pack: optional and OFF by default. " +
        "When enabled, events carry a rotatable 128-bit random pseudonymous installId stored locally in consent.json — " +
        "never derived from hardware serial numbers or linked to your license HWID.";

    // Retired SKU & Claim Guards (for compliance assertions)
    private static readonly string[] RetiredSkuTokens =
    [
        "FounderPass",
        "Founder Pass",
        "SovereignSuite",
        "Sovereign Suite",
        "Family Tier",
        "Family License",
        "AI Health Audit"
    ];

    private static readonly TimeZoneInfo EstTimeZone = ResolveEstTimeZone();

    /// <summary>
    /// Formats a UTC/offset timestamp in EST (UTC-4/UTC-5 Eastern Time) per DelgadoLogic display standards.
    /// </summary>
    public static string FormatEst(DateTimeOffset timestamp)
    {
        var converted = TimeZoneInfo.ConvertTime(timestamp, EstTimeZone);
        return $"{converted:yyyy-MM-dd HH:mm:ss} EST";
    }

    /// <summary>
    /// Formats byte counts into human-readable KB/MB/GB strings.
    /// </summary>
    public static string FormatBytes(long bytes)
    {
        if (bytes < 0) bytes = 0;
        if (bytes < 1024) return $"{bytes} B";
        if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
        if (bytes < 1024L * 1024L * 1024L) return $"{bytes / (1024.0 * 1024.0):F2} MB";
        return $"{bytes / (1024.0 * 1024.0 * 1024.0):F2} GB";
    }

    /// <summary>
    /// Checks whether user-facing text accidentally contains any retired SKU name or prohibited telemetry claim.
    /// </summary>
    public static bool ContainsProhibitedCopy(string? text, out string? violation)
    {
        violation = null;
        if (string.IsNullOrWhiteSpace(text))
            return false;

        foreach (var retired in RetiredSkuTokens)
        {
            if (text.Contains(retired, StringComparison.OrdinalIgnoreCase))
            {
                violation = $"Contains retired SKU '{retired}'.";
                return true;
            }
        }

        if (text.Contains("anonymous telemetry", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("anonymous diagnostics", StringComparison.OrdinalIgnoreCase))
        {
            violation = "Uses prohibited 'anonymous' telemetry phrasing instead of 'pseudonymous'.";
            return true;
        }

        if (text.Contains("zero-telemetry", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("no-telemetry", StringComparison.OrdinalIgnoreCase))
        {
            violation = "Uses prohibited blanket 'zero-telemetry'/'no-telemetry' slogan.";
            return true;
        }

        return false;
    }

    private static TimeZoneInfo ResolveEstTimeZone()
    {
        try
        {
            return TimeZoneInfo.FindSystemTimeZoneById("Eastern Standard Time");
        }
        catch
        {
            return TimeZoneInfo.CreateCustomTimeZone("EST", TimeSpan.FromHours(-4), "EST", "EST");
        }
    }
}
