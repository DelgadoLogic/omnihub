using System.Windows;
using System.Windows.Media;
using OmniHub.Core;

namespace OmniHub.App.Themes;

/// <summary>
/// Runtime theme manager switching seamlessly between Obsidian Dark (#00E5FF / #9333EA)
/// and Daylight Light palettes across all open OmniHub windows.
/// </summary>
public static class ThemeManager
{
    public static OmniHubThemeMode CurrentMode { get; private set; } = OmniHubThemeMode.Dark;

    public static void ApplyTheme(ResourceDictionary resources, OmniHubThemeMode mode)
    {
        ArgumentNullException.ThrowIfNull(resources);
        CurrentMode = mode;

        if (mode == OmniHubThemeMode.Light)
        {
            SetBrush(resources, "BgWindowBrush", "#F4F7FB");
            SetBrush(resources, "BgSidebarBrush", "#FFFFFF");
            SetBrush(resources, "BgHeaderBrush", "#FFFFFF");
            SetBrush(resources, "BgCardBrush", "#FFFFFF");
            SetBrush(resources, "BgCardElevatedBrush", "#F1F5F9");
            SetBrush(resources, "BgCardHoverBrush", "#E2E8F0");
            SetBrush(resources, "BgInputBrush", "#F8FAFC");
            SetBrush(resources, "BorderSubtleBrush", "#CBD5E1");
            SetBrush(resources, "BorderAccentBrush", "#660284C7");
            SetBrush(resources, "NavActiveFillBrush", "#180284C7");

            SetBrush(resources, "TextPrimaryBrush", "#0F172A");
            SetBrush(resources, "TextSecondaryBrush", "#475569");
            SetBrush(resources, "TextMutedBrush", "#64748B");
            SetBrush(resources, "AccentCyanBrush", "#0284C7");
            SetBrush(resources, "AccentPurpleBrush", "#7E22CE");

            resources["HeroBannerBrush"] = new LinearGradientBrush(
                new GradientStopCollection
                {
                    new(ColorFromHex("#E0F2FE"), 0.0),
                    new(ColorFromHex("#F3E8FF"), 0.65),
                    new(ColorFromHex("#EFF6FF"), 1.0)
                },
                new Point(0, 0),
                new Point(1, 0.6));
        }
        else
        {
            SetBrush(resources, "BgWindowBrush", "#080B12");
            SetBrush(resources, "BgSidebarBrush", "#0D121D");
            SetBrush(resources, "BgHeaderBrush", "#0B101B");
            SetBrush(resources, "BgCardBrush", "#121826");
            SetBrush(resources, "BgCardElevatedBrush", "#172033");
            SetBrush(resources, "BgCardHoverBrush", "#1C273E");
            SetBrush(resources, "BgInputBrush", "#0E1422");
            SetBrush(resources, "BorderSubtleBrush", "#1F2B42");
            SetBrush(resources, "BorderAccentBrush", "#5500E5FF");
            SetBrush(resources, "NavActiveFillBrush", "#1800E5FF");

            SetBrush(resources, "TextPrimaryBrush", "#F1F5F9");
            SetBrush(resources, "TextSecondaryBrush", "#94A3B8");
            SetBrush(resources, "TextMutedBrush", "#64748B");
            SetBrush(resources, "AccentCyanBrush", "#00E5FF");
            SetBrush(resources, "AccentPurpleBrush", "#9333EA");

            resources["HeroBannerBrush"] = new LinearGradientBrush(
                new GradientStopCollection
                {
                    new(ColorFromHex("#141C30"), 0.0),
                    new(ColorFromHex("#1B1534"), 0.65),
                    new(ColorFromHex("#0F1F2E"), 1.0)
                },
                new Point(0, 0),
                new Point(1, 0.6));
        }
    }

    private static void SetBrush(ResourceDictionary dict, string key, string hex)
    {
        var brush = new SolidColorBrush(ColorFromHex(hex));
        brush.Freeze();
        dict[key] = brush;
    }

    private static Color ColorFromHex(string hex) =>
        (Color)ColorConverter.ConvertFromString(hex);
}
