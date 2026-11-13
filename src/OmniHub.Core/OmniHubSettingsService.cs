using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32;

namespace OmniHub.Core;

public enum OmniHubThemeMode
{
    Dark = 0,
    Light = 1
}

public sealed class OmniHubUserSettings
{
    public OmniHubThemeMode Theme { get; set; } = OmniHubThemeMode.Dark;
    public bool MinimizeToTrayOnClose { get; set; } = true;
    public bool LaunchAtWindowsStartup { get; set; } = false;
    public string LogicFlowChannel { get; set; } = "stable";
    public string AeonChannel { get; set; } = "stable";
}

/// <summary>
/// Manages persistent OmniHub desktop preferences and Windows startup registration.
/// </summary>
public sealed class OmniHubSettingsService
{
    private const string RunRegistrySubKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
    private const string StartupValueName = "DelgadoLogicOmniHub";

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter() }
    };

    private readonly object _gate = new();
    private readonly string _settingsPath;
    private readonly Action<bool, string?>? _startupRegistryOverride;
    private OmniHubUserSettings? _cached;

    public OmniHubSettingsService(
        string? configDirectory = null,
        Action<bool, string?>? startupRegistryOverride = null)
    {
        var dir = string.IsNullOrWhiteSpace(configDirectory)
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "DelgadoLogic", "OmniHub")
            : configDirectory;
        Directory.CreateDirectory(dir);
        _settingsPath = Path.Combine(dir, "settings.json");
        _startupRegistryOverride = startupRegistryOverride;
    }

    public string SettingsFilePath => _settingsPath;

    public OmniHubUserSettings Load()
    {
        lock (_gate)
        {
            if (_cached is not null)
                return Clone(_cached);

            try
            {
                if (File.Exists(_settingsPath))
                {
                    var json = File.ReadAllText(_settingsPath);
                    var loaded = JsonSerializer.Deserialize<OmniHubUserSettings>(json, JsonOpts);
                    if (loaded is not null)
                    {
                        loaded.LogicFlowChannel = NormalizeChannel(loaded.LogicFlowChannel);
                        loaded.AeonChannel = NormalizeChannel(loaded.AeonChannel);
                        _cached = loaded;
                        return Clone(loaded);
                    }
                }
            }
            catch
            {
                // Corrupt file falls back to safe defaults
            }

            _cached = new OmniHubUserSettings();
            return Clone(_cached);
        }
    }

    public void Save(OmniHubUserSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        lock (_gate)
        {
            settings.LogicFlowChannel = NormalizeChannel(settings.LogicFlowChannel);
            settings.AeonChannel = NormalizeChannel(settings.AeonChannel);
            _cached = Clone(settings);

            var dir = Path.GetDirectoryName(_settingsPath);
            if (!string.IsNullOrEmpty(dir))
                Directory.CreateDirectory(dir);

            var tmp = _settingsPath + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(_cached, JsonOpts));
            File.Move(tmp, _settingsPath, overwrite: true);
        }
    }

    public bool SetLaunchAtStartup(bool enabled, string? executablePath = null)
    {
        try
        {
            var resolvedExe = executablePath ?? Environment.ProcessPath;
            if (_startupRegistryOverride is not null)
            {
                _startupRegistryOverride(enabled, resolvedExe);
            }
            else
            {
                using var key = Registry.CurrentUser.OpenSubKey(RunRegistrySubKey, writable: true);
                if (key is null)
                    return false;

                if (enabled)
                {
                    if (string.IsNullOrWhiteSpace(resolvedExe))
                        return false;
                    key.SetValue(StartupValueName, $"\"{resolvedExe}\" --tray");
                }
                else
                {
                    key.DeleteValue(StartupValueName, throwOnMissingValue: false);
                }
            }

            var current = Load();
            current.LaunchAtWindowsStartup = enabled;
            Save(current);
            return true;
        }
        catch
        {
            return false;
        }
    }

    public static string NormalizeChannel(string? channel) =>
        string.Equals(channel?.Trim(), "beta", StringComparison.OrdinalIgnoreCase) ? "beta" : "stable";

    private static OmniHubUserSettings Clone(OmniHubUserSettings s) => new()
    {
        Theme = s.Theme,
        MinimizeToTrayOnClose = s.MinimizeToTrayOnClose,
        LaunchAtWindowsStartup = s.LaunchAtWindowsStartup,
        LogicFlowChannel = s.LogicFlowChannel,
        AeonChannel = s.AeonChannel
    };
}
