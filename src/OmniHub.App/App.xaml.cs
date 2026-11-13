using System.Windows;
using System.Windows.Controls;
using OmniHub.App.Interop;
using OmniHub.App.Services;
using OmniHub.App.Themes;
using OmniHub.Core;

namespace OmniHub.App;

public partial class App : Application
{
    private Mutex? _singleInstanceMutex;
    private OmniHubRuntimeHost? _runtimeHost;
    private Win32TrayAndHotkeyService? _trayAndHotkey;
    private MainWindow? _mainWindow;
    private QuickLauncherWindow? _quickLauncher;
    private ContextMenu? _trayMenu;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        _singleInstanceMutex = new Mutex(true, @"Local\DelgadoLogic_OmniHub_SingleInstance_v1", out bool createdNew);
        if (!createdNew)
        {
            Shutdown(0);
            return;
        }

        _runtimeHost = new OmniHubRuntimeHost();
        var userSettings = _runtimeHost.Settings.Load();
        ThemeManager.ApplyTheme(Resources, userSettings.Theme);

        _runtimeHost.StartBackgroundServices();

        _trayAndHotkey = new Win32TrayAndHotkeyService();
        _trayAndHotkey.Initialize();

        _mainWindow = new MainWindow(_runtimeHost, _trayAndHotkey, OpenQuickLauncherAsync, ExitApplicationAsync);
        _quickLauncher = new QuickLauncherWindow(
            _runtimeHost,
            tabIdx =>
            {
                ShowMainWindow();
                _mainWindow.SelectNavigationTab(tabIdx);
            },
            () => _mainWindow.ToggleThemeMode());

        _trayMenu = BuildTrayContextMenu();

        _trayAndHotkey.GlobalHotkeyPressed += async (_, _) =>
        {
            if (_quickLauncher is not null)
                await _quickLauncher.ToggleOverlayAsync();
        };

        _trayAndHotkey.TrayOpenRequested += (_, _) => ShowMainWindow();
        _trayAndHotkey.TrayContextMenuRequested += (_, _) =>
        {
            if (_trayMenu is not null)
            {
                _trayMenu.IsOpen = true;
            }
        };

        bool startMinimizedToTray = e.Args.Any(a => string.Equals(a, "--tray", StringComparison.OrdinalIgnoreCase));
        if (!startMinimizedToTray)
        {
            ShowMainWindow();
        }
    }

    private void ShowMainWindow()
    {
        if (_mainWindow is null) return;
        if (!_mainWindow.IsVisible)
            _mainWindow.Show();
        if (_mainWindow.WindowState == WindowState.Minimized)
            _mainWindow.WindowState = WindowState.Normal;
        _mainWindow.Activate();
    }

    private async Task OpenQuickLauncherAsync()
    {
        if (_quickLauncher is not null)
            await _quickLauncher.ShowOverlayAsync();
    }

    private ContextMenu BuildTrayContextMenu()
    {
        var menu = new ContextMenu();

        var openItem = new MenuItem { Header = "Open OmniHub Dashboard", FontWeight = FontWeights.SemiBold };
        openItem.Click += (_, _) => ShowMainWindow();

        var quickItem = new MenuItem { Header = "Quick Launcher (Alt+Space)" };
        quickItem.Click += async (_, _) => await OpenQuickLauncherAsync();

        var launchLf = new MenuItem { Header = "Launch LogicFlow" };
        launchLf.Click += async (_, _) =>
        {
            if (_runtimeHost is not null)
                await _runtimeHost.AppManager.LaunchProductAsync(ManagedProductId.LogicFlow);
        };

        var launchAeon = new MenuItem { Header = "Launch Aeon Browser" };
        launchAeon.Click += async (_, _) =>
        {
            if (_runtimeHost is not null)
                await _runtimeHost.AppManager.LaunchProductAsync(ManagedProductId.AeonBrowser);
        };

        var snapItem = new MenuItem { Header = "Create Cloud .lfc Snapshot" };
        snapItem.Click += async (_, _) =>
        {
            if (_runtimeHost is not null)
                await _runtimeHost.CloudVault.CreateSnapshotAsync("SystemTray");
        };

        var exitItem = new MenuItem { Header = "Exit OmniHub" };
        exitItem.Click += async (_, _) => await ExitApplicationAsync();

        menu.Items.Add(openItem);
        menu.Items.Add(quickItem);
        menu.Items.Add(new Separator());
        menu.Items.Add(launchLf);
        menu.Items.Add(launchAeon);
        menu.Items.Add(snapItem);
        menu.Items.Add(new Separator());
        menu.Items.Add(exitItem);

        return menu;
    }

    private async Task ExitApplicationAsync()
    {
        try
        {
            _quickLauncher?.Close();
            if (_mainWindow is not null)
            {
                _mainWindow.AllowImmediateClose = true;
                _mainWindow.Close();
            }

            _trayAndHotkey?.Dispose();
            if (_runtimeHost is not null)
            {
                await _runtimeHost.DisposeAsync();
                _runtimeHost = null;
            }
        }
        finally
        {
            _singleInstanceMutex?.Dispose();
            _singleInstanceMutex = null;
            Shutdown(0);
        }
    }
}
