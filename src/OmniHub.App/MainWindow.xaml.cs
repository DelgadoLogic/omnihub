using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using Microsoft.Win32;
using OmniHub.App.Interop;
using OmniHub.App.Services;
using OmniHub.App.Themes;
using OmniHub.Core;
using OmniPulse;

namespace OmniHub.App;

public partial class MainWindow : Window
{
    private readonly OmniHubRuntimeHost _host;
    private readonly Win32TrayAndHotkeyService _trayService;
    private readonly Func<Task> _openQuickLauncherCallback;
    private readonly Func<Task> _exitCallback;
    private bool _suppressUiEvents;

    public bool AllowImmediateClose { get; set; }

    public MainWindow(
        OmniHubRuntimeHost host,
        Win32TrayAndHotkeyService trayService,
        Func<Task> openQuickLauncherCallback,
        Func<Task> exitCallback)
    {
        InitializeComponent();

        _host = host;
        _trayService = trayService;
        _openQuickLauncherCallback = openQuickLauncherCallback;
        _exitCallback = exitCallback;

        Icon = Win32TrayAndHotkeyService.CreateBrandWindowIcon(64);

        _host.CloudVault.SnapshotCreated += (_, _) => Dispatcher.InvokeAsync(RefreshCloudView);
        _host.CloudVault.VaultChanged += (_, _) => Dispatcher.InvokeAsync(RefreshCloudView);
        _host.HandoffPipe.HandoffReceived += (_, _) => Dispatcher.InvokeAsync(RefreshCloudView);

        Loaded += async (_, _) => await InitializeViewsAsync();
    }

    private async Task InitializeViewsAsync()
    {
        PopulatePrivacyRegionComboBox();
        LoadSettingsAndPrivacyUi();
        await RefreshAllAsync(computeModelHashes: false);
    }

    public void SelectNavigationTab(int index)
    {
        ViewApps.Visibility = index == 0 ? Visibility.Visible : Visibility.Collapsed;
        ViewCloud.Visibility = index == 1 ? Visibility.Visible : Visibility.Collapsed;
        ViewModels.Visibility = index == 2 ? Visibility.Visible : Visibility.Collapsed;
        ViewLicense.Visibility = index == 3 ? Visibility.Visible : Visibility.Collapsed;
        ViewSettings.Visibility = index == 4 ? Visibility.Visible : Visibility.Collapsed;

        var activeStyle = (Style)Application.Current.Resources["SidebarNavBtnActive"];
        var normalStyle = (Style)Application.Current.Resources["SidebarNavBtn"];

        BtnNavApps.Style = index == 0 ? activeStyle : normalStyle;
        BtnNavCloud.Style = index == 1 ? activeStyle : normalStyle;
        BtnNavModels.Style = index == 2 ? activeStyle : normalStyle;
        BtnNavLicense.Style = index == 3 ? activeStyle : normalStyle;
        BtnNavSettings.Style = index == 4 ? activeStyle : normalStyle;

        HeaderViewTitle.Text = index switch
        {
            0 => "Apps & Updates",
            1 => "Cloud & Cross-App Handoff",
            2 => "AI Model Vault",
            3 => "Unified License",
            4 => "Settings & Privacy",
            _ => "OmniHub"
        };
    }

    public void ToggleThemeMode()
    {
        var current = _host.Settings.Load();
        current.Theme = current.Theme == OmniHubThemeMode.Dark
            ? OmniHubThemeMode.Light
            : OmniHubThemeMode.Dark;
        _host.Settings.Save(current);
        ThemeManager.ApplyTheme(Application.Current.Resources, current.Theme);
        SetStatus($"Switched interface to {current.Theme} theme.");
    }

    // ─── Refresh Orchestration ───────────────────────────────────────────────

    private async Task RefreshAllAsync(bool computeModelHashes)
    {
        await RefreshAppsViewAsync();
        RefreshCloudView();
        await RefreshModelsViewAsync(computeModelHashes);
        RefreshLicenseView();
        LoadSettingsAndPrivacyUi();
    }

    private async Task RefreshAppsViewAsync()
    {
        var statuses = await _host.AppManager.DiscoverAllAsync();
        var lf = statuses.First(s => s.Product == ManagedProductId.LogicFlow);
        var aeon = statuses.First(s => s.Product == ManagedProductId.AeonBrowser);

        _suppressUiEvents = true;
        try
        {
            TxtLfVersionSub.Text = $"v{lf.Version} • System Optimization, HyperStore & Sentinel";
            TxtLfStatusBadge.Text = lf.IsRunning
                ? "Running"
                : lf.State switch
                {
                    ProductInstallState.Installed => "Installed",
                    ProductInstallState.InstallerAvailable => "Setup Ready",
                    _ => "Not Installed"
                };
            TxtLfPath.Text = $"Path: {lf.ExecutablePath ?? lf.InstallerPath ?? "Not found"}";
            TxtLfSha256.Text = lf.ExecutableSha256 is not null
                ? $"SHA-256: {lf.ExecutableSha256[..24]}… ({OmniHubBrandConstants.FormatBytes(lf.ExecutableSizeBytes ?? 0)})"
                : "SHA-256: —";
            CmbLfChannel.SelectedIndex = string.Equals(lf.Channel, "beta", StringComparison.OrdinalIgnoreCase) ? 1 : 0;
            BtnLfLaunch.IsEnabled = lf.State == ProductInstallState.Installed;
            BtnLfLaunchCli.IsEnabled = !string.IsNullOrWhiteSpace(lf.CliExecutablePath);

            TxtAeonVersionSub.Text = $"v{aeon.Version} • Anti-Fingerprinting & Agentic Browser";
            TxtAeonStatusBadge.Text = aeon.IsRunning
                ? "Running"
                : aeon.State switch
                {
                    ProductInstallState.Installed => "Installed",
                    ProductInstallState.InstallerAvailable => "Setup Ready",
                    _ => "Not Installed"
                };
            TxtAeonPath.Text = $"Path: {aeon.ExecutablePath ?? aeon.InstallerPath ?? "Not found"}";
            TxtAeonSha256.Text = aeon.ExecutableSha256 is not null
                ? $"SHA-256: {aeon.ExecutableSha256[..24]}… ({OmniHubBrandConstants.FormatBytes(aeon.ExecutableSizeBytes ?? 0)})"
                : "SHA-256: —";
            CmbAeonChannel.SelectedIndex = string.Equals(aeon.Channel, "beta", StringComparison.OrdinalIgnoreCase) ? 1 : 0;
            BtnAeonLaunch.IsEnabled = aeon.State == ProductInstallState.Installed;
        }
        finally
        {
            _suppressUiEvents = false;
        }
    }

    private void RefreshCloudView()
    {
        TxtCloudVaultPath.Text = _host.CloudVault.VaultRootPath;
        var files = _host.CloudVault.ListVaultFiles();
        var snapshots = _host.CloudVault.ListSnapshots();
        var events = _host.HandoffPipe.GetRecentEvents(25);

        TxtVaultFilesHeader.Text = $"Live DelgadoLogic Cloud Files ({files.Count})";
        LstVaultFiles.ItemsSource = files.Select(f => new
        {
            f.RelativePath,
            SizeDisplay = OmniHubBrandConstants.FormatBytes(f.SizeBytes),
            CategoryAndTime = $"{f.Category} • {OmniHubBrandConstants.FormatEst(f.LastModifiedUtc)}"
        }).ToArray();

        TxtSnapshotsHeader.Text = $"Zstd .lfc Snapshot History ({snapshots.Count})";
        LstSnapshots.ItemsSource = snapshots.Select(s => new SnapshotRowViewModel(
            s.SnapshotId,
            OmniHubBrandConstants.FormatEst(s.CreatedAtUtc),
            $"{s.FileCount} files • Raw {OmniHubBrandConstants.FormatBytes(s.RawBytes)} → .lfc {OmniHubBrandConstants.FormatBytes(s.CompressedBytes)} ({s.CompressionRatio:F2}x)",
            $"{s.TriggerReason} • Tree SHA-256: {s.ContentTreeSha256[..Math.Min(16, s.ContentTreeSha256.Length)]}…")).ToArray();

        if (LstSnapshots.Items.Count > 0 && LstSnapshots.SelectedIndex < 0)
            LstSnapshots.SelectedIndex = 0;

        LstHandoffEvents.ItemsSource = events.Select(ev => new
        {
            HeaderLine = $"[{OmniHubBrandConstants.FormatEst(ev.TimestampUtc)}] {ev.Method}",
            ev.Summary
        }).ToArray();

        SidebarPipeBadge.Text = _host.HandoffPipe.IsRunning
            ? $"IPC Online: {_host.HandoffPipe.FullPipePath}"
            : "IPC Pipe Stopped";
    }

    private async Task RefreshModelsViewAsync(bool computeHashes)
    {
        TxtModelVaultRoot.Text = _host.ModelVault.UsedNonElevatedFallback
            ? $"{_host.ModelVault.ActiveVaultRoot} (User-scope fallback — run elevated for %ProgramData%)"
            : _host.ModelVault.ActiveVaultRoot;

        var entries = await _host.ModelVault.ScanCatalogAsync(computeSha256: computeHashes);
        long activeSavings = entries
            .Where(e => e.ExistsInSharedVault && e.HardLinkCount > 1)
            .Sum(e => (long)(e.HardLinkCount - 1) * e.SizeBytes);

        int presentCount = entries.Count(e => e.ExistsInSharedVault);
        TxtModelSavingsMeter.Text = activeSavings > 0
            ? $"Active NTFS Hard-Link Savings: {OmniHubBrandConstants.FormatBytes(activeSavings)} saved across {presentCount} vaulted model(s)."
            : $"{presentCount} of {entries.Count} catalog model(s) present in Shared Vault • Click 'Scan & Hard-Link Deduplicate' to consolidate.";

        ItemsModelCatalog.ItemsSource = entries.Select(e => new
        {
            e.DisplayName,
            MetaBadge = $"{e.ParameterSummary} • {e.LicenseName}",
            FileNameAndSize = $"{e.FileName} • {OmniHubBrandConstants.FormatBytes(e.SizeBytes)}",
            ChecksumAndLinksLine = e.ExistsInSharedVault
                ? $"NTFS Links: {e.HardLinkCount} ({e.LinkedExternalPaths.Count} app dir linked, {e.UnlinkedDuplicatePaths.Count} unlinked) • GGUF {(e.HasValidGgufHeader ? $"v{e.GgufFormatVersion}" : "Unverified")}" +
                  (e.Sha256Hex is not null ? $" • SHA-256: {e.Sha256Hex[..20]}…" : "")
                : e.UnlinkedDuplicatePaths.Count > 0
                    ? $"Discovered in {e.UnlinkedDuplicatePaths.Count} external folder(s) — ready to hard-link into Shared Vault"
                    : "Not downloaded locally (optional on-demand GGUF sidecar)",
            PresenceBadge = e.ExistsInSharedVault
                ? (e.HardLinkCount > 1 ? $"HARD-LINKED (x{e.HardLinkCount})" : "IN VAULT")
                : (e.UnlinkedDuplicatePaths.Count > 0 ? "CAN DEDUPLICATE" : "NOT INSTALLED")
        }).ToArray();
    }

    private void RefreshLicenseView()
    {
        var snap = _host.LicenseHub.GetCurrentSnapshot();
        TxtLicenseEditionBig.Text = snap.EditionDisplayName;
        TxtLicenseSeatCount.Text = $"{snap.SeatLimit} {(snap.SeatLimit == 1 ? "Device Seat" : "Device Seats")}";
        TxtLicenseStatusSummary.Text = snap.StatusMessage;
        TxtLicenseSourceAndExpiry.Text = snap.IsTokenCryptographicallyValid
            ? $"Verified via {snap.SignatureAlgorithm} • Order: {snap.OrderId ?? "Offline"} • Expires: {(snap.ExpiresAt.HasValue ? OmniHubBrandConstants.FormatEst(snap.ExpiresAt.Value) : "Perpetual v1.x")}"
            : "Dual Ed25519 + RSA-2048 offline verification • Shared across LogicFlow & Aeon Browser";

        TxtMachineHwid.Text = snap.MachineHwid;
        SidebarEditionBadge.Text = $"{snap.EditionDisplayName} Edition";
        SidebarSeatsBadge.Text = $"{snap.SeatLimit} {(snap.SeatLimit == 1 ? "Seat" : "Seats")}";
    }

    private void PopulatePrivacyRegionComboBox()
    {
        _suppressUiEvents = true;
        try
        {
            CmbPrivacyRegion.Items.Clear();
            foreach (var region in Enum.GetValues<PrivacyRegion>())
            {
                CmbPrivacyRegion.Items.Add(new ComboBoxItem
                {
                    Content = region.DisplayName(),
                    Tag = region
                });
            }
        }
        finally
        {
            _suppressUiEvents = false;
        }
    }

    private void LoadSettingsAndPrivacyUi()
    {
        _suppressUiEvents = true;
        try
        {
            var settings = _host.Settings.Load();
            ChkLaunchAtStartup.IsChecked = settings.LaunchAtWindowsStartup;
            ChkMinimizeToTray.IsChecked = settings.MinimizeToTrayOnClose;
            TxtHotkeyStatus.Text = _trayService.HotkeyStatusDescription;

            var record = _host.Consent.Current;
            var effective = _host.Consent.EffectiveLevel();
            var activeRegion = record.RegionConfirmed ? record.Region : _host.Consent.DetectRegionFromWindows();

            for (int i = 0; i < CmbPrivacyRegion.Items.Count; i++)
            {
                if (CmbPrivacyRegion.Items[i] is ComboBoxItem item && item.Tag is PrivacyRegion r && r == activeRegion)
                {
                    CmbPrivacyRegion.SelectedIndex = i;
                    break;
                }
            }

            ChkStandardTelemetry.IsChecked = effective >= ConsentLevel.Standard;
            ChkExtendedTelemetry.IsChecked = effective == ConsentLevel.Extended;

            TxtEffectiveConsentBadge.Text = effective switch
            {
                ConsentLevel.Extended => "Effective Level: Extended Pseudonymous",
                ConsentLevel.Standard => "Effective Level: Standard Pseudonymous",
                _ => "Effective Level: None (OFF)"
            };

            TxtPseudonymousInstallId.Text = string.IsNullOrWhiteSpace(record.InstallId) || effective == ConsentLevel.None
                ? "None active (ConsentLevel.None — nothing queued or sent)"
                : record.InstallId;
        }
        finally
        {
            _suppressUiEvents = false;
        }
    }

    // ─── Navigation & Window Chrome Handlers ─────────────────────────────────

    private void OnNavAppsClick(object sender, RoutedEventArgs e) => SelectNavigationTab(0);
    private void OnNavCloudClick(object sender, RoutedEventArgs e) => SelectNavigationTab(1);
    private void OnNavModelsClick(object sender, RoutedEventArgs e) => SelectNavigationTab(2);
    private void OnNavLicenseClick(object sender, RoutedEventArgs e) => SelectNavigationTab(3);
    private void OnNavSettingsClick(object sender, RoutedEventArgs e) => SelectNavigationTab(4);

    private void OnToggleThemeClick(object sender, RoutedEventArgs e) => ToggleThemeMode();

    private async void OnRefreshAllClick(object sender, RoutedEventArgs e)
    {
        SetStatus("Refreshing OmniHub ecosystem state...");
        await RefreshAllAsync(computeModelHashes: false);
        SetStatus("Ecosystem state refreshed.");
    }

    private async void OnOpenQuickLauncherClick(object sender, RoutedEventArgs e) =>
        await _openQuickLauncherCallback();

    private void OnMinimizeClick(object sender, RoutedEventArgs e) =>
        WindowState = WindowState.Minimized;

    private void OnMaximizeRestoreClick(object sender, RoutedEventArgs e) =>
        WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;

    private async void OnCloseClick(object sender, RoutedEventArgs e)
    {
        var settings = _host.Settings.Load();
        if (settings.MinimizeToTrayOnClose)
        {
            Hide();
            return;
        }

        await _exitCallback();
    }

    private void OnWindowClosing(object? sender, CancelEventArgs e)
    {
        if (AllowImmediateClose)
            return;

        if (_host.Settings.Load().MinimizeToTrayOnClose)
        {
            e.Cancel = true;
            Hide();
        }
    }

    private async void OnWindowPreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (Keyboard.Modifiers == ModifierKeys.Control)
        {
            switch (e.Key)
            {
                case Key.D1: e.Handled = true; SelectNavigationTab(0); return;
                case Key.D2: e.Handled = true; SelectNavigationTab(1); return;
                case Key.D3: e.Handled = true; SelectNavigationTab(2); return;
                case Key.D4: e.Handled = true; SelectNavigationTab(3); return;
                case Key.D5: e.Handled = true; SelectNavigationTab(4); return;
                case Key.K: e.Handled = true; await _openQuickLauncherCallback(); return;
            }
        }
        else if (e.Key == Key.F5)
        {
            e.Handled = true;
            await RefreshAllAsync(computeModelHashes: false);
        }
    }

    // ─── View 0: Apps & Updates Handlers ─────────────────────────────────────

    private void OnLfChannelChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_suppressUiEvents || CmbLfChannel.SelectedItem is not ComboBoxItem item) return;
        var ch = item.Tag?.ToString() ?? "stable";
        _host.AppManager.SetChannel(ManagedProductId.LogicFlow, ch);
        TxtLfUpdateStatus.Text = $"Channel set to {ch}";
    }

    private void OnAeonChannelChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_suppressUiEvents || CmbAeonChannel.SelectedItem is not ComboBoxItem item) return;
        var ch = item.Tag?.ToString() ?? "stable";
        _host.AppManager.SetChannel(ManagedProductId.AeonBrowser, ch);
        TxtAeonUpdateStatus.Text = $"Channel set to {ch}";
    }

    private async void OnCheckAllUpdatesClick(object sender, RoutedEventArgs e)
    {
        TxtAppsActivityLog.Text = "Checking sovereign Ed25519 update manifests for LogicFlow and Aeon Browser...";
        var lfOut = await _host.AppManager.CheckForUpdateAsync(ManagedProductId.LogicFlow);
        var aeonOut = await _host.AppManager.CheckForUpdateAsync(ManagedProductId.AeonBrowser);
        TxtLfUpdateStatus.Text = lfOut.Message;
        TxtAeonUpdateStatus.Text = aeonOut.Message;
        TxtAppsActivityLog.Text = $"• LogicFlow ({lfOut.Channel}): {lfOut.Message}\n• Aeon Browser ({aeonOut.Channel}): {aeonOut.Message}";
        SetStatus("Completed sovereign update checks.");
    }

    private async void OnLfLaunchClick(object sender, RoutedEventArgs e)
    {
        var res = await _host.AppManager.LaunchProductAsync(ManagedProductId.LogicFlow);
        TxtAppsActivityLog.Text = res.Message;
        SetStatus(res.Message);
        await RefreshAppsViewAsync();
    }

    private async void OnLfLaunchCliClick(object sender, RoutedEventArgs e)
    {
        var res = await _host.LogicFlowCli.GetSystemStatusAsync();
        TxtAppsActivityLog.Text = res.Success
            ? $"lf.exe sys status --json succeeded (exit {res.ExitCode})."
            : $"lf.exe output: {res.StandardError}";
        SetStatus(TxtAppsActivityLog.Text);
    }

    private async void OnLfCheckUpdateClick(object sender, RoutedEventArgs e)
    {
        TxtLfUpdateStatus.Text = "Verifying Ed25519 manifest...";
        var res = await _host.AppManager.CheckForUpdateAsync(ManagedProductId.LogicFlow);
        TxtLfUpdateStatus.Text = res.Message;
        TxtAppsActivityLog.Text = res.Message;
        SetStatus(res.Message);
    }

    private async void OnLfInstallUpdateClick(object sender, RoutedEventArgs e)
    {
        TxtAppsActivityLog.Text = "Verifying and launching LogicFlow installer...";
        var res = await _host.AppManager.InstallOrUpdateAsync(ManagedProductId.LogicFlow, silent: false);
        TxtAppsActivityLog.Text = res.Message;
        SetStatus(res.Message);
        await RefreshAppsViewAsync();
    }

    private async void OnLfRepairClick(object sender, RoutedEventArgs e)
    {
        var rep = await _host.AppManager.RepairAsync(ManagedProductId.LogicFlow, launchInstallerOnFailure: false);
        TxtAppsActivityLog.Text = rep.Message;
        SetStatus(rep.Message);
    }

    private async void OnAeonLaunchClick(object sender, RoutedEventArgs e)
    {
        var res = await _host.AppManager.LaunchProductAsync(ManagedProductId.AeonBrowser);
        TxtAppsActivityLog.Text = res.Message;
        SetStatus(res.Message);
        await RefreshAppsViewAsync();
    }

    private async void OnAeonCheckUpdateClick(object sender, RoutedEventArgs e)
    {
        TxtAeonUpdateStatus.Text = "Verifying Ed25519 manifest...";
        var res = await _host.AppManager.CheckForUpdateAsync(ManagedProductId.AeonBrowser);
        TxtAeonUpdateStatus.Text = res.Message;
        TxtAppsActivityLog.Text = res.Message;
        SetStatus(res.Message);
    }

    private async void OnAeonInstallUpdateClick(object sender, RoutedEventArgs e)
    {
        TxtAppsActivityLog.Text = "Verifying and launching Aeon Browser installer...";
        var res = await _host.AppManager.InstallOrUpdateAsync(ManagedProductId.AeonBrowser, silent: false);
        TxtAppsActivityLog.Text = res.Message;
        SetStatus(res.Message);
        await RefreshAppsViewAsync();
    }

    private async void OnAeonRepairClick(object sender, RoutedEventArgs e)
    {
        var rep = await _host.AppManager.RepairAsync(ManagedProductId.AeonBrowser, launchInstallerOnFailure: false);
        TxtAppsActivityLog.Text = rep.Message;
        SetStatus(rep.Message);
    }

    // ─── View 1: Cloud & Cross-App Handoff Handlers ──────────────────────────

    private async void OnCreateCloudSnapshotClick(object sender, RoutedEventArgs e)
    {
        try
        {
            var snap = await _host.CloudVault.CreateSnapshotAsync("Manual UI", forceEvenIfUnchanged: true);
            RefreshCloudView();
            SetStatus($"Created .lfc snapshot {snap.SnapshotId} ({OmniHubBrandConstants.FormatBytes(snap.CompressedBytes)}).");
        }
        catch (Exception ex)
        {
            SetStatus($"Snapshot failed: {ex.Message}");
        }
    }

    private async void OnPackFolderToVaultClick(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFolderDialog
        {
            Title = "Select Directory to Pack into HyperStore .lfc Archive"
        };
        if (dlg.ShowDialog(this) != true)
            return;

        try
        {
            SetStatus($"Packing '{dlg.FolderName}' into HyperStore .lfc...");
            var outPath = await _host.CloudVault.PackExternalDirectoryToVaultAsync(dlg.FolderName);
            await _host.CloudVault.CreateSnapshotAsync($"Packed {System.IO.Path.GetFileName(outPath)}");
            RefreshCloudView();
            SetStatus($"Packed archive: {outPath}");
        }
        catch (Exception ex)
        {
            SetStatus($"Folder pack failed: {ex.Message}");
        }
    }

    private void OnOpenCloudFolderClick(object sender, RoutedEventArgs e) =>
        OmniHubRuntimeHost.OpenDirectoryInExplorer(_host.CloudVault.VaultRootPath);

    private async void OnRestoreSelectedSnapshotClick(object sender, RoutedEventArgs e)
    {
        if (LstSnapshots.SelectedItem is not SnapshotRowViewModel selected)
        {
            SetStatus("Select a snapshot from the history list first.");
            return;
        }

        try
        {
            var res = await _host.CloudVault.RestoreSnapshotAsync(selected.SnapshotId);
            RefreshCloudView();
            SetStatus(res.Message);
        }
        catch (Exception ex)
        {
            SetStatus($"Restore failed: {ex.Message}");
        }
    }

    private async void OnPullAeonSessionClick(object sender, RoutedEventArgs e)
    {
        try
        {
            var ev = await _host.HandoffPipe.HandoffSessionAsync("pull", "default", null, protectDpapi: true);
            RefreshCloudView();
            SetStatus(ev.Summary);
        }
        catch (Exception ex)
        {
            SetStatus($"Aeon session export unavailable: {ex.Message}");
        }
    }

    private async void OnPushAeonSessionClick(object sender, RoutedEventArgs e)
    {
        try
        {
            var ev = await _host.HandoffPipe.HandoffSessionAsync("export_to_aeon", "default");
            RefreshCloudView();
            SetStatus(ev.Summary);
        }
        catch (Exception ex)
        {
            SetStatus($"Aeon session push failed: {ex.Message}");
        }
    }

    private async void OnSendFileToHyperStoreClick(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog { Title = "Select File to Pack into HyperStore .lfc" };
        if (dlg.ShowDialog(this) != true) return;

        try
        {
            var ev = await _host.HandoffPipe.HandoffFileAsync(dlg.FileName, "hyperstore");
            RefreshCloudView();
            SetStatus(ev.Summary);
        }
        catch (Exception ex)
        {
            SetStatus($"HyperStore handoff failed: {ex.Message}");
        }
    }

    private async void OnScanFileWithSentinelClick(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog { Title = "Select File to Scan with Sentinel & Defender" };
        if (dlg.ShowDialog(this) != true) return;

        try
        {
            var ev = await _host.HandoffPipe.HandoffFileAsync(dlg.FileName, "sentinel", invokeExternalDefender: true);
            RefreshCloudView();
            SetStatus(ev.Summary);
        }
        catch (Exception ex)
        {
            SetStatus($"Sentinel scan failed: {ex.Message}");
        }
    }

    private async void OnQueryAeonTabsClick(object sender, RoutedEventArgs e)
    {
        if (!await _host.AeonPipe.IsAvailableAsync())
        {
            SetStatus(@"Aeon Browser IPC pipe (\\.\pipe\aeon-agent) is currently offline. Launch Aeon Browser first.");
            return;
        }

        var tabs = await _host.AeonPipe.ListTabsAsync();
        SetStatus($"Aeon Browser connected via Named Pipe: {tabs.Count} open tab(s).");
    }

    private async void OnOpenUrlInAeonClick(object sender, RoutedEventArgs e)
    {
        var url = TxtAeonUrlInput.Text.Trim();
        var ok = await _host.AeonPipe.OpenUrlAsync(url, newTab: true);
        SetStatus(ok
            ? $"Opened '{url}' in Aeon Browser via \\\\.\\pipe\\aeon-agent."
            : "Could not send URL to Aeon Browser pipe (verify Aeon Browser is running and URL uses https://).");
    }

    // ─── View 2: AI Model Vault Handlers ─────────────────────────────────────

    private async void OnDeduplicateModelsClick(object sender, RoutedEventArgs e)
    {
        SetStatus("Scanning LogicFlow & Aeon GGUF directories and creating NTFS hard links...");
        var report = await _host.ModelVault.DeduplicateAndLinkAllAsync();
        await RefreshModelsViewAsync(computeHashes: true);
        SetStatus($"Deduplication complete: {report.HardLinksCreated} hard link(s) created, {OmniHubBrandConstants.FormatBytes(report.BytesSavedThisRun)} newly reclaimed.");
    }

    private async void OnVerifyModelsShaClick(object sender, RoutedEventArgs e)
    {
        SetStatus("Computing streaming SHA-256 checksums across Shared Model Vault...");
        await RefreshModelsViewAsync(computeHashes: true);
        SetStatus("Model Vault SHA-256 verification complete.");
    }

    private void OnOpenModelVaultFolderClick(object sender, RoutedEventArgs e) =>
        OmniHubRuntimeHost.OpenDirectoryInExplorer(_host.ModelVault.ActiveVaultRoot);

    // ─── View 3: Unified License Handlers ────────────────────────────────────

    private void OnCopyHwidClick(object sender, RoutedEventArgs e)
    {
        try
        {
            Clipboard.SetText(TxtMachineHwid.Text);
            SetStatus("Copied Machine HWID to clipboard.");
        }
        catch (Exception ex)
        {
            SetStatus($"Clipboard copy failed: {ex.Message}");
        }
    }

    private async void OnActivateCloudOrderClick(object sender, RoutedEventArgs e)
    {
        SetStatus("Contacting DelgadoLogic license activation endpoint...");
        var res = await _host.LicenseHub.ActivateCloudOrderAsync(TxtOrderIdInput.Text, TxtOrderEmailInput.Text);
        RefreshLicenseView();
        SetStatus(res.Message);
    }

    private async void OnImportOfflineTokenClick(object sender, RoutedEventArgs e)
    {
        var res = await _host.LicenseHub.ImportOfflineTokenAsync(TxtOfflineTokenInput.Text);
        RefreshLicenseView();
        SetStatus(res.Message);
    }

    private async void OnBrowseLicenseFileClick(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Title = "Select DelgadoLogic License File",
            Filter = "License Files (*.lic;*.json)|*.lic;*.json|All Files (*.*)|*.*"
        };
        if (dlg.ShowDialog(this) != true)
            return;

        TxtOfflineTokenInput.Text = await System.IO.File.ReadAllTextAsync(dlg.FileName);
        var res = await _host.LicenseHub.ImportOfflineTokenAsync(dlg.FileName);
        RefreshLicenseView();
        SetStatus(res.Message);
    }

    // ─── View 4: Settings & Privacy Handlers ─────────────────────────────────

    private void OnStartupToggleClick(object sender, RoutedEventArgs e)
    {
        if (_suppressUiEvents) return;
        bool enabled = ChkLaunchAtStartup.IsChecked == true;
        bool ok = _host.Settings.SetLaunchAtStartup(enabled);
        SetStatus(ok
            ? (enabled ? "Enabled OmniHub tray launch at Windows sign-in." : "Disabled OmniHub Windows sign-in launch.")
            : "Unable to update HKCU Run startup registry key.");
    }

    private void OnMinimizeToTrayToggleClick(object sender, RoutedEventArgs e)
    {
        if (_suppressUiEvents) return;
        var s = _host.Settings.Load();
        s.MinimizeToTrayOnClose = ChkMinimizeToTray.IsChecked == true;
        _host.Settings.Save(s);
        SetStatus(s.MinimizeToTrayOnClose
            ? "Closing OmniHub will keep the background tray icon & Alt+Space active."
            : "Closing OmniHub will exit the application.");
    }

    private void OnPrivacyRegionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_suppressUiEvents || CmbPrivacyRegion.SelectedItem is not ComboBoxItem item || item.Tag is not PrivacyRegion region)
            return;

        _host.Consent.SetRegion(region);
        SetStatus($"Updated local privacy region to {region.DisplayName()} (no IP lookup performed).");
    }

    private void OnTelemetryConsentChanged(object sender, RoutedEventArgs e)
    {
        if (_suppressUiEvents) return;

        bool std = ChkStandardTelemetry.IsChecked == true;
        bool ext = ChkExtendedTelemetry.IsChecked == true;
        if (ext && !std)
        {
            std = true;
            ChkStandardTelemetry.IsChecked = true;
        }

        if (!std && !ext)
        {
            _host.Consent.SetOptionalTelemetry(false, false);
        }
        else
        {
            _host.Consent.SetOptionalTelemetry(std, ext);
        }

        LoadSettingsAndPrivacyUi();
        RefreshLicenseView();
        SetStatus($"Updated OmniPulse pseudonymous diagnostics consent to {_host.Consent.EffectiveLevel()}.");
    }

    private void OnRotateInstallIdClick(object sender, RoutedEventArgs e)
    {
        _host.Consent.RotateInstallId();
        LoadSettingsAndPrivacyUi();
        SetStatus("Rotated 128-bit random pseudonymous installId.");
    }

    private void OnDeleteTelemetryDataClick(object sender, RoutedEventArgs e)
    {
        var oldId = _host.Consent.ClearInstallId();
        if (!string.IsNullOrWhiteSpace(oldId))
            _host.Consent.SetPendingDelete(oldId);
        _host.Consent.SwitchToFree("2026-11", OmniHubBrandConstants.LogicFlowSetupSha256);

        LoadSettingsAndPrivacyUi();
        RefreshLicenseView();
        SetStatus("Cleared local pseudonymous installId, queued tombstone erasure, and reset consent to ConsentLevel.None.");
    }

    private void SetStatus(string text)
    {
        TxtGlobalStatusBar.Text = text;
    }

    private sealed record SnapshotRowViewModel(
        string SnapshotId,
        string EstTime,
        string MetricsLine,
        string ReasonAndHash);
}
