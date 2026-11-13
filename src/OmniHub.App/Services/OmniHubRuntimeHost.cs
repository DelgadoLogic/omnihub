using System.Diagnostics;
using System.IO;
using OmniHub.Core;
using OmniPulse;

namespace OmniHub.App.Services;

/// <summary>
/// Central runtime host owning all OmniHub services, Named Pipe IPC daemon,
/// Cloud Vault watcher, and dynamic QuickLauncher command catalog.
/// </summary>
public sealed class OmniHubRuntimeHost : IAsyncDisposable
{
    public OmniHubSettingsService Settings { get; }
    public ConsentStore Consent { get; }
    public AppDiscoveryAndManagerService AppManager { get; }
    public UnifiedLicenseHubService LicenseHub { get; }
    public CloudVaultSyncService CloudVault { get; }
    public AeonPipeClient AeonPipe { get; }
    public LogicFlowCliBridge LogicFlowCli { get; }
    public CrossAppHandoffPipeService HandoffPipe { get; }
    public SharedModelVaultService ModelVault { get; }
    public QuickLauncherSearchService QuickSearch { get; }

    public OmniHubRuntimeHost()
    {
        Settings = new OmniHubSettingsService();
        Consent = new ConsentStore();
        AppManager = new AppDiscoveryAndManagerService(new AppDiscoveryOptions
        {
            SettingsService = Settings
        });
        LicenseHub = new UnifiedLicenseHubService(new UnifiedLicenseOptions
        {
            ConsentStore = Consent
        });
        CloudVault = new CloudVaultSyncService();
        AeonPipe = new AeonPipeClient();
        LogicFlowCli = new LogicFlowCliBridge(AppManager);
        HandoffPipe = new CrossAppHandoffPipeService(
            CloudVault,
            AeonPipe,
            LogicFlowCli,
            AppManager,
            LicenseHub);
        ModelVault = new SharedModelVaultService();
        QuickSearch = new QuickLauncherSearchService();
    }

    public void StartBackgroundServices()
    {
        CloudVault.InitializeVault();
        CloudVault.StartWatching();
        HandoffPipe.Start();
    }

    /// <summary>
    /// Builds the live Raycast-style command &amp; resource catalog across apps, .lfc snapshots,
    /// Aeon tabs/handoffs, AI vault operations, and OmniHub navigation.
    /// </summary>
    public async Task<IReadOnlyList<QuickLauncherItem>> BuildQuickLauncherCatalogAsync(
        Action<int>? navigateToTabCallback = null,
        Action? toggleThemeCallback = null,
        CancellationToken ct = default)
    {
        var items = new List<QuickLauncherItem>
        {
            new(
                "app.launch.logicflow",
                "Launch LogicFlow",
                "Start LogicFlow v1.0 desktop system suite",
                QuickCommandCategory.Apps,
                "APP",
                ["logicflow", "launch", "open", "optimizer", "guardian", "sentinel"],
                async token => { await AppManager.LaunchProductAsync(ManagedProductId.LogicFlow, false, null, token); }),

            new(
                "app.launch.logicflow.cli",
                "Launch LogicFlow CLI (lf.exe)",
                "Open headless LogicFlow command-line tool",
                QuickCommandCategory.Apps,
                "CLI",
                ["lf", "cli", "terminal", "logicflow", "json"],
                async token => { await AppManager.LaunchProductAsync(ManagedProductId.LogicFlow, true, "sys status --json", token); }),

            new(
                "app.launch.aeon",
                "Launch Aeon Browser",
                "Start Aeon Browser v0.22.0 privacy & agentic browser",
                QuickCommandCategory.Apps,
                "APP",
                ["aeon", "browser", "launch", "web"],
                async token => { await AppManager.LaunchProductAsync(ManagedProductId.AeonBrowser, false, null, token); }),

            new(
                "app.update.logicflow",
                "Check LogicFlow Updates",
                "Verify Ed25519 manifest on api.delgadologic.tech",
                QuickCommandCategory.Apps,
                "UPDATE",
                ["update", "logicflow", "ed25519", "manifest"],
                async token =>
                {
                    navigateToTabCallback?.Invoke(0);
                    await AppManager.CheckForUpdateAsync(ManagedProductId.LogicFlow, null, token);
                }),

            new(
                "app.update.aeon",
                "Check Aeon Browser Updates",
                "Verify Ed25519 manifest on api.delgadologic.tech",
                QuickCommandCategory.Apps,
                "UPDATE",
                ["update", "aeon", "ed25519", "manifest"],
                async token =>
                {
                    navigateToTabCallback?.Invoke(0);
                    await AppManager.CheckForUpdateAsync(ManagedProductId.AeonBrowser, null, token);
                }),

            new(
                "vault.snapshot.create",
                "Create Cloud .lfc Snapshot Now",
                "Pack %USERPROFILE%\\DelgadoLogic Cloud into a Zstd .lfc container",
                QuickCommandCategory.CloudVault,
                "CLOUD .LFC",
                ["snapshot", "lfc", "backup", "cloud", "vault", "zstd"],
                async token => { await CloudVault.CreateSnapshotAsync("QuickLauncher", ct: token); }),

            new(
                "vault.open.folder",
                "Open DelgadoLogic Cloud Folder",
                CloudVault.VaultRootPath,
                QuickCommandCategory.CloudVault,
                "FOLDER",
                ["open", "explorer", "cloud", "dropzone", "folder"],
                _ =>
                {
                    OpenDirectoryInExplorer(CloudVault.VaultRootPath);
                    return Task.CompletedTask;
                }),

            new(
                "aeon.session.pull",
                "Export Aeon Browser auth.json Session",
                "Pull Playwright storage state via \\\\.\\pipe\\aeon-agent and protect with DPAPI",
                QuickCommandCategory.AeonHandoff,
                "HANDOFF",
                ["session", "auth.json", "aeon", "dpapi", "cookies", "export"],
                async token => { await HandoffPipe.HandoffSessionAsync("pull", "default", null, true, token); }),

            new(
                "ai.deduplicate",
                "Scan & Hard-Link Deduplicate GGUF Models",
                "Deduplicate Gemma 4 & BGE weights into Shared Model Vault via NTFS CreateHardLinkW",
                QuickCommandCategory.AiModelVault,
                "AI VAULT",
                ["ai", "gemma", "gguf", "deduplicate", "hardlink", "models", "bge"],
                async token =>
                {
                    navigateToTabCallback?.Invoke(2);
                    await ModelVault.DeduplicateAndLinkAllAsync(token);
                }),

            new(
                "ai.open.folder",
                "Open Shared AI Model Vault Folder",
                ModelVault.ActiveVaultRoot,
                QuickCommandCategory.AiModelVault,
                "AI VAULT",
                ["models", "folder", "gguf", "programdata", "gemma"],
                _ =>
                {
                    OpenDirectoryInExplorer(ModelVault.ActiveVaultRoot);
                    return Task.CompletedTask;
                }),

            new(
                "nav.apps",
                "Go to Apps & Updates",
                "Manage LogicFlow v1.0 & Aeon Browser v0.22.0",
                QuickCommandCategory.Navigation,
                "VIEW",
                ["apps", "updates", "dashboard"],
                _ => { navigateToTabCallback?.Invoke(0); return Task.CompletedTask; }),

            new(
                "nav.cloud",
                "Go to Cloud & Cross-App Handoff",
                "Snapshots, Dropzone, Sessions & IPC Pipe Activity",
                QuickCommandCategory.Navigation,
                "VIEW",
                ["cloud", "handoff", "pipe", "snapshots"],
                _ => { navigateToTabCallback?.Invoke(1); return Task.CompletedTask; }),

            new(
                "nav.models",
                "Go to AI Model Vault",
                "Shared Gemma 4 E2B/E4B & BGE-Small GGUF catalog",
                QuickCommandCategory.Navigation,
                "VIEW",
                ["ai", "model", "vault", "gemma"],
                _ => { navigateToTabCallback?.Invoke(2); return Task.CompletedTask; }),

            new(
                "nav.license",
                "Go to Unified License",
                "Machine HWID, Edition seats & offline token activation",
                QuickCommandCategory.Navigation,
                "VIEW",
                ["license", "hwid", "pro", "activate", "seats"],
                _ => { navigateToTabCallback?.Invoke(3); return Task.CompletedTask; }),

            new(
                "nav.settings",
                "Go to Settings & Privacy",
                "Tray startup, Alt+Space hotkey & OmniPulse privacy controls",
                QuickCommandCategory.Navigation,
                "VIEW",
                ["settings", "privacy", "telemetry", "consent", "hotkey"],
                _ => { navigateToTabCallback?.Invoke(4); return Task.CompletedTask; }),

            new(
                "sys.theme.toggle",
                "Toggle Dark / Light Theme",
                "Switch between Obsidian Dark and Daylight Light mode",
                QuickCommandCategory.System,
                "THEME",
                ["theme", "dark", "light", "appearance"],
                _ => { toggleThemeCallback?.Invoke(); return Task.CompletedTask; })
        };

        // Append live .lfc snapshots for 1-click restore from Quick Launcher
        foreach (var snap in CloudVault.ListSnapshots().Take(8))
        {
            var capturedId = snap.SnapshotId;
            items.Add(new QuickLauncherItem(
                $"snapshot.restore.{capturedId}",
                $"Restore Snapshot {capturedId}",
                $"{snap.FileCount} files ({OmniHubBrandConstants.FormatBytes(snap.RawBytes)}) • {OmniHubBrandConstants.FormatEst(snap.CreatedAtUtc)}",
                QuickCommandCategory.CloudVault,
                "RESTORE",
                ["restore", "snapshot", "lfc", capturedId, snap.TriggerReason],
                async token => { await CloudVault.RestoreSnapshotAsync(capturedId, null, true, token); }));
        }

        // Append live Aeon Browser tabs if Aeon agent pipe is online
        if (await AeonPipe.IsAvailableAsync(ct).ConfigureAwait(false))
        {
            var tabs = await AeonPipe.ListTabsAsync(ct).ConfigureAwait(false);
            foreach (var tab in tabs.Take(10))
            {
                var tabUrl = tab.Url;
                var tabTitle = tab.Title;
                items.Add(new QuickLauncherItem(
                    $"aeon.tab.{tab.Id}",
                    $"Clip Aeon Tab: {tabTitle}",
                    tabUrl,
                    QuickCommandCategory.AeonHandoff,
                    "AEON TAB",
                    ["aeon", "tab", "clip", tabTitle, tabUrl],
                    async token =>
                    {
                        await HandoffPipe.HandoffClipAsync(
                            tabTitle,
                            $"# {tabTitle}\n\nSource URL: {tabUrl}\nClipped from live Aeon Browser tab #{tab.Id}.",
                            "markdown",
                            tabUrl,
                            ["aeon", "quick-clip"],
                            token);
                    }));
            }
        }

        return items;
    }

    public static void OpenDirectoryInExplorer(string directoryPath)
    {
        try
        {
            Directory.CreateDirectory(directoryPath);
            Process.Start(new ProcessStartInfo
            {
                FileName = "explorer.exe",
                Arguments = $"\"{directoryPath}\"",
                UseShellExecute = true
            });
        }
        catch
        {
            // Ignore shell open failures in headless environments
        }
    }

    public async ValueTask DisposeAsync()
    {
        await HandoffPipe.DisposeAsync().ConfigureAwait(false);
        CloudVault.Dispose();
        AppManager.Dispose();
    }
}
