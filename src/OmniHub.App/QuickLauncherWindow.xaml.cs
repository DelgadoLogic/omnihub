using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using OmniHub.App.Services;
using OmniHub.Core;

namespace OmniHub.App;

public partial class QuickLauncherWindow : Window
{
    private readonly OmniHubRuntimeHost _host;
    private readonly Action<int> _navigateCallback;
    private readonly Action _toggleThemeCallback;
    private IReadOnlyList<QuickLauncherItem> _catalog = [];
    private bool _isExecuting;

    public QuickLauncherWindow(
        OmniHubRuntimeHost host,
        Action<int> navigateCallback,
        Action toggleThemeCallback)
    {
        InitializeComponent();
        _host = host;
        _navigateCallback = navigateCallback;
        _toggleThemeCallback = toggleThemeCallback;
    }

    public async Task ToggleOverlayAsync()
    {
        if (IsVisible)
        {
            Hide();
            return;
        }

        await ShowOverlayAsync();
    }

    public async Task ShowOverlayAsync()
    {
        PositionUpperCenter();
        _catalog = await _host.BuildQuickLauncherCatalogAsync(_navigateCallback, _toggleThemeCallback);
        SearchBox.Text = "";
        RefreshResults("");

        Show();
        Activate();
        SearchBox.Focus();
    }

    private void PositionUpperCenter()
    {
        var workArea = SystemParameters.WorkArea;
        Left = workArea.Left + ((workArea.Width - Width) / 2.0);
        Top = workArea.Top + Math.Max(60.0, workArea.Height * 0.16);
    }

    private void RefreshResults(string query)
    {
        PlaceholderText.Visibility = string.IsNullOrEmpty(query) ? Visibility.Visible : Visibility.Collapsed;
        var matches = _host.QuickSearch.Search(_catalog, query, maxResults: 25);
        ResultsList.ItemsSource = matches;
        if (matches.Count > 0)
        {
            ResultsList.SelectedIndex = 0;
            ResultsList.ScrollIntoView(matches[0]);
        }
        FooterStatusText.Text = $"{matches.Count} {(matches.Count == 1 ? "command" : "commands")}   •   ↑↓ Navigate   •   ↵ Execute   •   Esc Dismiss";
    }

    private void OnSearchTextChanged(object sender, TextChangedEventArgs e)
    {
        RefreshResults(SearchBox.Text);
    }

    private async void OnWindowPreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Escape)
        {
            e.Handled = true;
            Hide();
            return;
        }

        if (e.Key == Key.Down)
        {
            e.Handled = true;
            if (ResultsList.Items.Count > 0)
            {
                ResultsList.SelectedIndex = Math.Min(ResultsList.Items.Count - 1, ResultsList.SelectedIndex + 1);
                ResultsList.ScrollIntoView(ResultsList.SelectedItem);
            }
            return;
        }

        if (e.Key == Key.Up)
        {
            e.Handled = true;
            if (ResultsList.Items.Count > 0)
            {
                ResultsList.SelectedIndex = Math.Max(0, ResultsList.SelectedIndex - 1);
                ResultsList.ScrollIntoView(ResultsList.SelectedItem);
            }
            return;
        }

        if (e.Key == Key.Enter)
        {
            e.Handled = true;
            await ExecuteSelectedAsync();
        }
    }

    private async void OnResultDoubleClick(object sender, MouseButtonEventArgs e)
    {
        await ExecuteSelectedAsync();
    }

    private async Task ExecuteSelectedAsync()
    {
        if (_isExecuting || ResultsList.SelectedItem is not ScoredQuickLauncherItem scored)
            return;

        _isExecuting = true;
        try
        {
            Hide();
            if (scored.Item.ExecuteAsync is not null)
            {
                await scored.Item.ExecuteAsync(CancellationToken.None);
            }
        }
        catch (Exception ex)
        {
            FooterStatusText.Text = $"Action failed: {ex.Message}";
        }
        finally
        {
            _isExecuting = false;
        }
    }

    private void OnWindowDeactivated(object? sender, EventArgs e)
    {
        if (!_isExecuting && IsVisible)
        {
            Hide();
        }
    }
}
