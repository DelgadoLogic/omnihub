using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace OmniHub.Core;

public sealed record AeonTabInfo(
    int Id,
    string Title,
    string Url,
    bool Active);

public sealed record AeonBrowserInfo(
    bool Connected,
    string Version,
    int OpenTabCount,
    string? EngineName);

public sealed record AeonSessionExportResult(
    bool Success,
    string? AuthJson,
    int CookieCount,
    int OriginCount,
    string Message);

/// <summary>
/// Named Pipe IPC client for Aeon Browser (\\.\pipe\aeon-agent).
/// Speaks Aeon's newline-delimited JSON command protocol.
/// </summary>
public sealed class AeonPipeClient
{
    private static readonly UTF8Encoding Utf8NoBom = new(encoderShouldEmitUTF8Identifier: false);

    private readonly string _pipeName;
    private readonly TimeSpan _connectTimeout;
    private readonly TimeSpan _responseTimeout;

    public AeonPipeClient(
        string? pipeName = null,
        TimeSpan? connectTimeout = null,
        TimeSpan? responseTimeout = null)
    {
        _pipeName = NormalizePipeName(pipeName ?? OmniHubBrandConstants.DefaultAeonAgentPipeName);
        _connectTimeout = connectTimeout ?? TimeSpan.FromMilliseconds(1500);
        _responseTimeout = responseTimeout ?? TimeSpan.FromSeconds(5);
    }

    public string PipeName => _pipeName;
    public string FullPipePath => $@"\\.\pipe\{_pipeName}";

    public static string NormalizePipeName(string rawPipe)
    {
        if (string.IsNullOrWhiteSpace(rawPipe))
            return OmniHubBrandConstants.DefaultAeonAgentPipeName;

        var trimmed = rawPipe.Trim();
        const string prefix = @"\\.\pipe\";
        if (trimmed.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            return trimmed[prefix.Length..];
        return trimmed;
    }

    public async Task<bool> IsAvailableAsync(CancellationToken ct = default)
    {
        try
        {
            await using var client = new NamedPipeClientStream(".", _pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromMilliseconds(500));
            await client.ConnectAsync(cts.Token).ConfigureAwait(false);
            return client.IsConnected;
        }
        catch
        {
            return false;
        }
    }

    public async Task<JsonDocument> SendRawCommandAsync(object commandPayload, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(commandPayload);

        await using var client = new NamedPipeClientStream(".", _pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        using (var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct))
        {
            connectCts.CancelAfter(_connectTimeout);
            await client.ConnectAsync(connectCts.Token).ConfigureAwait(false);
        }

        var serialized = JsonSerializer.Serialize(commandPayload, new JsonSerializerOptions
        {
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
        }) + "\n";

        var reqBytes = Utf8NoBom.GetBytes(serialized);
        using var respCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        respCts.CancelAfter(_responseTimeout);

        await client.WriteAsync(reqBytes, respCts.Token).ConfigureAwait(false);
        await client.FlushAsync(respCts.Token).ConfigureAwait(false);

        using var reader = new StreamReader(client, Utf8NoBom, detectEncodingFromByteOrderMarks: false, bufferSize: 16384, leaveOpen: true);
        var line = await reader.ReadLineAsync(respCts.Token).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(line))
        {
            var rest = await reader.ReadToEndAsync(respCts.Token).ConfigureAwait(false);
            line = rest?.Trim();
        }

        if (string.IsNullOrWhiteSpace(line))
            throw new IOException("Aeon agent pipe closed without sending a JSON response.");

        return JsonDocument.Parse(line);
    }

    public async Task<AeonBrowserInfo> GetBrowserInfoAsync(CancellationToken ct = default)
    {
        try
        {
            using var doc = await SendRawCommandAsync(new { cmd = "browser.info" }, ct).ConfigureAwait(false);
            var root = doc.RootElement;
            bool ok = !root.TryGetProperty("ok", out var okProp) || okProp.ValueKind != JsonValueKind.False;
            if (!ok)
                return new AeonBrowserInfo(false, OmniHubBrandConstants.AeonBaselineVersion, 0, null);

            var ver = TryGetString(root, "version") ?? OmniHubBrandConstants.AeonBaselineVersion;
            var engine = TryGetString(root, "engine") ?? "Aeon Blink/Camoufox";
            int tabCount = root.TryGetProperty("tab_count", out var tc) && tc.TryGetInt32(out var n)
                ? n
                : root.TryGetProperty("tabs", out var tArr) && tArr.ValueKind == JsonValueKind.Array
                    ? tArr.GetArrayLength()
                    : 0;

            return new AeonBrowserInfo(true, ver, tabCount, engine);
        }
        catch
        {
            return new AeonBrowserInfo(false, OmniHubBrandConstants.AeonBaselineVersion, 0, null);
        }
    }

    public async Task<IReadOnlyList<AeonTabInfo>> ListTabsAsync(CancellationToken ct = default)
    {
        try
        {
            using var doc = await SendRawCommandAsync(new { cmd = "tab.list" }, ct).ConfigureAwait(false);
            var root = doc.RootElement;
            if (!root.TryGetProperty("tabs", out var tabsElem) || tabsElem.ValueKind != JsonValueKind.Array)
                return [];

            var list = new List<AeonTabInfo>();
            foreach (var item in tabsElem.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.Object) continue;
                int id = item.TryGetProperty("id", out var idProp) && idProp.TryGetInt32(out var parsedId)
                    ? parsedId
                    : list.Count;
                string title = TryGetString(item, "title") ?? "Untitled Tab";
                string url = TryGetString(item, "url") ?? "about:blank";
                bool active = item.TryGetProperty("active", out var actProp) && actProp.ValueKind == JsonValueKind.True;
                list.Add(new AeonTabInfo(id, title, url, active));
            }
            return list;
        }
        catch
        {
            return [];
        }
    }

    public async Task<bool> OpenUrlAsync(string url, bool newTab = true, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(url) || !IsAllowedBrowserUrl(url))
            return false;

        try
        {
            var payload = newTab
                ? (object)new { cmd = "tab.new", url = url.Trim() }
                : new { cmd = "navigate", url = url.Trim() };
            using var doc = await SendRawCommandAsync(payload, ct).ConfigureAwait(false);
            return !doc.RootElement.TryGetProperty("ok", out var okProp) || okProp.ValueKind == JsonValueKind.True;
        }
        catch
        {
            return false;
        }
    }

    public async Task<AeonSessionExportResult> ExportSessionAsync(string? domainFilter = null, CancellationToken ct = default)
    {
        try
        {
            object payload = string.IsNullOrWhiteSpace(domainFilter)
                ? new { cmd = "session.export" }
                : new { cmd = "session.export", domain = domainFilter.Trim() };

            using var doc = await SendRawCommandAsync(payload, ct).ConfigureAwait(false);
            var root = doc.RootElement;

            if (root.TryGetProperty("ok", out var okProp) && okProp.ValueKind == JsonValueKind.False)
            {
                var err = TryGetString(root, "error") ?? "Aeon Browser rejected session.export.";
                return new AeonSessionExportResult(false, null, 0, 0, err);
            }

            string? authJson = ExtractAuthJsonFromElement(root);
            if (string.IsNullOrWhiteSpace(authJson))
            {
                return new AeonSessionExportResult(false, null, 0, 0, "Aeon Browser returned an empty session state.");
            }

            var (cookies, origins) = CountStorageStateItems(authJson);
            return new AeonSessionExportResult(
                true,
                authJson,
                cookies,
                origins,
                $"Exported Playwright auth.json ({cookies} cookies, {origins} origins).");
        }
        catch (Exception ex)
        {
            return new AeonSessionExportResult(false, null, 0, 0, $"Aeon pipe unavailable: {ex.Message}");
        }
    }

    public async Task<(bool Success, string Message)> ImportSessionAsync(string authJson, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(authJson))
            return (false, "authJson payload is empty.");

        try
        {
            using var _ = JsonDocument.Parse(authJson); // Ensure valid JSON before sending
            using var doc = await SendRawCommandAsync(new { cmd = "session.import", auth_json = authJson }, ct).ConfigureAwait(false);
            bool ok = !doc.RootElement.TryGetProperty("ok", out var okProp) || okProp.ValueKind == JsonValueKind.True;
            var msg = ok
                ? "Imported session storage state into Aeon Browser."
                : (TryGetString(doc.RootElement, "error") ?? "Aeon Browser rejected session.import.");
            return (ok, msg);
        }
        catch (Exception ex)
        {
            return (false, $"Session import failed: {ex.Message}");
        }
    }

    public static (int Cookies, int Origins) CountStorageStateItems(string authJson)
    {
        try
        {
            using var doc = JsonDocument.Parse(authJson);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                return (0, 0);

            int cookies = root.TryGetProperty("cookies", out var c) && c.ValueKind == JsonValueKind.Array ? c.GetArrayLength() : 0;
            int origins = root.TryGetProperty("origins", out var o) && o.ValueKind == JsonValueKind.Array ? o.GetArrayLength() : 0;
            return (cookies, origins);
        }
        catch
        {
            return (0, 0);
        }
    }

    private static string? ExtractAuthJsonFromElement(JsonElement root)
    {
        foreach (var key in new[] { "auth_json", "authJson", "storageState", "storage_state", "session" })
        {
            if (!root.TryGetProperty(key, out var prop))
                continue;

            if (prop.ValueKind == JsonValueKind.String)
                return prop.GetString();
            if (prop.ValueKind == JsonValueKind.Object)
                return prop.GetRawText();
        }

        // If the response itself has cookies/origins directly
        if (root.TryGetProperty("cookies", out _) || root.TryGetProperty("origins", out _))
        {
            return root.GetRawText();
        }

        return null;
    }

    private static bool IsAllowedBrowserUrl(string url)
    {
        var trimmed = url.Trim();
        if (trimmed.StartsWith("aeon://", StringComparison.OrdinalIgnoreCase))
            return true;

        return Uri.TryCreate(trimmed, UriKind.Absolute, out var uri) &&
               (uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
                uri.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase));
    }

    private static string? TryGetString(JsonElement obj, string propName)
    {
        return obj.TryGetProperty(propName, out var prop) && prop.ValueKind == JsonValueKind.String
            ? prop.GetString()
            : null;
    }
}
