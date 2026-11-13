using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using LogicFlow.Storage.Engine.Compression;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace OmniHub.Core;

public sealed record HandoffEventRecord(
    string EventId,
    string Method,
    bool Success,
    string Summary,
    string? ArtifactPath,
    string? SnapshotId,
    DateTimeOffset TimestampUtc);

public sealed record StoredSessionMetadata(
    string SessionName,
    bool IsDpapiProtected,
    string StorageFilePath,
    int CookieCount,
    int OriginCount,
    string PlaintextSha256,
    DateTimeOffset UpdatedAtUtc);

/// <summary>
/// Asynchronous multi-client JSON-RPC 2.0 Named Pipe server on \\.\pipe\delgadologic-omnihub
/// orchestrating cross-app file, clip, and DPAPI-protected Playwright session handoffs between
/// Aeon Browser, LogicFlow, and DelgadoLogic Cloud.
/// </summary>
public sealed class CrossAppHandoffPipeService : IAsyncDisposable, IDisposable
{
    private static readonly UTF8Encoding Utf8NoBom = new(encoderShouldEmitUTF8Identifier: false);
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
        WriteIndented = false
    };

    private readonly string _pipeName;
    private readonly CloudVaultSyncService _cloudVault;
    private readonly AeonPipeClient _aeonClient;
    private readonly LogicFlowCliBridge _lfBridge;
    private readonly AppDiscoveryAndManagerService _appDiscovery;
    private readonly UnifiedLicenseHubService _licenseHub;
    private readonly ILogger<CrossAppHandoffPipeService> _logger;
    private readonly ConcurrentQueue<HandoffEventRecord> _recentEvents = new();
    private readonly ConcurrentBag<Task> _clientTasks = [];

    private CancellationTokenSource? _serverCts;
    private Task? _acceptLoopTask;
    private bool _disposed;

    public event EventHandler<HandoffEventRecord>? HandoffReceived;

    public CrossAppHandoffPipeService(
        CloudVaultSyncService cloudVault,
        AeonPipeClient aeonClient,
        LogicFlowCliBridge lfBridge,
        AppDiscoveryAndManagerService appDiscovery,
        UnifiedLicenseHubService licenseHub,
        string? pipeName = null,
        ILogger<CrossAppHandoffPipeService>? logger = null)
    {
        _cloudVault = cloudVault ?? throw new ArgumentNullException(nameof(cloudVault));
        _aeonClient = aeonClient ?? throw new ArgumentNullException(nameof(aeonClient));
        _lfBridge = lfBridge ?? throw new ArgumentNullException(nameof(lfBridge));
        _appDiscovery = appDiscovery ?? throw new ArgumentNullException(nameof(appDiscovery));
        _licenseHub = licenseHub ?? throw new ArgumentNullException(nameof(licenseHub));
        _pipeName = AeonPipeClient.NormalizePipeName(pipeName ?? OmniHubBrandConstants.DefaultOmniHubPipeName);
        _logger = logger ?? NullLogger<CrossAppHandoffPipeService>.Instance;
    }

    public string PipeName => _pipeName;
    public string FullPipePath => $@"\\.\pipe\{_pipeName}";
    public bool IsRunning => _serverCts is { IsCancellationRequested: false } && _acceptLoopTask is { IsCompleted: false };

    public IReadOnlyList<HandoffEventRecord> GetRecentEvents(int maxCount = 50) =>
        _recentEvents.Reverse().Take(maxCount).ToArray();

    public void Start()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (IsRunning) return;

        _cloudVault.InitializeVault();
        _serverCts = new CancellationTokenSource();
        _acceptLoopTask = Task.Run(() => AcceptConnectionsLoopAsync(_serverCts.Token));
    }

    public async Task StopAsync()
    {
        if (_serverCts is null) return;
        await _serverCts.CancelAsync().ConfigureAwait(false);

        if (_acceptLoopTask is not null)
        {
            try { await _acceptLoopTask.ConfigureAwait(false); }
            catch (OperationCanceledException) { }
            catch { }
        }

        var active = _clientTasks.Where(t => !t.IsCompleted).ToArray();
        if (active.Length > 0)
        {
            try { await Task.WhenAll(active).WaitAsync(TimeSpan.FromSeconds(2)).ConfigureAwait(false); }
            catch { }
        }

        _serverCts.Dispose();
        _serverCts = null;
        _acceptLoopTask = null;
    }

    // ─── Direct Programmatic Handoff APIs (Shared by UI + Named Pipe RPC) ───

    public async Task<HandoffEventRecord> HandoffFileAsync(
        string sourcePath,
        string action = "vault",
        string? customFileName = null,
        bool invokeExternalDefender = false,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(sourcePath) || !File.Exists(sourcePath))
            throw new FileNotFoundException($"Handoff source file does not exist: {sourcePath}");

        _cloudVault.InitializeVault();
        var safeFileName = SanitizeSingleFileName(customFileName ?? Path.GetFileName(sourcePath));
        var dropzoneDest = Path.Combine(_cloudVault.DropzonePath, safeFileName);

        if (!string.Equals(Path.GetFullPath(sourcePath), Path.GetFullPath(dropzoneDest), StringComparison.OrdinalIgnoreCase))
        {
            File.Copy(sourcePath, dropzoneDest, overwrite: true);
        }

        string normalizedAction = (action ?? "vault").Trim().ToLowerInvariant();
        string artifactPath = dropzoneDest;
        string summary;

        switch (normalizedAction)
        {
            case "hyperstore":
            {
                var archiveOut = Path.Combine(
                    _cloudVault.ArchivesPath,
                    $"{Path.GetFileNameWithoutExtension(safeFileName)}_{DateTimeOffset.UtcNow:yyyyMMdd_HHmmss}.lfc");
                var (_, outPath, msg) = await _lfBridge.PackToHyperStoreAsync(dropzoneDest, archiveOut, CompressionTier.Hot, ct).ConfigureAwait(false);
                artifactPath = outPath;
                summary = msg;
                break;
            }

            case "sentinel":
            {
                var verdict = await _lfBridge.ScanFileAsync(dropzoneDest, invokeExternalDefender, ct).ConfigureAwait(false);
                var reportPath = Path.Combine(_cloudVault.ArchivesPath, $"{safeFileName}.sentinel.json");
                await File.WriteAllTextAsync(reportPath, JsonSerializer.Serialize(verdict, new JsonSerializerOptions { WriteIndented = true }), ct).ConfigureAwait(false);
                summary = verdict.Summary;
                break;
            }

            case "lazarus":
            {
                var queueDir = Path.Combine(_cloudVault.ArchivesPath, "LazarusQueue");
                Directory.CreateDirectory(queueDir);
                var queueManifest = Path.Combine(queueDir, $"{safeFileName}.lazarus.json");
                var payload = new
                {
                    queuedAtUtc = DateTimeOffset.UtcNow,
                    sourcePath,
                    stagedVaultPath = dropzoneDest,
                    sizeBytes = new FileInfo(dropzoneDest).Length
                };
                await File.WriteAllTextAsync(queueManifest, JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true }), ct).ConfigureAwait(false);
                artifactPath = queueManifest;
                summary = $"Queued '{safeFileName}' for LogicFlow Lazarus forensic inspection.";
                break;
            }

            default:
                summary = $"Ingested '{safeFileName}' into DelgadoLogic Cloud Dropzone.";
                break;
        }

        var snapshot = await _cloudVault.CreateSnapshotAsync($"handoff.file ({normalizedAction}): {safeFileName}", CompressionTier.Hot, false, ct).ConfigureAwait(false);
        return RecordEvent("handoff.file", true, summary, artifactPath, snapshot.SnapshotId);
    }

    public async Task<HandoffEventRecord> HandoffClipAsync(
        string title,
        string content,
        string format = "markdown",
        string? sourceUrl = null,
        IReadOnlyList<string>? tags = null,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(content))
            throw new ArgumentException("Clip content cannot be empty.", nameof(content));

        _cloudVault.InitializeVault();
        bool isHtml = string.Equals(format?.Trim(), "html", StringComparison.OrdinalIgnoreCase);
        var ext = isHtml ? ".html" : ".md";
        var baseSlug = SanitizeSlug(string.IsNullOrWhiteSpace(title) ? "aeon_clip" : title);
        var fileName = $"{DateTimeOffset.UtcNow:yyyyMMdd_HHmmss}_{baseSlug}{ext}";
        var clipPath = Path.Combine(_cloudVault.ClipsPath, fileName);

        string fullDocument;
        if (isHtml)
        {
            var comment = $"<!-- Clipped via DelgadoLogic OmniHub | Title: {title} | Source: {sourceUrl ?? "local"} | UTC: {DateTimeOffset.UtcNow:O} -->\n";
            fullDocument = comment + content;
        }
        else
        {
            var sb = new StringBuilder();
            sb.AppendLine("---");
            sb.AppendLine($"title: \"{(title ?? "Untitled Clip").Replace("\"", "\\\"")}\"");
            if (!string.IsNullOrWhiteSpace(sourceUrl))
                sb.AppendLine($"source_url: \"{sourceUrl.Replace("\"", "\\\"")}\"");
            sb.AppendLine($"clipped_at_utc: \"{DateTimeOffset.UtcNow:O}\"");
            if (tags is { Count: > 0 })
                sb.AppendLine($"tags: [{string.Join(", ", tags.Select(t => $"\"{t.Replace("\"", "")}\""))}]");
            sb.AppendLine("---");
            sb.AppendLine();
            sb.Append(content);
            fullDocument = sb.ToString();
        }

        await File.WriteAllTextAsync(clipPath, fullDocument, Utf8NoBom, ct).ConfigureAwait(false);
        var snapshot = await _cloudVault.CreateSnapshotAsync($"handoff.clip: {fileName}", CompressionTier.Hot, false, ct).ConfigureAwait(false);
        return RecordEvent("handoff.clip", true, $"Saved web clip '{fileName}' + .lfc snapshot.", clipPath, snapshot.SnapshotId);
    }

    public async Task<HandoffEventRecord> HandoffSessionAsync(
        string mode = "pull",
        string sessionName = "default",
        string? authJson = null,
        bool protectDpapi = true,
        CancellationToken ct = default)
    {
        _cloudVault.InitializeVault();
        var safeSession = SanitizeSlug(string.IsNullOrWhiteSpace(sessionName) ? "default" : sessionName);
        var normalizedMode = (mode ?? "pull").Trim().ToLowerInvariant();

        if (normalizedMode == "export_to_aeon")
        {
            var loadedAuth = await LoadStoredSessionAuthJsonAsync(safeSession, ct).ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(loadedAuth))
                throw new FileNotFoundException($"Stored session '{safeSession}' not found in DelgadoLogic Cloud\\Sessions.");

            var (ok, msg) = await _aeonClient.ImportSessionAsync(loadedAuth, ct).ConfigureAwait(false);
            if (!ok)
                throw new IOException(msg);

            return RecordEvent("handoff.session", true, $"Pushed stored session '{safeSession}' into Aeon Browser.", null, null);
        }

        string resolvedAuthJson;
        if (normalizedMode == "pull" && string.IsNullOrWhiteSpace(authJson))
        {
            var exported = await _aeonClient.ExportSessionAsync(null, ct).ConfigureAwait(false);
            if (!exported.Success || string.IsNullOrWhiteSpace(exported.AuthJson))
                throw new IOException(exported.Message);

            resolvedAuthJson = exported.AuthJson;
        }
        else
        {
            if (string.IsNullOrWhiteSpace(authJson))
                throw new ArgumentException("authJson is required when mode is 'push'.", nameof(authJson));

            using var _ = JsonDocument.Parse(authJson); // Validate JSON syntax
            resolvedAuthJson = authJson;
        }

        var (cookies, origins) = AeonPipeClient.CountStorageStateItems(resolvedAuthJson);
        var plainHash = Convert.ToHexString(SHA256.HashData(Utf8NoBom.GetBytes(resolvedAuthJson)));

        string storagePath;
        if (protectDpapi)
        {
            storagePath = Path.Combine(_cloudVault.SessionsPath, $"{safeSession}.auth.dpapi");
            var encrypted = DpapiProtector.ProtectString(resolvedAuthJson);
            await File.WriteAllBytesAsync(storagePath, encrypted, ct).ConfigureAwait(false);

            // Remove any stale plaintext file of the same session name
            var stalePlain = Path.Combine(_cloudVault.SessionsPath, $"{safeSession}.auth.json");
            if (File.Exists(stalePlain)) File.Delete(stalePlain);
        }
        else
        {
            storagePath = Path.Combine(_cloudVault.SessionsPath, $"{safeSession}.auth.json");
            await File.WriteAllTextAsync(storagePath, resolvedAuthJson, Utf8NoBom, ct).ConfigureAwait(false);
        }

        var meta = new StoredSessionMetadata(
            safeSession,
            protectDpapi,
            storagePath,
            cookies,
            origins,
            plainHash,
            DateTimeOffset.UtcNow);
        var metaPath = Path.Combine(_cloudVault.SessionsPath, $"{safeSession}.meta.json");
        await File.WriteAllTextAsync(metaPath, JsonSerializer.Serialize(meta, new JsonSerializerOptions { WriteIndented = true }), ct).ConfigureAwait(false);

        var snapshot = await _cloudVault.CreateSnapshotAsync($"handoff.session: {safeSession}", CompressionTier.Hot, false, ct).ConfigureAwait(false);
        var protectionLabel = protectDpapi ? "DPAPI-encrypted" : "JSON";
        return RecordEvent(
            "handoff.session",
            true,
            $"Saved {protectionLabel} Aeon session '{safeSession}' ({cookies} cookies, {origins} origins).",
            storagePath,
            snapshot.SnapshotId);
    }

    public async Task<string?> LoadStoredSessionAuthJsonAsync(string sessionName = "default", CancellationToken ct = default)
    {
        var safeSession = SanitizeSlug(string.IsNullOrWhiteSpace(sessionName) ? "default" : sessionName);
        var dpapiPath = Path.Combine(_cloudVault.SessionsPath, $"{safeSession}.auth.dpapi");
        if (File.Exists(dpapiPath))
        {
            var cipher = await File.ReadAllBytesAsync(dpapiPath, ct).ConfigureAwait(false);
            return DpapiProtector.UnprotectString(cipher);
        }

        var plainPath = Path.Combine(_cloudVault.SessionsPath, $"{safeSession}.auth.json");
        if (File.Exists(plainPath))
        {
            return await File.ReadAllTextAsync(plainPath, Utf8NoBom, ct).ConfigureAwait(false);
        }

        return null;
    }

    public IReadOnlyList<StoredSessionMetadata> ListStoredSessions()
    {
        _cloudVault.InitializeVault();
        var list = new List<StoredSessionMetadata>();
        foreach (var metaFile in Directory.EnumerateFiles(_cloudVault.SessionsPath, "*.meta.json", SearchOption.TopDirectoryOnly))
        {
            try
            {
                var meta = JsonSerializer.Deserialize<StoredSessionMetadata>(
                    File.ReadAllText(metaFile),
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
                if (meta is not null && File.Exists(meta.StorageFilePath))
                    list.Add(meta);
            }
            catch
            {
                // Ignore unreadable metadata file
            }
        }
        return list.OrderByDescending(m => m.UpdatedAtUtc).ToArray();
    }

    // ─── Named Pipe Accept & JSON-RPC 2.0 Dispatch ──────────────────────────

    private async Task AcceptConnectionsLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            NamedPipeServerStream? serverPipe = null;
            try
            {
                serverPipe = new NamedPipeServerStream(
                    _pipeName,
                    PipeDirection.InOut,
                    NamedPipeServerStream.MaxAllowedServerInstances,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous);

                await serverPipe.WaitForConnectionAsync(ct).ConfigureAwait(false);
                var acceptedPipe = serverPipe;
                serverPipe = null; // Ownership transferred to client task

                var clientTask = Task.Run(() => HandlePipeClientAsync(acceptedPipe, ct), CancellationToken.None);
                _clientTasks.Add(clientTask);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                serverPipe?.Dispose();
                break;
            }
            catch (Exception ex)
            {
                serverPipe?.Dispose();
                _logger.LogDebug(ex, "[OmniHub.IPC] Pipe accept loop transient error.");
                try { await Task.Delay(50, ct).ConfigureAwait(false); } catch { break; }
            }
        }
    }

    private async Task HandlePipeClientAsync(NamedPipeServerStream pipe, CancellationToken ct)
    {
        await using (pipe)
        {
            try
            {
                using var reader = new StreamReader(pipe, Utf8NoBom, detectEncodingFromByteOrderMarks: false, bufferSize: 16384, leaveOpen: true);
                await using var writer = new StreamWriter(pipe, Utf8NoBom, bufferSize: 16384, leaveOpen: true) { AutoFlush = true };

                while (pipe.IsConnected && !ct.IsCancellationRequested)
                {
                    var line = await reader.ReadLineAsync(ct).ConfigureAwait(false);
                    if (line is null)
                        break;
                    if (string.IsNullOrWhiteSpace(line))
                        continue;

                    var responseJson = await DispatchJsonRpcLineAsync(line, ct).ConfigureAwait(false);
                    await writer.WriteLineAsync(responseJson.AsMemory(), ct).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException)
            {
            }
            catch (IOException)
            {
                // Client disconnected after reading response
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "[OmniHub.IPC] Error handling pipe client.");
            }
        }
    }

    internal async Task<string> DispatchJsonRpcLineAsync(string rawJson, CancellationToken ct = default)
    {
        JsonNode? idNode = null;
        try
        {
            using var doc = JsonDocument.Parse(rawJson);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
                return BuildRpcError(null, -32600, "Invalid Request: JSON root must be an object.");

            if (root.TryGetProperty("id", out var idElem))
                idNode = JsonNode.Parse(idElem.GetRawText());

            var method = GetPropString(root, "method") ?? GetPropString(root, "cmd");
            if (string.IsNullOrWhiteSpace(method))
                return BuildRpcError(idNode, -32600, "Invalid Request: missing 'method' field.");

            JsonElement paramsObj = root.TryGetProperty("params", out var pElem) && pElem.ValueKind == JsonValueKind.Object
                ? pElem
                : root;

            object resultPayload = await ExecuteRpcMethodAsync(method.Trim(), paramsObj, ct).ConfigureAwait(false);
            return BuildRpcResult(idNode, resultPayload);
        }
        catch (JsonException ex)
        {
            return BuildRpcError(idNode, -32700, $"Parse error: {ex.Message}");
        }
        catch (UnknownRpcMethodException ex)
        {
            return BuildRpcError(idNode, -32601, ex.Message);
        }
        catch (Exception ex)
        {
            RecordEvent("rpc.error", false, ex.Message, null, null);
            return BuildRpcError(idNode, -32000, ex.Message);
        }
    }

    private async Task<object> ExecuteRpcMethodAsync(string method, JsonElement p, CancellationToken ct)
    {
        switch (method.ToLowerInvariant())
        {
            case "omnihub.ping":
                return new
                {
                    ok = true,
                    service = "OmniHub",
                    publisher = OmniHubBrandConstants.LegalEntity,
                    version = OmniHubBrandConstants.Version,
                    pipe = _pipeName,
                    timestampUtc = DateTimeOffset.UtcNow
                };

            case "omnihub.status":
            {
                var apps = await _appDiscovery.DiscoverAllAsync(ct).ConfigureAwait(false);
                var lic = _licenseHub.GetCurrentSnapshot();
                var snaps = _cloudVault.ListSnapshots();
                return new
                {
                    ok = true,
                    version = OmniHubBrandConstants.Version,
                    vaultRoot = _cloudVault.VaultRootPath,
                    snapshotCount = snaps.Count,
                    recentHandoffsCount = _recentEvents.Count,
                    activeEdition = lic.EditionDisplayName,
                    seatLimit = lic.SeatLimit,
                    logicFlowState = apps.First(a => a.Product == ManagedProductId.LogicFlow).State.ToString(),
                    aeonState = apps.First(a => a.Product == ManagedProductId.AeonBrowser).State.ToString()
                };
            }

            case "handoff.file":
            {
                var sourcePath = GetPropString(p, "sourcePath", "source_path", "path");
                if (string.IsNullOrWhiteSpace(sourcePath))
                    throw new ArgumentException("Missing required parameter 'sourcePath'.");

                var action = GetPropString(p, "action") ?? "vault";
                var fileName = GetPropString(p, "fileName", "file_name");
                bool runDefender = p.TryGetProperty("invokeDefender", out var defEl) && defEl.ValueKind == JsonValueKind.True;

                var ev = await HandoffFileAsync(sourcePath, action, fileName, runDefender, ct).ConfigureAwait(false);
                return new
                {
                    ok = ev.Success,
                    eventId = ev.EventId,
                    summary = ev.Summary,
                    artifactPath = ev.ArtifactPath,
                    snapshotId = ev.SnapshotId
                };
            }

            case "handoff.clip":
            {
                var title = GetPropString(p, "title") ?? "Aeon Web Clip";
                var content = GetPropString(p, "content", "markdown", "html");
                if (string.IsNullOrWhiteSpace(content))
                    throw new ArgumentException("Missing required parameter 'content'.");

                var format = GetPropString(p, "format") ?? "markdown";
                var sourceUrl = GetPropString(p, "sourceUrl", "source_url", "url");
                List<string>? tags = null;
                if (p.TryGetProperty("tags", out var tagsEl) && tagsEl.ValueKind == JsonValueKind.Array)
                {
                    tags = tagsEl.EnumerateArray()
                        .Where(x => x.ValueKind == JsonValueKind.String)
                        .Select(x => x.GetString()!)
                        .ToList();
                }

                var ev = await HandoffClipAsync(title, content, format, sourceUrl, tags, ct).ConfigureAwait(false);
                return new
                {
                    ok = ev.Success,
                    eventId = ev.EventId,
                    summary = ev.Summary,
                    clipPath = ev.ArtifactPath,
                    snapshotId = ev.SnapshotId
                };
            }

            case "handoff.session":
            {
                var mode = GetPropString(p, "mode") ?? "pull";
                var sessionName = GetPropString(p, "sessionName", "session_name") ?? "default";
                var authJson = GetPropString(p, "authJson", "auth_json");
                if (string.IsNullOrWhiteSpace(authJson) &&
                    p.TryGetProperty("authJson", out var authObj) &&
                    authObj.ValueKind == JsonValueKind.Object)
                {
                    authJson = authObj.GetRawText();
                }

                bool protectDpapi = !p.TryGetProperty("protectDpapi", out var dpEl) || dpEl.ValueKind != JsonValueKind.False;
                var ev = await HandoffSessionAsync(mode, sessionName, authJson, protectDpapi, ct).ConfigureAwait(false);
                return new
                {
                    ok = ev.Success,
                    eventId = ev.EventId,
                    summary = ev.Summary,
                    sessionPath = ev.ArtifactPath,
                    snapshotId = ev.SnapshotId
                };
            }

            default:
                throw new UnknownRpcMethodException($"Method not found: '{method}'.");
        }
    }

    private HandoffEventRecord RecordEvent(
        string method,
        bool success,
        string summary,
        string? artifactPath,
        string? snapshotId)
    {
        var ev = new HandoffEventRecord(
            Guid.NewGuid().ToString("N")[..12],
            method,
            success,
            summary,
            artifactPath,
            snapshotId,
            DateTimeOffset.UtcNow);

        _recentEvents.Enqueue(ev);
        while (_recentEvents.Count > 200 && _recentEvents.TryDequeue(out _))
        {
        }

        HandoffReceived?.Invoke(this, ev);
        return ev;
    }

    private static string BuildRpcResult(JsonNode? idNode, object result)
    {
        var envelope = new JsonObject
        {
            ["jsonrpc"] = "2.0",
            ["id"] = idNode?.DeepClone(),
            ["result"] = JsonSerializer.SerializeToNode(result, JsonOpts)
        };
        return envelope.ToJsonString();
    }

    private static string BuildRpcError(JsonNode? idNode, int code, string message)
    {
        var envelope = new JsonObject
        {
            ["jsonrpc"] = "2.0",
            ["id"] = idNode?.DeepClone(),
            ["error"] = new JsonObject
            {
                ["code"] = code,
                ["message"] = message
            }
        };
        return envelope.ToJsonString();
    }

    private static string? GetPropString(JsonElement obj, params string[] names)
    {
        foreach (var n in names)
        {
            if (obj.TryGetProperty(n, out var prop) && prop.ValueKind == JsonValueKind.String)
                return prop.GetString();
        }
        return null;
    }

    private static string SanitizeSingleFileName(string rawName)
    {
        var justName = Path.GetFileName(rawName.Trim());
        var invalid = Path.GetInvalidFileNameChars();
        var cleaned = new string(justName.Select(c => invalid.Contains(c) ? '_' : c).ToArray()).Trim('.');
        return string.IsNullOrWhiteSpace(cleaned) ? $"handoff_{DateTimeOffset.UtcNow:yyyyMMdd_HHmmss}.bin" : cleaned;
    }

    private static string SanitizeSlug(string input)
    {
        var sb = new StringBuilder(input.Length);
        foreach (var ch in input.Trim())
        {
            if (char.IsLetterOrDigit(ch) || ch is '-' or '_')
                sb.Append(char.ToLowerInvariant(ch));
            else if (char.IsWhiteSpace(ch))
                sb.Append('_');
        }
        var res = sb.ToString().Trim('_');
        if (res.Length > 48) res = res[..48];
        return string.IsNullOrWhiteSpace(res) ? "item" : res;
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        _disposed = true;
        await StopAsync().ConfigureAwait(false);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        StopAsync().GetAwaiter().GetResult();
    }

    private sealed class UnknownRpcMethodException(string message) : Exception(message);
}

/// <summary>
/// JSON-RPC 2.0 Named Pipe client helper for connecting to \\.\pipe\delgadologic-omnihub.
/// </summary>
public static class OmniHubPipeClient
{
    private static readonly UTF8Encoding Utf8NoBom = new(encoderShouldEmitUTF8Identifier: false);

    public static async Task<JsonDocument> SendRequestAsync(
        string pipeName,
        string method,
        object? parameters = null,
        string? requestId = null,
        TimeSpan? timeout = null,
        CancellationToken ct = default)
    {
        var normalizedPipe = AeonPipeClient.NormalizePipeName(pipeName);
        var effectiveTimeout = timeout ?? TimeSpan.FromSeconds(10);

        await using var client = new NamedPipeClientStream(".", normalizedPipe, PipeDirection.InOut, PipeOptions.Asynchronous);
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(effectiveTimeout);

        await client.ConnectAsync(cts.Token).ConfigureAwait(false);

        var envelope = new
        {
            jsonrpc = "2.0",
            id = requestId ?? Guid.NewGuid().ToString("N")[..8],
            method,
            @params = parameters ?? new { }
        };

        await using var writer = new StreamWriter(client, Utf8NoBom, 8192, leaveOpen: true) { AutoFlush = true };
        using var reader = new StreamReader(client, Utf8NoBom, detectEncodingFromByteOrderMarks: false, bufferSize: 16384, leaveOpen: true);

        await writer.WriteLineAsync(JsonSerializer.Serialize(envelope).AsMemory(), cts.Token).ConfigureAwait(false);
        var responseLine = await reader.ReadLineAsync(cts.Token).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(responseLine))
            throw new IOException("OmniHub pipe server returned an empty response.");

        return JsonDocument.Parse(responseLine);
    }
}
