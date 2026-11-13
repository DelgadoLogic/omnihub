using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using LogicFlow.Storage.Engine.Container;
using OmniHub.Core;
using OmniPulse;

namespace OmniHub.Tests;

public sealed class CrossAppHandoffPipeTests : IAsyncDisposable
{
    private static readonly UTF8Encoding Utf8NoBom = new(encoderShouldEmitUTF8Identifier: false);

    private readonly string _tempRoot;
    private readonly string _vaultRoot;
    private readonly string _omniHubPipeName;
    private readonly string _aeonPipeName;
    private readonly CloudVaultSyncService _cloudVault;
    private readonly AeonPipeClient _aeonClient;
    private readonly AppDiscoveryAndManagerService _appDiscovery;
    private readonly LogicFlowCliBridge _lfBridge;
    private readonly UnifiedLicenseHubService _licenseHub;
    private readonly CrossAppHandoffPipeService _handoffServer;
    private readonly CancellationTokenSource _mockAeonCts = new();
    private readonly Task _mockAeonTask;
    private readonly ConcurrentQueue<string> _aeonReceivedCommands = new();

    private string _mockAeonExportedAuthJson = """
        {
          "cookies": [
            { "name": "session_token", "value": "SUPER_SECRET_AEON_COOKIE_99182", "domain": ".delgadologic.tech", "path": "/" },
            { "name": "csrf_guard", "value": "CSRF_VAL_772", "domain": ".delgadologic.tech", "path": "/" }
          ],
          "origins": [
            {
              "origin": "https://delgadologic.tech",
              "localStorage": [
                { "name": "theme", "value": "obsidian" }
              ]
            }
          ]
        }
        """;

    private string? _lastAeonImportedAuthJson;

    public CrossAppHandoffPipeTests()
    {
        _tempRoot = Path.Combine(Path.GetTempPath(), $"omnihub_ipc_tests_{Guid.NewGuid():N}");
        _vaultRoot = Path.Combine(_tempRoot, "DelgadoLogic Cloud");
        Directory.CreateDirectory(_tempRoot);

        _omniHubPipeName = $"omnihub-test-{Guid.NewGuid():N}";
        _aeonPipeName = $"aeon-test-{Guid.NewGuid():N}";

        _mockAeonTask = Task.Run(() => RunMockAeonPipeServerAsync(_mockAeonCts.Token));

        _cloudVault = new CloudVaultSyncService(_vaultRoot);
        _aeonClient = new AeonPipeClient(_aeonPipeName, TimeSpan.FromSeconds(3), TimeSpan.FromSeconds(5));
        _appDiscovery = new AppDiscoveryAndManagerService(new AppDiscoveryOptions
        {
            ProgramFilesOverride = Path.Combine(_tempRoot, "PF"),
            LocalAppDataOverride = Path.Combine(_tempRoot, "LocalAppData"),
            WorkspaceRootOverride = Path.Combine(_tempRoot, "WS"),
            StagingRootOverride = Path.Combine(_tempRoot, "Staging"),
            RegistryReader = (_, _) => null,
            ProcessDetector = _ => [],
            SettingsService = new OmniHubSettingsService(Path.Combine(_tempRoot, "Settings"), (_, _) => { })
        });
        _lfBridge = new LogicFlowCliBridge(_appDiscovery);
        _licenseHub = new UnifiedLicenseHubService(new UnifiedLicenseOptions
        {
            LicenseSearchPathsOverride = [Path.Combine(_tempRoot, "nonexistent.lic")],
            ConsentStore = new ConsentStore(Path.Combine(_tempRoot, "Pulse"), (_, _) => null)
        });

        _handoffServer = new CrossAppHandoffPipeService(
            _cloudVault,
            _aeonClient,
            _lfBridge,
            _appDiscovery,
            _licenseHub,
            _omniHubPipeName);
        _handoffServer.Start();
    }

    [Fact]
    public async Task PingAndStatus_OverNamedPipeJsonRpc_ReturnVerifiedPublisherAndRuntimeSnapshot()
    {
        using var pingDoc = await OmniHubPipeClient.SendRequestAsync(_omniHubPipeName, "omnihub.ping");
        var pingResult = pingDoc.RootElement.GetProperty("result");
        Assert.True(pingResult.GetProperty("ok").GetBoolean());
        Assert.Equal("OmniHub", pingResult.GetProperty("service").GetString());
        Assert.Equal(OmniHubBrandConstants.LegalEntity, pingResult.GetProperty("publisher").GetString());
        Assert.Equal(_omniHubPipeName, pingResult.GetProperty("pipe").GetString());

        using var statusDoc = await OmniHubPipeClient.SendRequestAsync(_omniHubPipeName, "omnihub.status");
        var statusResult = statusDoc.RootElement.GetProperty("result");
        Assert.True(statusResult.GetProperty("ok").GetBoolean());
        Assert.Equal(_cloudVault.VaultRootPath, statusResult.GetProperty("vaultRoot").GetString());
        Assert.Equal("Free", statusResult.GetProperty("activeEdition").GetString());
    }

    [Fact]
    public async Task HandoffFile_VaultAction_OverNamedPipe_CopiesToDropzoneAndCreatesLfcSnapshot()
    {
        var externalFile = Path.Combine(_tempRoot, "scraped_dataset.csv");
        await File.WriteAllTextAsync(externalFile, "id,metric\n1,99.4\n2,88.1\n", Encoding.UTF8);

        using var resp = await OmniHubPipeClient.SendRequestAsync(_omniHubPipeName, "handoff.file", new
        {
            sourcePath = externalFile,
            action = "vault"
        });

        var res = resp.RootElement.GetProperty("result");
        Assert.True(res.GetProperty("ok").GetBoolean());

        var artifactPath = res.GetProperty("artifactPath").GetString()!;
        Assert.True(File.Exists(artifactPath));
        Assert.StartsWith(_cloudVault.DropzonePath, artifactPath, StringComparison.OrdinalIgnoreCase);

        var snapshotId = res.GetProperty("snapshotId").GetString()!;
        Assert.Contains(_cloudVault.ListSnapshots(), s => s.SnapshotId == snapshotId);
    }

    [Fact]
    public async Task HandoffFile_HyperStoreAction_OverNamedPipe_PacksValidLfcArchiveIntoVaultArchives()
    {
        var externalFile = Path.Combine(_tempRoot, "telemetry_bundle.json");
        await File.WriteAllTextAsync(externalFile, string.Concat(Enumerable.Repeat("{\"event\":\"sample\"}\n", 80)), Encoding.UTF8);

        using var resp = await OmniHubPipeClient.SendRequestAsync(_omniHubPipeName, "handoff.file", new
        {
            sourcePath = externalFile,
            action = "hyperstore"
        });

        var res = resp.RootElement.GetProperty("result");
        Assert.True(res.GetProperty("ok").GetBoolean());

        var lfcPath = res.GetProperty("artifactPath").GetString()!;
        Assert.True(File.Exists(lfcPath));
        Assert.EndsWith(".lfc", lfcPath, StringComparison.OrdinalIgnoreCase);

        using var reader = new LfcReader();
        var info = reader.InspectArchive(lfcPath);
        Assert.Equal(1, info.TotalFiles);
    }

    [Fact]
    public async Task HandoffFile_SentinelAndLazarusActions_OverNamedPipe_WriteForensicVerdictAndQueueManifest()
    {
        var sampleBin = Path.Combine(_tempRoot, "driver_sample.bin");
        await File.WriteAllBytesAsync(sampleBin, [0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00]);

        using var sentinelResp = await OmniHubPipeClient.SendRequestAsync(_omniHubPipeName, "handoff.file", new
        {
            sourcePath = sampleBin,
            action = "sentinel",
            invokeDefender = false
        });
        Assert.True(sentinelResp.RootElement.GetProperty("result").GetProperty("ok").GetBoolean());
        var expectedSentinelJson = Path.Combine(_cloudVault.ArchivesPath, "driver_sample.bin.sentinel.json");
        Assert.True(File.Exists(expectedSentinelJson));
        Assert.Contains("ShannonEntropy", await File.ReadAllTextAsync(expectedSentinelJson), StringComparison.Ordinal);

        using var lazarusResp = await OmniHubPipeClient.SendRequestAsync(_omniHubPipeName, "handoff.file", new
        {
            sourcePath = sampleBin,
            action = "lazarus"
        });
        var lazRes = lazarusResp.RootElement.GetProperty("result");
        Assert.True(lazRes.GetProperty("ok").GetBoolean());
        var queueManifest = lazRes.GetProperty("artifactPath").GetString()!;
        Assert.True(File.Exists(queueManifest));
        Assert.EndsWith(".lazarus.json", queueManifest, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task HandoffClip_MarkdownAndHtml_OverNamedPipe_WritesFrontmatterClipsAndSnapshots()
    {
        using var mdResp = await OmniHubPipeClient.SendRequestAsync(_omniHubPipeName, "handoff.clip", new
        {
            title = "Gemma 4 Architecture Notes",
            content = "## Key Takeaways\n- 128K context window\n- Apache-2.0 weights",
            format = "markdown",
            sourceUrl = "https://delgadologic.tech/research/gemma4",
            tags = new[] { "ai", "gguf" }
        });

        var mdRes = mdResp.RootElement.GetProperty("result");
        Assert.True(mdRes.GetProperty("ok").GetBoolean());
        var mdPath = mdRes.GetProperty("clipPath").GetString()!;
        Assert.True(File.Exists(mdPath));
        var mdText = await File.ReadAllTextAsync(mdPath);
        Assert.Contains("title: \"Gemma 4 Architecture Notes\"", mdText, StringComparison.Ordinal);
        Assert.Contains("source_url: \"https://delgadologic.tech/research/gemma4\"", mdText, StringComparison.Ordinal);
        Assert.Contains("tags: [\"ai\", \"gguf\"]", mdText, StringComparison.Ordinal);

        using var htmlResp = await OmniHubPipeClient.SendRequestAsync(_omniHubPipeName, "handoff.clip", new
        {
            title = "Captured DOM",
            content = "<article><h1>Captured</h1></article>",
            format = "html",
            sourceUrl = "https://delgadologic.tech"
        });

        var htmlPath = htmlResp.RootElement.GetProperty("result").GetProperty("clipPath").GetString()!;
        Assert.EndsWith(".html", htmlPath, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("<!-- Clipped via DelgadoLogic OmniHub", await File.ReadAllTextAsync(htmlPath), StringComparison.Ordinal);
    }

    [Fact]
    public async Task HandoffSession_PullFromAeonAgentPipe_EncryptsPlaywrightStateWithDpapiAndExportsBackToAeon()
    {
        // 1. Pull live Playwright storage state from \\.\pipe\aeon-test-* and store DPAPI-encrypted
        using var pullResp = await OmniHubPipeClient.SendRequestAsync(_omniHubPipeName, "handoff.session", new
        {
            mode = "pull",
            sessionName = "work_profile",
            protectDpapi = true
        });

        var pullRes = pullResp.RootElement.GetProperty("result");
        Assert.True(pullRes.GetProperty("ok").GetBoolean());

        var dpapiPath = pullRes.GetProperty("sessionPath").GetString()!;
        Assert.True(File.Exists(dpapiPath));
        Assert.EndsWith(".auth.dpapi", dpapiPath, StringComparison.OrdinalIgnoreCase);

        // Verify raw ciphertext on disk NEVER contains the plaintext cookie value
        var rawCipherBytes = await File.ReadAllBytesAsync(dpapiPath);
        var rawAsLatin1 = Encoding.Latin1.GetString(rawCipherBytes);
        Assert.DoesNotContain("SUPER_SECRET_AEON_COOKIE_99182", rawAsLatin1, StringComparison.Ordinal);

        // Verify metadata and DPAPI decryption round-trip
        var sessions = _handoffServer.ListStoredSessions();
        var sessionMeta = Assert.Single(sessions, s => s.SessionName == "work_profile");
        Assert.True(sessionMeta.IsDpapiProtected);
        Assert.Equal(2, sessionMeta.CookieCount);
        Assert.Equal(1, sessionMeta.OriginCount);

        var decrypted = await _handoffServer.LoadStoredSessionAuthJsonAsync("work_profile");
        Assert.NotNull(decrypted);
        Assert.Contains("SUPER_SECRET_AEON_COOKIE_99182", decrypted!, StringComparison.Ordinal);

        // 2. Push stored DPAPI session back into Aeon via session.import
        using var pushBackResp = await OmniHubPipeClient.SendRequestAsync(_omniHubPipeName, "handoff.session", new
        {
            mode = "export_to_aeon",
            sessionName = "work_profile"
        });
        Assert.True(pushBackResp.RootElement.GetProperty("result").GetProperty("ok").GetBoolean());
        Assert.NotNull(_lastAeonImportedAuthJson);
        Assert.Contains("SUPER_SECRET_AEON_COOKIE_99182", _lastAeonImportedAuthJson!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task AeonPipeClient_ListTabsBrowserInfoAndOpenUrl_CommunicatesOverNewlineJsonPipe()
    {
        Assert.True(await _aeonClient.IsAvailableAsync());

        var info = await _aeonClient.GetBrowserInfoAsync();
        Assert.True(info.Connected);
        Assert.Equal("0.22.0", info.Version);
        Assert.Equal(2, info.OpenTabCount);

        var tabs = await _aeonClient.ListTabsAsync();
        Assert.Equal(2, tabs.Count);
        Assert.Contains(tabs, t => t.Title == "DelgadoLogic Portal" && t.Active);

        Assert.True(await _aeonClient.OpenUrlAsync("https://delgadologic.tech/docs", newTab: true));
        // Reject javascript: / file: URLs fail-closed
        Assert.False(await _aeonClient.OpenUrlAsync("javascript:alert(1)"));
    }

    [Fact]
    public async Task UnknownMethodAndMalformedJson_OverNamedPipe_ReturnStandardJsonRpcErrorCodesWithoutCrashing()
    {
        using var unknownDoc = await OmniHubPipeClient.SendRequestAsync(_omniHubPipeName, "omnihub.nonexistent_method");
        var err = unknownDoc.RootElement.GetProperty("error");
        Assert.Equal(-32601, err.GetProperty("code").GetInt32());

        // Malformed JSON via internal line dispatcher
        var parseErrRaw = await _handoffServer.DispatchJsonRpcLineAsync("{not-valid-json");
        using var parseErrDoc = JsonDocument.Parse(parseErrRaw);
        Assert.Equal(-32700, parseErrDoc.RootElement.GetProperty("error").GetProperty("code").GetInt32());

        // Verify server remains healthy afterward
        using var pingAfter = await OmniHubPipeClient.SendRequestAsync(_omniHubPipeName, "omnihub.ping");
        Assert.True(pingAfter.RootElement.GetProperty("result").GetProperty("ok").GetBoolean());
    }

    [Fact]
    public async Task ConcurrentPipeClients_ParallelRequests_AllCompleteDeterministically()
    {
        var tasks = Enumerable.Range(0, 8).Select(async idx =>
        {
            using var doc = await OmniHubPipeClient.SendRequestAsync(
                _omniHubPipeName,
                "omnihub.ping",
                requestId: $"req-{idx}");
            Assert.Equal($"req-{idx}", doc.RootElement.GetProperty("id").GetString());
            Assert.True(doc.RootElement.GetProperty("result").GetProperty("ok").GetBoolean());
        });

        await Task.WhenAll(tasks);
    }

    // ─── Mock \\.\pipe\aeon-agent Server ─────────────────────────────────────

    private async Task RunMockAeonPipeServerAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            NamedPipeServerStream? server = null;
            try
            {
                server = new NamedPipeServerStream(
                    _aeonPipeName,
                    PipeDirection.InOut,
                    NamedPipeServerStream.MaxAllowedServerInstances,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous);

                await server.WaitForConnectionAsync(ct).ConfigureAwait(false);
                var clientPipe = server;
                server = null;

                _ = Task.Run(async () =>
                {
                    await using (clientPipe)
                    {
                        try
                        {
                            using var reader = new StreamReader(clientPipe, Utf8NoBom, false, 16384, leaveOpen: true);
                            await using var writer = new StreamWriter(clientPipe, Utf8NoBom, 16384, leaveOpen: true) { AutoFlush = true };

                            var line = await reader.ReadLineAsync(ct).ConfigureAwait(false);
                            if (string.IsNullOrWhiteSpace(line))
                                return;

                            _aeonReceivedCommands.Enqueue(line);
                            using var doc = JsonDocument.Parse(line);
                            var cmd = doc.RootElement.TryGetProperty("cmd", out var c) ? c.GetString() : "";

                            string reply = cmd switch
                            {
                                "browser.info" => """{"ok":true,"version":"0.22.0","tab_count":2,"engine":"Aeon Chromium"}""",
                                "tab.list" => """{"ok":true,"tabs":[{"id":1,"title":"DelgadoLogic Portal","url":"https://delgadologic.tech","active":true},{"id":2,"title":"LogicFlow Docs","url":"https://delgadologic.tech/logicflow","active":false}]}""",
                                "session.export" => JsonSerializer.Serialize(new
                                {
                                    ok = true,
                                    auth_json = _mockAeonExportedAuthJson
                                }),
                                "session.import" => HandleMockSessionImport(doc.RootElement),
                                "tab.new" or "navigate" => """{"ok":true}""",
                                _ => """{"ok":false,"error":"unknown cmd"}"""
                            };

                            await writer.WriteLineAsync(reply.AsMemory(), ct).ConfigureAwait(false);
                        }
                        catch
                        {
                        }
                    }
                }, CancellationToken.None);
            }
            catch (OperationCanceledException)
            {
                server?.Dispose();
                break;
            }
            catch
            {
                server?.Dispose();
            }
        }
    }

    private string HandleMockSessionImport(JsonElement root)
    {
        _lastAeonImportedAuthJson = root.TryGetProperty("auth_json", out var aj) ? aj.GetString() : null;
        return """{"ok":true}""";
    }

    public async ValueTask DisposeAsync()
    {
        await _mockAeonCts.CancelAsync();
        await _handoffServer.DisposeAsync();
        _cloudVault.Dispose();
        _appDiscovery.Dispose();
        try { await _mockAeonTask; } catch { }
        _mockAeonCts.Dispose();

        try
        {
            if (Directory.Exists(_tempRoot))
                Directory.Delete(_tempRoot, recursive: true);
        }
        catch
        {
        }
    }
}
