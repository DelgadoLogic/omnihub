# DelgadoLogic OmniHub

**OmniHub** is the unified desktop command center for **Delgado Creative Enterprises LLC d/b/a DelgadoLogic**, orchestrating **LogicFlow v1.0** and **Aeon Browser v0.22.0** across updates, cloud-synced `.lfc` snapshots, cross-app IPC handoffs, shared GGUF local AI models, and unified cryptographic licensing.

---

## Architecture Overview

| Project | Target Framework | Responsibility |
| :--- | :--- | :--- |
| `src/OmniHub.Core` | `net8.0-windows` | Core runtime services: `AppDiscoveryAndManagerService`, `UnifiedLicenseHubService`, `CloudVaultSyncService`, `CrossAppHandoffPipeService` (`\\.\pipe\delgadologic-omnihub` + `\\.\pipe\aeon-agent` + `lf.exe`), `SharedModelVaultService`, and `QuickLauncherSearchService`. |
| `src/OmniHub.App` | `net8.0-windows` (`WPF`) | Sleek Obsidian + Cyan (`#00E5FF`) / Electric Purple (`#9333EA`) desktop dashboard (`WPF-UI 4.3.0`), Dark/Light theme switcher, pure Win32 `Shell_NotifyIconW` system tray integration, and global `Alt+Space` Raycast-style Quick Launcher (`QuickLauncherWindow`). |
| `tests/OmniHub.Tests` | `net8.0-windows` (`xUnit`) | Empirical unit & integration test suite covering Ed25519 manifest verification, Zstd `.lfc` snapshot pack/restore, Named Pipe JSON-RPC round-trips, NTFS `CreateHardLinkW` GGUF deduplication, RSA-2048/Ed25519 licensing, and `FACTS.md` compliance. |

---

## Key Capabilities

1. **Apps & Sovereign Updates (`AppDiscoveryAndManagerService`)**
   - Discovers installed versions, SHA-256 binary digests, and running state of **LogicFlow** and **Aeon Browser**.
   - Verifies `stable` and `beta` update channels from `https://api.delgadologic.tech/v1/update/{product}/{channel}` via canonical sorted-JSON **Ed25519** signatures and fail-closed **SHA-256** verification before staging or launching installers.
2. **DelgadoLogic Cloud & Cross-App Handoff (`CloudVaultSyncService` & `CrossAppHandoffPipeService`)**
   - Watches `%USERPROFILE%\DelgadoLogic Cloud` (`Dropzone`, `Sessions`, `Clips`, `Archives`, hidden `.snapshots`) with debounced content-addressed **HyperStore `.lfc`** Zstandard snapshots (`LfcWriter` / `LfcReader`).
   - Exposes an async JSON-RPC 2.0 Named Pipe server on `\\.\pipe\delgadologic-omnihub` (`omnihub.ping`, `omnihub.status`, `handoff.file`, `handoff.clip`, `handoff.session`) and bridges `\\.\pipe\aeon-agent` (`AeonPipeClient`) + `lf.exe --json` (`LogicFlowCliBridge`) with Windows DPAPI protection for exported Playwright `auth.json` sessions.
3. **Shared Local AI Model Vault (`SharedModelVaultService`)**
   - Manages `%ProgramData%\DelgadoLogic\Models` (with non-elevated `%LOCALAPPDATA%\DelgadoLogic\Models` fallback) for `gemma-4-E2B-it-Q4_K_M.gguf`, `gemma-4-E4B-it-Q4_K_M.gguf`, and `bge-small-en-v1.5-q8_0.gguf`, deduplicating identical weights across LogicFlow and Aeon via atomic Win32 NTFS hard links (`CreateHardLinkW`).
4. **Unified Cryptographic Licensing (`UnifiedLicenseHubService`)**
   - Validates offline **Ed25519** and **RSA-2048** tokens across `%ProgramData%\DelgadoLogic\license.lic`, `%ProgramData%\DelgadoLogic\license_token.json`, and `%APPDATA%\DelgadoLogic\license.lic` for `Free`, `Community`, `Pro` (3 devices), and `Team 10-Pack` (10 devices).
5. **Privacy & Compliance (`OmniPulse.ConsentStore`)**
   - Defaults strictly to `ConsentLevel.None` (**OFF by default**). Uses rotatable 128-bit random **pseudonymous** `installId` tokens (never linked to license `HWID`).
   - Backed by DelgadoLogic's **60-day no-questions-asked money-back guarantee**. Minimum user age: **16+**.

---

## Build & Test

```powershell
dotnet build .\OmniHub.sln -c Release
dotnet test .\OmniHub.sln -c Release --no-build
```

---

## Legal & Contact

- **Publisher**: `Delgado Creative Enterprises LLC d/b/a DelgadoLogic` (District of Columbia LLC)
- **Address**: `6218 Georgia Avenue NW, Ste 1-698, Washington, DC 20011, USA`
- **Support**: `support@delgadologic.tech` (Monday–Friday, 9:00 AM – 5:00 PM EST)
