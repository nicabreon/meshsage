# Implementation Plan: Split-Pane Terminal User Interface (TUI)

Implement a Terminal User Interface (TUI) for Meshsage to provide a cleaner separation between chat messages and system/protocol logs, while displaying real-time status and retaining interactive command entry.

## User Review Required

> [!NOTE]
> The TUI will be optional. By default, Meshsage will run in standard CLI mode (perfect for scripts, file inputs, and backward compatibility). Users can start the TUI mode by passing the `-tui` CLI flag: `./meshsage -tui`.

## Proposed Changes

### Component 1: `pkg/logger`
Update the logging library to support dynamic output redirection and provide a separate stream for user-facing console/chat output.

#### [MODIFY] [logger.go](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage/pkg/logger/logger.go)
- Introduce `DisplayWriter io.Writer` (defaults to `os.Stdout`).
- Implement `Displayf(format string, args ...interface{})` and `Displayln(args ...interface{})` wrappers that print to `DisplayWriter`.
- Make it easy to change `L`'s target writer during runtime so we can stream logging records directly to the TUI system logs panel.

---

### Component 2: Protocol Log Conversion (`pkg/protocol/` & `pkg/storage/`)
Convert direct `fmt.Printf` statements to either system logs (using `logger.Info` or `logger.Debug`) or user-facing chat output (using `logger.Displayf`/`logger.Displayln`).

#### [MODIFY] [messaging.go](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage/pkg/protocol/messaging.go)
- Convert user-facing prints (chat receipts, file notification info, success reports) to use `logger.Displayf`.
- Convert protocol prints (X3DH handshakes, session details) to use `logger.Debug()` / `logger.Info()`.

#### [MODIFY] [group.go](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage/pkg/protocol/group.go)
- Convert group chat messages to `logger.Displayf`.
- Convert cryptographic rotations and handshake steps (`[GROUP E2EE]`, `[Group Ratchet]`) to `logger.Debug()`.

#### [MODIFY] [replication.go](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage/pkg/protocol/replication.go)
- Convert all `[Replication]` and `[Cluster]` prints to `logger.Info()` or `logger.Error()`.

#### [MODIFY] [alias.go](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage/pkg/protocol/alias.go)
- Convert all `[Alias DHT]` prints to `logger.Info()` / `logger.Debug()`.

#### [MODIFY] [gc.go](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage/pkg/storage/gc.go)
- Convert all `[GC]` output to `logger.Info()`.

---

### Component 3: Terminal UI Engine (`pkg/tui/`)
Create a new package that manages layout, screen drawing, input processing, and logging redirection.

#### [NEW] [tui.go](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage/pkg/tui/tui.go)
- Build a layout with `tview.Flex` or `tview.Grid`:
  - **System Log Panel** (`tview.TextView` with custom formatting, border title `📋 System Log [D: Dump]`).
  - **Chat Panel** (`tview.TextView` with border title `💬 Chat Messages`).
  - **Status Bar** (`tview.TextView` with border title `📊 Node Status`).
  - **Input Panel** (`tview.InputField` labeled `Command/Msg > `).
- Intercept keys:
  - Intercept key `d`/`D` to grab plain text from the System Log Panel, write it to a local file (`meshsage-logs-YYYYMMDD-HHMMSS.txt`), and display a toast/status notification.
- Feed user inputs from the input bar into `protocol.ProcessCommand`.
- Periodically update the status bar with peer count, current alias, E2EE status, and role.
- Provide a thread-safe `io.Writer` implementation to update panels without race conditions.

---

### Component 4: App Entrypoint (`cmd/node/`)

#### [MODIFY] [main.go](file:///Users/nicabreon/Documents/Distributed-Messaging-Platform/meshsage/cmd/node/main.go)
- Add `-tui` flag.
- If `-tui` is enabled:
  - Wire up `logger.L` to write to the TUI log panel writer.
  - Wire up `logger.DisplayWriter` to write to the TUI chat panel writer.
  - Start the TUI application in a goroutine and update status.
  - Skip starting the standard terminal stdin prompt (`StartChatPrompt`).
- If `-tui` is disabled, proceed with normal non-TUI launch.

---

## Verification Plan

### Automated Tests
- Run `go test ./pkg/protocol/...` to ensure refactored display output doesn't break any protocol unit tests.
- Compile: `go build -o meshsage ./cmd/node`

### Manual Verification
- Run `./meshsage -tui` on multiple terminals/machines.
- Verify split layout layout.
- Send messages and run commands (`/msg`, `/register`, `/join`, etc.) in TUI.
- Press `d` / `D` in TUI and verify a log file is written with the complete logging history.
