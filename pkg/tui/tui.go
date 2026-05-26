package tui

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/libp2p/go-libp2p/core/host"
	"github.com/nicabreon/meshsage/pkg/logger"
	"github.com/nicabreon/meshsage/pkg/network"
	"github.com/nicabreon/meshsage/pkg/storage"
)

var (
	statusMessage string
	statusExpires time.Time
	statusMu      sync.Mutex
)

type logMsg []byte
type chatMsg []byte
type statusUpdateMsg string

type logWriter struct {
	program *tea.Program
}

func (w *logWriter) Write(p []byte) (n int, err error) {
	if w.program != nil {
		w.program.Send(logMsg(p))
	}
	return len(p), nil
}

type chatWriter struct {
	program *tea.Program
}

func (w *chatWriter) Write(p []byte) (n int, err error) {
	if w.program != nil {
		w.program.Send(chatMsg(p))
	}
	return len(p), nil
}

type focusState int

const (
	focusInput focusState = iota
	focusLogs
	focusChats
)

type model struct {
	ctx          context.Context
	host         host.Host
	processCmd   func(string)

	logs         []string
	chats        []string
	statusText   string

	logViewport  viewport.Model
	chatViewport viewport.Model
	input        textinput.Model

	focus        focusState
	width        int
	height       int
}

func initialModel(ctx context.Context, h host.Host, processCmd func(string)) model {
	ti := textinput.New()
	ti.Placeholder = "Type a command or message (e.g. /msg @alias hello)..."
	ti.Focus()
	ti.CharLimit = 500

	vpLog := viewport.New(80, 10)
	vpLog.SetContent("Waiting for system logs...")

	vpChat := viewport.New(80, 15)
	vpChat.SetContent("Welcome to Meshsage Chat!\n")

	return model{
		ctx:          ctx,
		host:         h,
		processCmd:   processCmd,
		input:        ti,
		logViewport:  vpLog,
		chatViewport: vpChat,
		focus:        focusInput,
		statusText:   "Initializing Node Status...",
	}
}

func (m model) Init() tea.Cmd {
	return textinput.Blink
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyCtrlC:
			return m, tea.Quit
		case tea.KeyCtrlD:
			// Dump logs to file
			logText := strings.Join(m.logs, "")
			timestamp := time.Now().Format("20060102-150405")
			filename := fmt.Sprintf("meshsage-logs-%s.txt", timestamp)
			err := os.WriteFile(filename, []byte(logText), 0644)
			if err != nil {
				showStatus(fmt.Sprintf("Failed to dump logs: %v", err))
			} else {
				showStatus(fmt.Sprintf("Logs successfully dumped to %s", filename))
			}
		case tea.KeyEsc:
			// Toggle between input focus and viewport focus
			if m.focus == focusInput {
				m.input.Blur()
				m.focus = focusChats
			} else {
				m.input.Focus()
				m.focus = focusInput
			}
		case tea.KeyTab:
			// Toggle focus between Log View and Chat View when input is not focused
			if m.focus == focusChats {
				m.focus = focusLogs
			} else if m.focus == focusLogs {
				m.focus = focusChats
			}
		case tea.KeyEnter:
			if m.focus == focusInput {
				val := strings.TrimSpace(m.input.Value())
				if val != "" {
					if strings.HasPrefix(val, "/") {
						m.chats = append(m.chats, fmt.Sprintf("\033[33mExecuting command: %s\033[0m\n", val))
					} else {
						m.chats = append(m.chats, fmt.Sprintf("\033[34mYou:\033[0m %s\n", val))
					}
					m.chatViewport.SetContent(strings.Join(m.chats, ""))
					m.chatViewport.GotoBottom()

					go m.processCmd(val)
					m.input.SetValue("")
				}
			}
		}

	case logMsg:
		m.logs = append(m.logs, string(msg))
		m.logViewport.SetContent(strings.Join(m.logs, ""))
		m.logViewport.GotoBottom()

	case chatMsg:
		m.chats = append(m.chats, string(msg))
		m.chatViewport.SetContent(strings.Join(m.chats, ""))
		m.chatViewport.GotoBottom()

	case statusUpdateMsg:
		m.statusText = string(msg)

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height

		overhead := 8
		usableHeight := msg.Height - overhead
		if usableHeight < 4 {
			usableHeight = 4
		}
		logHeight := usableHeight / 3
		if logHeight < 2 {
			logHeight = 2
		}
		chatHeight := usableHeight - logHeight
		if chatHeight < 2 {
			chatHeight = 2
		}

		m.logViewport.Width = msg.Width - 4
		m.logViewport.Height = logHeight

		m.chatViewport.Width = msg.Width - 4
		m.chatViewport.Height = chatHeight

		m.input.Width = msg.Width - 20
	}

	var cmd tea.Cmd
	if m.focus == focusInput {
		m.input, cmd = m.input.Update(msg)
		cmds = append(cmds, cmd)
	} else if m.focus == focusLogs {
		m.logViewport, cmd = m.logViewport.Update(msg)
		cmds = append(cmds, cmd)
	} else if m.focus == focusChats {
		m.chatViewport, cmd = m.chatViewport.Update(msg)
		cmds = append(cmds, cmd)
	}

	return m, tea.Batch(cmds...)
}

func (m model) View() string {
	if m.width == 0 || m.height == 0 {
		return "Initializing UI..."
	}

	// 1. Log View style
	borderLogColor := "220" // Yellow
	logTitle := " 📋 System Log [Ctrl-D to Dump] "
	if m.focus == focusLogs {
		borderLogColor = "82" // Green
		logTitle = " 📋 System Log [Ctrl-D to Dump] (Scrolling Active) "
	}
	logHeaderStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(borderLogColor)).Bold(true)
	logBox := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(borderLogColor)).
		Width(m.width - 2).
		Height(m.logViewport.Height).
		Render(m.logViewport.View())

	// 2. Chat View style
	borderChatColor := "33" // Blue/Cyan
	chatTitle := " 💬 Chat Messages "
	if m.focus == focusChats {
		borderChatColor = "82" // Green
		chatTitle = " 💬 Chat Messages (Scrolling Active) "
	}
	chatHeaderStyle := lipgloss.NewStyle().Foreground(lipgloss.Color(borderChatColor)).Bold(true)
	chatBox := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color(borderChatColor)).
		Width(m.width - 2).
		Height(m.chatViewport.Height).
		Render(m.chatViewport.View())

	// 3. Status Bar style
	statusBar := lipgloss.NewStyle().
		Foreground(lipgloss.Color("82")).
		Background(lipgloss.Color("235")).
		Width(m.width).
		Render(m.statusText)

	// 4. Input Field style
	inputLabel := lipgloss.NewStyle().Foreground(lipgloss.Color("220")).Render("Command/Msg > ")
	inputBox := lipgloss.JoinHorizontal(lipgloss.Center, inputLabel, m.input.View())

	return lipgloss.JoinVertical(
		lipgloss.Left,
		logHeaderStyle.Render(logTitle),
		logBox,
		chatHeaderStyle.Render(chatTitle),
		chatBox,
		statusBar,
		inputBox,
	)
}

func showStatus(msg string, duration ...time.Duration) {
	statusMu.Lock()
	defer statusMu.Unlock()

	dur := 3 * time.Second
	if len(duration) > 0 {
		dur = duration[0]
	}

	statusMessage = msg
	statusExpires = time.Now().Add(dur)
}

// StartTUI initializes and runs the split-pane terminal user interface
func StartTUI(ctx context.Context, h host.Host, processCmd func(string)) {
	m := initialModel(ctx, h, processCmd)
	p := tea.NewProgram(m, tea.WithAltScreen(), tea.WithMouseCellMotion())

	logger.SetOutputTUI(&logWriter{program: p})
	logger.DisplayWriter = &chatWriter{program: p}

	// Status Updater Loop
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				statusMu.Lock()
				expires := statusExpires
				msg := statusMessage
				statusMu.Unlock()

				var statusText string
				if time.Now().Before(expires) {
					statusText = msg
				} else {
					peers := h.Network().Peers()
					role := "Standard Node"
					if network.IsDedicated {
						role = "Dedicated Relay"
					} else if network.IsClientOnly {
						role = "Client Node"
					}

					aliasName, err := storage.FindAliasByPeerID(h.ID().String())
					if err != nil || aliasName == "" {
						aliasName = "None"
					}

					statusText = fmt.Sprintf("ID: %s | Alias: %s | Role: %s | Peers: %d | Esc: Toggle Focus | Ctrl-C: Quit",
						h.ID().String()[:12]+"...", aliasName, role, len(peers))
				}

				p.Send(statusUpdateMsg(statusText))
			}
		}
	}()

	if _, err := p.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "TUI Error: %v\n", err)
	}
}
