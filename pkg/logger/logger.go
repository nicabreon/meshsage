package logger

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Global logger instance
var L zerolog.Logger

// DisplayWriter points to the writer where user-facing messages should be written
var DisplayWriter io.Writer = os.Stdout

func init() {
	// Default to Info level
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	
	// Default output to pretty console
	L = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})
}

// SetOutput dynamically updates the logger destination
func SetOutput(w io.Writer) {
	L = log.Output(zerolog.ConsoleWriter{Out: w, TimeFormat: time.RFC3339})
}

// SetOutputTUI redirects logs to the TUI text writer without ANSI color codes
func SetOutputTUI(w io.Writer) {
	L = log.Output(zerolog.ConsoleWriter{Out: w, TimeFormat: time.RFC3339, NoColor: true})
}

// SetDebug toggles between Debug and Info levels
func SetDebug(enabled bool) {
	if enabled {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		L.Debug().Msg("Debug logging ENABLED")
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
}

// IsDebugEnabled returns true if global level is set to Debug
func IsDebugEnabled() bool {
	return zerolog.GlobalLevel() == zerolog.DebugLevel
}

// Displayf formats and writes to DisplayWriter
func Displayf(format string, args ...interface{}) {
	fmt.Fprintf(DisplayWriter, format, args...)
}

// Displayln writes to DisplayWriter with a newline
func Displayln(args ...interface{}) {
	fmt.Fprintln(DisplayWriter, args...)
}

// Shortcut functions for convenience
func Info() *zerolog.Event { return L.Info() }
func Debug() *zerolog.Event { return L.Debug() }
func Warn() *zerolog.Event { return L.Warn() }
func Error() *zerolog.Event { return L.Error() }
func Fatal() *zerolog.Event { return L.Fatal() }

