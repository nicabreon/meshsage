package logger

import (
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Global logger instance
var L zerolog.Logger

func init() {
	// Default to Info level
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	
	// Default output to pretty console
	L = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})
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

// Shortcut functions for convenience
func Info() *zerolog.Event { return L.Info() }
func Debug() *zerolog.Event { return L.Debug() }
func Warn() *zerolog.Event { return L.Warn() }
func Error() *zerolog.Event { return L.Error() }
func Fatal() *zerolog.Event { return L.Fatal() }
