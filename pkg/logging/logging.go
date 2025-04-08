package logging

import (
	"io"
	"log/slog"
	"os"
	"strings"
)

func Setup(logLevelStr string, logPath string, defaultWriter io.Writer) {
	var level slog.Level
	switch strings.ToLower(logLevelStr) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	logWriter := defaultWriter
	if logPath != "" {
		logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0640)
		if err != nil {
			// Use a temporary logger to the default writer for this error message
			tempLogger := slog.New(slog.NewTextHandler(defaultWriter, nil))
			tempLogger.Error("Failed to open configured log file, falling back to default writer", "path", logPath, "error", err)
		} else {
			logWriter = logFile
		}
	}

	opts := &slog.HandlerOptions{
		Level:     level,
		AddSource: level <= slog.LevelDebug,
	}
	logger := slog.New(slog.NewTextHandler(logWriter, opts))
	slog.SetDefault(logger)
}
