package cmdutil

import (
	"os"

	"golang.org/x/exp/slog"
)

func NewLogger(service string) *slog.Logger {
	env := os.Getenv("ENV")
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	child := logger.With(slog.Group("service_info", slog.String("env", env), slog.String("service", service)))
	return child
}
