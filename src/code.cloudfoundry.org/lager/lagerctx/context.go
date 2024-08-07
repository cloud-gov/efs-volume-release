// Package lagerctx provides convenience when using lager with the context
// feature of the standard library.
package lagerctx

import (
	"context"

	"code.cloudfoundry.org/lager/v3"
)

// NewContext returns a derived context containing the logger.
func NewContext(parent context.Context, logger lager.Logger) context.Context {
	return context.WithValue(parent, contextKey{}, logger)
}

// FromContext returns the logger contained in the context, or an inert logger
// that will not log anything.
func FromContext(ctx context.Context) lager.Logger {
	l, ok := ctx.Value(contextKey{}).(lager.Logger)
	if !ok {
		return &discardLogger{}
	}

	return l
}

// WithSession returns a new logger that has, for convenience, had a new
// session created on it.
func WithSession(ctx context.Context, task string, data ...lager.Data) lager.Logger {
	return FromContext(ctx).Session(task, data...)
}

// WithData returns a new logger that has, for convenience, had new data added
// to on it.
func WithData(ctx context.Context, data lager/v3.Data) lager/v3.Logger {
	return FromContext(ctx).WithData(data)
}

// contextKey is used to retrieve the logger from the context.
type contextKey struct{}

// discardLogger is an inert logger.
type discardLogger struct{}

func (*discardLogger) Debug(string, ...lager/v3.Data)                  {}
func (*discardLogger) Info(string, ...lager/v3.Data)                   {}
func (*discardLogger) Error(string, error, ...lager/v3.Data)           {}
func (*discardLogger) Fatal(string, error, ...lager/v3.Data)           {}
func (*discardLogger) RegisterSink(lager/v3.Sink)                      {}
func (*discardLogger) SessionName() string                          { return "" }
func (d *discardLogger) Session(string, ...lager/v3.Data) lager/v3.Logger { return d }
func (d *discardLogger) WithData(lager/v3.Data) lager/v3.Logger           { return d }
