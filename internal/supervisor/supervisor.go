// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

// Package supervisor provides the fail-open guarantee for the transparent proxy.
//
// The hazard: a nat REDIRECT rule that points at a dead proxy port blackholes
// every flow it matches. For a reliability tool this is the one unacceptable
// outcome — the proxy failing must never leave the target worse than untouched.
//
// Guard ties the interception rules to the proxy's lifetime and guarantees the
// rules are removed on EVERY exit path: normal return, serve error, context
// cancellation, a panic in serve, or the deadman timer. Teardown is idempotent,
// retried, and time-bounded. (A SIGKILL can still orphan rules; that residual
// is the orchestrator's responsibility via an out-of-band Exited() hook, which
// can call Revert directly.)
package supervisor

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// Interceptor installs and removes the traffic-steering rules.
type Interceptor interface {
	Apply(ctx context.Context) error
	Revert(ctx context.Context) error
}

// Guard runs a serve loop bracketed by guaranteed interception teardown.
type Guard struct {
	Interceptor Interceptor
	Logger      *slog.Logger

	// RevertTimeout bounds each teardown attempt. Default 10s.
	RevertTimeout time.Duration
	// RevertRetries is how many times teardown is attempted. Default 3.
	RevertRetries int
	// MaxDuration, if > 0, is a deadman: the run self-terminates (and tears
	// down) after this long even if nothing else stops it, so a forgotten or
	// wedged proxy heals itself.
	MaxDuration time.Duration

	once sync.Once
}

func (g *Guard) logger() *slog.Logger {
	if g.Logger != nil {
		return g.Logger
	}
	return slog.Default()
}

// Run applies the interception, runs serve, and guarantees teardown.
//
// If Apply fails it rolls back immediately (a partial apply is still torn down)
// and returns the error without ever calling serve. Otherwise serve runs until
// it returns, ctx is cancelled, MaxDuration elapses, or it panics — and Revert
// always runs exactly once afterwards.
func (g *Guard) Run(ctx context.Context, serve func(ctx context.Context) error) (err error) {
	if aerr := g.Interceptor.Apply(ctx); aerr != nil {
		// Roll back any partial state from a failed apply.
		g.teardown(context.WithoutCancel(ctx), "rollback after failed apply")
		return fmt.Errorf("apply interception: %w", aerr)
	}

	// Teardown is guaranteed here: it runs on normal return, on a serve error,
	// and (because the panic below is recovered) on a panic too. Using a
	// cancellation-immune context means teardown still runs when ctx is the
	// thing that ended the run.
	defer g.teardown(context.WithoutCancel(ctx), "run finished")

	runCtx := ctx
	if g.MaxDuration > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(ctx, g.MaxDuration)
		defer cancel()
	}

	func() {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("proxy panicked: %v", r)
				g.logger().Error("recovered panic in serve; tearing down", slog.Any("panic", r))
			}
		}()
		err = serve(runCtx)
	}()
	return err
}

// Teardown removes the interception immediately and idempotently. Safe to call
// directly (e.g. from an orchestrator's Exited() hook) in addition to Run.
func (g *Guard) Teardown(ctx context.Context) {
	g.teardown(ctx, "explicit teardown")
}

func (g *Guard) teardown(ctx context.Context, reason string) {
	g.once.Do(func() {
		timeout := g.RevertTimeout
		if timeout <= 0 {
			timeout = 10 * time.Second
		}
		retries := g.RevertRetries
		if retries < 1 {
			retries = 3
		}

		for attempt := 1; attempt <= retries; attempt++ {
			rctx, cancel := context.WithTimeout(ctx, timeout)
			err := g.Interceptor.Revert(rctx)
			cancel()
			if err == nil {
				g.logger().Info("interception torn down (fail-open)", slog.String("reason", reason))
				return
			}
			g.logger().Error("interception teardown attempt failed",
				slog.Int("attempt", attempt), slog.Int("of", retries), slog.Any("err", err))
		}
		// Nothing more we can do in-process; make it loud so the orchestrator
		// and operator can intervene before the dead-port rules cause harm.
		g.logger().Error("CRITICAL: interception teardown failed after all retries; "+
			"target may have stale rules pointing at a dead proxy",
			slog.String("reason", reason))
	})
}
