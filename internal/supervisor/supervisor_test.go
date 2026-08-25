// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package supervisor

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeInterceptor struct {
	applyCalls      int
	revertCalls     int
	applyErr        error
	revertFailFirst int // fail this many Revert attempts before succeeding
}

func (f *fakeInterceptor) Apply(context.Context) error {
	f.applyCalls++
	return f.applyErr
}

func (f *fakeInterceptor) Revert(context.Context) error {
	f.revertCalls++
	if f.revertCalls <= f.revertFailFirst {
		return errors.New("revert failed")
	}
	return nil
}

func TestGuard_TearsDownOnNormalReturn(t *testing.T) {
	fi := &fakeInterceptor{}
	g := &Guard{Interceptor: fi}
	served := false
	err := g.Run(context.Background(), func(context.Context) error {
		served = true
		return nil
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !served {
		t.Fatal("serve was not called")
	}
	if fi.applyCalls != 1 || fi.revertCalls != 1 {
		t.Fatalf("apply=%d revert=%d, want 1/1", fi.applyCalls, fi.revertCalls)
	}
}

func TestGuard_TearsDownOnServeError(t *testing.T) {
	fi := &fakeInterceptor{}
	g := &Guard{Interceptor: fi}
	want := errors.New("serve boom")
	err := g.Run(context.Background(), func(context.Context) error { return want })
	if !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
	if fi.revertCalls != 1 {
		t.Fatalf("revert called %d times, want 1", fi.revertCalls)
	}
}

func TestGuard_TearsDownOnPanic(t *testing.T) {
	fi := &fakeInterceptor{}
	g := &Guard{Interceptor: fi}
	err := g.Run(context.Background(), func(context.Context) error {
		panic("serve exploded")
	})
	if err == nil {
		t.Fatal("expected an error from a panicking serve, got nil")
	}
	if fi.revertCalls != 1 {
		t.Fatalf("teardown must run on panic: revert called %d times, want 1", fi.revertCalls)
	}
}

func TestGuard_RollbackOnApplyFailure(t *testing.T) {
	fi := &fakeInterceptor{applyErr: errors.New("apply boom")}
	g := &Guard{Interceptor: fi}
	served := false
	err := g.Run(context.Background(), func(context.Context) error {
		served = true
		return nil
	})
	if err == nil {
		t.Fatal("expected apply failure to be returned")
	}
	if served {
		t.Fatal("serve must not run when apply fails")
	}
	if fi.revertCalls != 1 {
		t.Fatalf("failed apply must still roll back: revert called %d times, want 1", fi.revertCalls)
	}
}

func TestGuard_Deadman(t *testing.T) {
	fi := &fakeInterceptor{}
	g := &Guard{Interceptor: fi, MaxDuration: 100 * time.Millisecond}
	start := time.Now()
	// serve blocks until its context is cancelled (by the deadman).
	err := g.Run(context.Background(), func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	})
	if elapsed := time.Since(start); elapsed < 90*time.Millisecond {
		t.Fatalf("deadman fired too early after %v", elapsed)
	}
	if err == nil {
		t.Fatal("expected the deadman-cancelled serve to report an error")
	}
	if fi.revertCalls != 1 {
		t.Fatalf("deadman must tear down: revert called %d times, want 1", fi.revertCalls)
	}
}

func TestGuard_RevertRetries(t *testing.T) {
	fi := &fakeInterceptor{revertFailFirst: 2}
	g := &Guard{Interceptor: fi, RevertRetries: 3, RevertTimeout: time.Second}
	if err := g.Run(context.Background(), func(context.Context) error { return nil }); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if fi.revertCalls != 3 {
		t.Fatalf("expected 3 revert attempts (2 fail, 1 succeed), got %d", fi.revertCalls)
	}
}

func TestGuard_TeardownIdempotent(t *testing.T) {
	fi := &fakeInterceptor{}
	g := &Guard{Interceptor: fi}
	if err := g.Run(context.Background(), func(context.Context) error { return nil }); err != nil {
		t.Fatalf("Run: %v", err)
	}
	// An out-of-band teardown (e.g. an orchestrator Exited hook) must not
	// double-revert.
	g.Teardown(context.Background())
	if fi.revertCalls != 1 {
		t.Fatalf("teardown must be idempotent: revert called %d times, want 1", fi.revertCalls)
	}
}
