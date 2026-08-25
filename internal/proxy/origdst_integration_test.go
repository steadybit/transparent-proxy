// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH
//go:build linux && integration

// These tests require Linux, root, and iptables (nat table). They exercise the
// SO_ORIGINAL_DST recovery path against a real `-j REDIRECT` rule, which cannot
// be unit-tested on a dev machine. Run with:
//
//	go test -tags integration ./internal/proxy/ -run TestOriginalDst -v
//
// (see the Docker/CI harness in the repo for a self-contained way to run it).
package proxy

import (
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"testing"
	"time"
)

func iptables(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("iptables", args...).CombinedOutput(); err != nil {
		t.Fatalf("iptables %v: %v\n%s", args, err, out)
	}
}

func TestOriginalDst_UnderIptablesRedirect(t *testing.T) {
	const origIP = "127.0.0.1"
	const origPort = "5000"

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	proxyPort := fmt.Sprint(ln.Addr().(*net.TCPAddr).Port)

	// Redirect connections destined for 127.0.0.1:5000 to our listener. The
	// kernel stashes the pre-DNAT destination for SO_ORIGINAL_DST to recover.
	match := []string{
		"-p", "tcp", "-d", origIP, "--dport", origPort,
		"-j", "REDIRECT", "--to-ports", proxyPort,
	}
	iptables(t, append([]string{"-t", "nat", "-A", "OUTPUT"}, match...)...)
	defer iptables(t, append([]string{"-t", "nat", "-D", "OUTPUT"}, match...)...)

	type result struct {
		ap  netip.AddrPort
		err error
	}
	done := make(chan result, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			done <- result{err: err}
			return
		}
		defer c.Close()
		ap, err := originalDst(c.(*net.TCPConn))
		done <- result{ap: ap, err: err}
	}()

	// Connecting to the original destination is transparently redirected to the
	// listener above; the connection itself need not complete a protocol.
	conn, err := net.DialTimeout("tcp", origIP+":"+origPort, 2*time.Second)
	if err != nil {
		t.Fatalf("dial redirected destination: %v", err)
	}
	defer conn.Close()

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("originalDst: %v", r.err)
		}
		if got := r.ap.Addr().Unmap().String(); got != origIP {
			t.Fatalf("original dst addr = %s, want %s", got, origIP)
		}
		if got := fmt.Sprint(r.ap.Port()); got != origPort {
			t.Fatalf("original dst port = %s, want %s", got, origPort)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for the redirected connection")
	}
}
