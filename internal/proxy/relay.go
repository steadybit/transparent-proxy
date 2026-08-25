// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package proxy

import (
	"io"
	"net"
	"sync"
)

// relay copies bytes in both directions between two TCP connections until both
// halves are closed. On Linux, io.Copy between two *net.TCPConn uses splice(2),
// so payload bytes move kernel-to-kernel with no userspace copy — this is the
// low-overhead fast path. Each direction is half-closed independently so a
// peer that stops sending doesn't force the other direction shut.
func relay(a, b *net.TCPConn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(a, b)
		_ = a.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(b, a)
		_ = b.CloseWrite()
	}()
	wg.Wait()
}
