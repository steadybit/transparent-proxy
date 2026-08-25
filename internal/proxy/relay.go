// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package proxy

import (
	"io"
	"net"
	"sync"
)

// relay copies bytes in both directions between the client and upstream until
// both halves are closed, returning the bytes moved each way. On Linux, io.Copy
// between two *net.TCPConn uses splice(2), so payload bytes move kernel-to-kernel
// with no userspace copy — the low-overhead fast path. Each direction is
// half-closed independently so a peer that stops sending doesn't force the other
// direction shut.
func relay(client, upstream *net.TCPConn) (toUpstream, toClient int64) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		toUpstream, _ = io.Copy(upstream, client)
		_ = upstream.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		toClient, _ = io.Copy(client, upstream)
		_ = client.CloseWrite()
	}()
	wg.Wait()
	return toUpstream, toClient
}
