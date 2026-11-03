// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH
//go:build unix

package proxy

import (
	"net"
	"syscall"
)

// idleConnAlive reports whether an idle connection can still carry a request:
// nothing is waiting to be read from it — neither the peer's close (EOF), a
// reset, nor unexpected data. It peeks without blocking and without consuming
// anything, so it is safe to call before every reuse.
func idleConnAlive(c *net.TCPConn) bool {
	rc, err := c.SyscallConn()
	if err != nil {
		return false
	}
	alive := false
	buf := make([]byte, 1)
	err = rc.Read(func(fd uintptr) bool {
		_, _, rerr := syscall.Recvfrom(int(fd), buf, syscall.MSG_PEEK|syscall.MSG_DONTWAIT)
		alive = rerr == syscall.EAGAIN || rerr == syscall.EWOULDBLOCK
		return true // never wait for the socket to become readable
	})
	return err == nil && alive
}
