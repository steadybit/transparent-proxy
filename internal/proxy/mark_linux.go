// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH
//go:build linux

package proxy

import "syscall"

// setSocketMark stamps SO_MARK on a socket so the interception rules can RETURN
// (exempt) the proxy's own upstream traffic and avoid a redirect self-loop.
func setSocketMark(fd uintptr, mark uint32) error {
	return syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, int(mark))
}
