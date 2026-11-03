// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH
//go:build !unix

package proxy

import "net"

// idleConnAlive cannot peek without blocking off Unix, so it assumes the
// connection is alive; a closed one then fails the request it carries.
func idleConnAlive(*net.TCPConn) bool {
	return true
}
