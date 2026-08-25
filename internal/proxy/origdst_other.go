// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH
//go:build !linux

package proxy

import (
	"errors"
	"net"
	"net/netip"
)

// originalDst is only implementable on Linux (it relies on netfilter's
// SO_ORIGINAL_DST). On other platforms the proxy can still run in tests via an
// injected Server.ResolveDst, but transparent interception is unavailable.
func originalDst(*net.TCPConn) (netip.AddrPort, error) {
	return netip.AddrPort{}, errors.New("transparent interception requires Linux (SO_ORIGINAL_DST)")
}
