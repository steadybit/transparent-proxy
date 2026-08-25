// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH
//go:build linux

package proxy

import (
	"errors"
	"net"
	"net/netip"
	"syscall"
	"unsafe"
)

// getsockopt option to read the pre-DNAT destination of a REDIRECTed socket.
// Same numeric value at the IPv4 (SOL_IP) and IPv6 (SOL_IPV6) levels.
const (
	soOriginalDst = 80 // SO_ORIGINAL_DST / IP6T_SO_ORIGINAL_DST
	solIP         = 0  // SOL_IP
	solIPv6       = 41 // SOL_IPV6
)

var errNoOriginalDst = errors.New("could not read SO_ORIGINAL_DST (socket not REDIRECTed?)")

// originalDst returns the pre-redirect destination of a connection that was
// captured by an iptables `-j REDIRECT` (or TPROXY) rule. It reads the
// SO_ORIGINAL_DST socket option that netfilter stashes at accept time.
func originalDst(c *net.TCPConn) (netip.AddrPort, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, err
	}

	var (
		addr    netip.AddrPort
		lookErr error
	)
	ctrlErr := raw.Control(func(fd uintptr) {
		// IPv4 (and IPv4-mapped) sockets answer at SOL_IP; try that first,
		// then fall back to the native IPv6 level.
		if a, ok := readOriginalDst(fd, solIP); ok {
			addr = a
			return
		}
		if a, ok := readOriginalDst(fd, solIPv6); ok {
			addr = a
			return
		}
		lookErr = errNoOriginalDst
	})
	if ctrlErr != nil {
		return netip.AddrPort{}, ctrlErr
	}
	return addr, lookErr
}

func readOriginalDst(fd, level uintptr) (netip.AddrPort, bool) {
	// Large enough for sockaddr_in (16) or sockaddr_in6 (28).
	var buf [28]byte
	size := uint32(len(buf))
	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		fd, level, uintptr(soOriginalDst),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
	)
	if errno != 0 {
		return netip.AddrPort{}, false
	}
	return parseSockaddr(buf[:size])
}

// parseSockaddr decodes a raw sockaddr_in / sockaddr_in6. The family field is
// in host byte order; the port and address are in network byte order.
func parseSockaddr(b []byte) (netip.AddrPort, bool) {
	if len(b) < 2 {
		return netip.AddrPort{}, false
	}
	family := uint16(b[0]) | uint16(b[1])<<8
	switch family {
	case syscall.AF_INET:
		if len(b) < 8 {
			return netip.AddrPort{}, false
		}
		port := uint16(b[2])<<8 | uint16(b[3])
		ip := netip.AddrFrom4([4]byte{b[4], b[5], b[6], b[7]})
		return netip.AddrPortFrom(ip, port), true
	case syscall.AF_INET6:
		if len(b) < 24 {
			return netip.AddrPort{}, false
		}
		port := uint16(b[2])<<8 | uint16(b[3])
		var a [16]byte
		copy(a[:], b[8:24])
		return netip.AddrPortFrom(netip.AddrFrom16(a).Unmap(), port), true
	default:
		return netip.AddrPort{}, false
	}
}
