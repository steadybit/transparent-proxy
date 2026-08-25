// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH
//go:build !linux

package proxy

// setSocketMark is a no-op on non-Linux platforms. SO_MARK only matters when the
// proxy runs behind real iptables interception, which is Linux-only; treating it
// as an error here would break the default configuration (Mark defaults non-zero
// for loop protection) for local development and tests on macOS/Windows.
func setSocketMark(uintptr, uint32) error {
	return nil
}
