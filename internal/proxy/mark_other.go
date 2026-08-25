// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH
//go:build !linux

package proxy

import "errors"

// setSocketMark is a no-op stub: SO_MARK exists only on Linux. Setting a mark on
// any other platform is a configuration error rather than a silent success.
func setSocketMark(uintptr, uint32) error {
	return errors.New("SO_MARK (upstream loop protection) is only supported on linux")
}
