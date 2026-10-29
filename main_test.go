// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package main

import (
	"strings"
	"testing"
)

func TestBuildInterceptor_PortScopes(t *testing.T) {
	cases := []struct {
		name, cidrs, ports string
		wantIntercept      bool
		wantErr            bool
		wantInScript       string
		notInScript        string
	}{
		{name: "neither: pure proxy", wantIntercept: false},
		{name: "ports without cidrs", ports: "80", wantErr: true},
		{name: "explicit ports", cidrs: "0.0.0.0/0", ports: "80,443", wantIntercept: true, wantInScript: "--dport 443"},
		{name: "empty ports: rejected", cidrs: "0.0.0.0/0", ports: "", wantErr: true},
		{name: "only separators: rejected", cidrs: "0.0.0.0/0", ports: " , ", wantErr: true},
		{name: "invalid port", cidrs: "0.0.0.0/0", ports: "80,http", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ic, want, err := buildInterceptor(tc.cidrs, tc.ports, "", "exec", 0, 3128, false, nil)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if want != tc.wantIntercept {
				t.Fatalf("wantIntercept = %v, want %v", want, tc.wantIntercept)
			}
			if !want {
				return
			}
			script := strings.Join(ic.(interceptorAdapter).cfg.AddScript(), "\n")
			if tc.wantInScript != "" && !strings.Contains(script, tc.wantInScript) {
				t.Errorf("script missing %q:\n%s", tc.wantInScript, script)
			}
			if tc.notInScript != "" && strings.Contains(script, tc.notInScript) {
				t.Errorf("script must not contain %q:\n%s", tc.notInScript, script)
			}
		})
	}
}
