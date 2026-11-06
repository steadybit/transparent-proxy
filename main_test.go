// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// loopbackCIDR is the whole IPv4 loopback range: 127.0.0.1 (localhost) and every
// other 127.x.x.x address, which the kernel delivers inside the network
// namespace without ever leaving it.
const loopbackCIDR = "127.0.0.0/8"

func TestBuildInterceptor_PortScopes(t *testing.T) {
	cases := []struct {
		name, cidrs, ports string
		loopback           bool
		loopbackExcludes   string
		wantIntercept      bool
		wantErr            bool
		wantInScript       string
		notInScript        string
	}{
		{name: "neither: pure proxy", wantIntercept: false},
		{name: "ports without cidrs", ports: "80", wantErr: true},
		{name: "explicit ports", cidrs: "0.0.0.0/0", ports: "80,443", wantIntercept: true, wantInScript: "--dport 443"},
		{name: "empty ports: every port", cidrs: "0.0.0.0/0", ports: "", wantIntercept: true, wantInScript: "-d " + loopbackCIDR + " -j RETURN", notInScript: "--dport"},
		{name: "only separators: rejected", cidrs: "0.0.0.0/0", ports: " , ", wantErr: true},
		{name: "invalid port", cidrs: "0.0.0.0/0", ports: "80,http", wantErr: true},
		{name: "explicit ports: loopback excluded", cidrs: "0.0.0.0/0", ports: "80", wantIntercept: true, wantInScript: "-d " + loopbackCIDR + " -j RETURN"},
		{name: "explicit ports: loopback captured", cidrs: "0.0.0.0/0", ports: "80", loopback: true, wantIntercept: true, notInScript: loopbackCIDR},
		{name: "every port: loopback captured", cidrs: "0.0.0.0/0", loopback: true, wantIntercept: true, notInScript: loopbackCIDR},
		{name: "loopback captured except own ports", cidrs: "0.0.0.0/0", loopback: true, loopbackExcludes: "8085,8081", wantIntercept: true, wantInScript: "-p tcp -d " + loopbackCIDR + " --dport 8081 -j RETURN"},
		{name: "invalid loopback exclude port", cidrs: "0.0.0.0/0", loopback: true, loopbackExcludes: "ext", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ic, want, err := buildInterceptor(tc.cidrs, tc.ports, "", tc.loopback, tc.loopbackExcludes, "exec", 0, 3128, false, nil)
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

func TestServerFirstTimeout(t *testing.T) {
	cases := []struct {
		name      string
		flagValue time.Duration
		explicit  bool
		allPorts  bool
		want      time.Duration
	}{
		{name: "explicit ports, flag unset: off", want: 0},
		{name: "all ports, flag unset: default", allPorts: true, want: defaultServerFirstTimeout},
		{name: "all ports, explicit value wins", flagValue: time.Second, explicit: true, allPorts: true, want: time.Second},
		{name: "all ports, explicitly disabled", flagValue: 0, explicit: true, allPorts: true, want: 0},
		{name: "explicit ports, explicit value", flagValue: 100 * time.Millisecond, explicit: true, want: 100 * time.Millisecond},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := serverFirstTimeout(tc.flagValue, tc.explicit, tc.allPorts); got != tc.want {
				t.Fatalf("serverFirstTimeout = %v, want %v", got, tc.want)
			}
		})
	}
}
func Test_loadUpstreamCAs(t *testing.T) {
	pool, err := loadUpstreamCAs("")
	if pool != nil || err != nil {
		t.Fatalf("empty path = %v, %v; want no pool and no error", pool, err)
	}

	if pool, err := loadUpstreamCAs("testdata/example.com-chain.pem"); pool == nil || err != nil {
		t.Fatalf("PEM bundle = %v, %v; want a pool", pool, err)
	}

	garbage := filepath.Join(t.TempDir(), "garbage.pem")
	if err := os.WriteFile(garbage, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadUpstreamCAs(garbage); err == nil {
		t.Fatal("a file without certificates should be rejected")
	}
}
