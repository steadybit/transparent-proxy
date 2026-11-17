// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

// preconnect is the lab's workload: it opens a TLS connection ahead of time, the
// way a warmed-up pool or a browser preconnect does, leaves it idle, and only
// then sends a request on it. While idle it watches the connection, so it can
// tell when, and whether, the other side closed it.
//
// It prints one line of key=value pairs for run.sh to check:
//
//	result=200 closed_after=- retried=0 err=-
//
// result is the final status code, or 000 when no response came; closed_after
// is how long after the handshake the peer closed the idle connection, or -.
package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/net/http2"
)

func main() {
	var (
		rawURL = flag.String("url", "https://upstream.test/", "the URL to request")
		caFile = flag.String("cacert", "", "PEM CA certificates to trust (default: the system roots)")
		proto  = flag.String("proto", "h1", "h1: HTTP/1.1; h2: HTTP/2, preface sent at connect; h2-lazy: HTTP/2, preface only sent with the request")
		idle   = flag.Duration("idle", 15*time.Second, "how long the connection stays idle before the request")
		warm   = flag.Bool("warm", false, "send one request right after connecting, before idling (keep-alive reuse rather than a preconnect)")
		retry  = flag.Bool("retry", false, "when the request fails on the idle connection, retry it once on a new one, as most pools do for idempotent requests")
		tls12  = flag.Bool("tls12", false, "cap the client at TLS 1.2, where a rejected certificate fails the handshake itself")
	)
	flag.Parse()

	u, err := url.Parse(*rawURL)
	if err != nil {
		fail(err)
	}
	cfg := &tls.Config{ServerName: u.Hostname()}
	if *caFile != "" {
		pem, err := os.ReadFile(*caFile)
		if err != nil {
			fail(err)
		}
		cfg.RootCAs = x509.NewCertPool()
		cfg.RootCAs.AppendCertsFromPEM(pem)
	}
	if *tls12 {
		cfg.MaxVersion = tls.VersionTLS12
	}
	switch *proto {
	case "h1":
		cfg.NextProtos = []string{"http/1.1"}
	case "h2", "h2-lazy":
		cfg.NextProtos = []string{"h2"}
	default:
		fail(fmt.Errorf("unknown -proto %q", *proto))
	}
	addr := net.JoinHostPort(u.Hostname(), portOr(u.Port(), "443"))

	c := &client{url: u, addr: addr, cfg: cfg, proto: *proto}
	status, closedAfter, err := c.once(*idle, *warm)
	retried := 0
	if err != nil && *retry {
		retried = 1
		status, _, err = c.once(0, false)
	}
	fmt.Printf("result=%s closed_after=%s retried=%d err=%s\n", status, closedAfter, retried, errText(err))
}

type client struct {
	url   *url.URL
	addr  string
	cfg   *tls.Config
	proto string
}

// once connects, optionally sends a warm-up request, idles, and sends the
// request. It returns the last status ("000" when none), how long after the
// handshake the peer closed the idle connection ("-" when it did not), and the
// error that ended the attempt.
func (c *client) once(idle time.Duration, warm bool) (status, closedAfter string, err error) {
	status, closedAfter = "000", "-"
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", c.addr, c.cfg)
	if err != nil {
		return status, closedAfter, fmt.Errorf("handshake: %w", err)
	}
	defer conn.Close()

	switch c.proto {
	case "h1":
		br := bufio.NewReader(conn)
		if warm {
			if status, err = c.h1(conn, br); err != nil {
				return status, closedAfter, err
			}
		}
		pending, closed, werr := watch(conn, idle)
		if closed > 0 {
			closedAfter = fmt.Sprintf("%.1fs", closed.Seconds())
		}
		// A closed connection is still used, as a pooled client that did not
		// notice would: the request then fails the way that client sees it.
		_ = werr
		br = bufio.NewReader(io.MultiReader(bytes.NewReader(pending), br))
		status, err = c.h1(conn, br)
		return status, closedAfter, err

	default: // h2, h2-lazy
		var rc net.Conn = conn
		if c.proto == "h2-lazy" {
			// Only the TLS handshake ahead of time: the preface goes out with the
			// request. Whatever the server sent meanwhile (its SETTINGS) is replayed.
			pending, closed, _ := watch(conn, idle)
			if closed > 0 {
				closedAfter = fmt.Sprintf("%.1fs", closed.Seconds())
			}
			rc = &replayConn{Conn: conn, r: io.MultiReader(bytes.NewReader(pending), conn)}
		}
		cc, err := (&http2.Transport{}).NewClientConn(rc)
		if err != nil {
			return status, closedAfter, err
		}
		if warm {
			if status, err = c.h2(cc); err != nil {
				return status, closedAfter, err
			}
		}
		if c.proto == "h2" {
			start := time.Now()
			for time.Since(start) < idle {
				if cc.State().Closed && closedAfter == "-" {
					closedAfter = fmt.Sprintf("%.1fs", time.Since(start).Seconds())
				}
				time.Sleep(100 * time.Millisecond)
			}
		}
		status, err = c.h2(cc)
		return status, closedAfter, err
	}
}

func (c *client) h1(conn net.Conn, br *bufio.Reader) (string, error) {
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetDeadline(time.Time{})
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: preconnect-lab\r\n\r\n", c.url.RequestURI(), c.url.Host)
	if _, err := io.WriteString(conn, req); err != nil {
		return "000", err
	}
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return "000", err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return fmt.Sprint(resp.StatusCode), nil
}

func (c *client) h2(cc *http2.ClientConn) (string, error) {
	req, _ := http.NewRequest(http.MethodGet, c.url.String(), nil)
	req.Header.Set("User-Agent", "preconnect-lab")
	resp, err := cc.RoundTrip(req)
	if err != nil {
		return "000", err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return fmt.Sprint(resp.StatusCode), nil
}

// watch reads from the idle connection for up to d, keeping whatever arrives,
// and reports how long until the peer closed it (0 when it stayed open).
func watch(conn net.Conn, d time.Duration) (pending []byte, closedAfter time.Duration, err error) {
	start := time.Now()
	_ = conn.SetReadDeadline(start.Add(d))
	defer conn.SetReadDeadline(time.Time{})
	buf := make([]byte, 4096)
	for {
		n, err := conn.Read(buf)
		pending = append(pending, buf[:n]...)
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return pending, 0, nil
			}
			return pending, time.Since(start), err
		}
	}
}

type replayConn struct {
	net.Conn
	r io.Reader
}

func (c *replayConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func portOr(p, def string) string {
	if p == "" {
		return def
	}
	return p
}

func errText(err error) string {
	if err == nil {
		return "-"
	}
	return strings.ReplaceAll(err.Error(), " ", "_")
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "preconnect:", err)
	os.Exit(2)
}
