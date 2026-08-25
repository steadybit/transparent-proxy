// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

// Command transparent-proxy is a low-overhead transparent L4 TCP proxy used to
// inject network faults against internal and external dependencies. Traffic is
// steered into it by an out-of-band iptables REDIRECT/TPROXY rule; the proxy
// recovers the original destination, optionally matches by TLS SNI, applies a
// fault, and splices the connection through to the real upstream.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/steadybit/transparent-proxy/internal/config"
	"github.com/steadybit/transparent-proxy/internal/fault"
	"github.com/steadybit/transparent-proxy/internal/interception"
	"github.com/steadybit/transparent-proxy/internal/preflight"
	"github.com/steadybit/transparent-proxy/internal/proxy"
)

func main() {
	var (
		listen      = flag.String("listen", "0.0.0.0:3128", "address to accept redirected connections on")
		rulesPath   = flag.String("config", "", "path to a JSON fault-rules file (optional; empty = pure pass-through)")
		logLevel    = flag.String("log-level", "info", "log level: debug, info, warn, error")
		dialTimeout = flag.Duration("dial-timeout", 10*time.Second, "upstream connection timeout")
		mark        = flag.Uint("mark", uint(interception.DefaultMark), "SO_MARK stamped on upstream sockets for interception loop-protection (0 disables)")
		prePorts    = flag.String("preflight-ports", "", "comma-separated target ports; if set, refuse to start when an existing transparent proxy (mesh) already captures any of them")
	)
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: parseLevel(*logLevel)}))
	slog.SetDefault(logger)

	var rules []fault.Rule
	if *rulesPath != "" {
		var err error
		rules, err = config.Load(*rulesPath)
		if err != nil {
			logger.Error("failed to load config", slog.Any("err", err))
			os.Exit(1)
		}
		logger.Info("loaded fault rules", slog.Int("count", len(rules)))
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if *prePorts != "" {
		ports, err := parsePorts(*prePorts)
		if err != nil {
			logger.Error("invalid --preflight-ports", slog.Any("err", err))
			os.Exit(2)
		}
		res, err := preflight.Detect(ctx, interception.ExecRunner{})
		if err != nil {
			logger.Error("preflight scan failed; cannot verify the namespace is clear", slog.Any("err", err))
			os.Exit(1)
		}
		if f, conflict := res.Conflict(ports); conflict {
			logger.Error("preflight refusal", slog.String("reason", f.Message()))
			os.Exit(1)
		}
		logger.Info("preflight clean", slog.Any("backends", res.Backends))
	}

	srv := &proxy.Server{
		Listen:      *listen,
		Faults:      fault.NewEngine(rules),
		Logger:      logger,
		DialTimeout: *dialTimeout,
		Mark:        uint32(*mark),
	}

	if err := srv.Run(ctx); err != nil {
		logger.Error("proxy stopped with error", slog.Any("err", err))
		os.Exit(1)
	}
	logger.Info("proxy stopped")
}

func parsePorts(s string) ([]uint16, error) {
	var out []uint16
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q: %w", p, err)
		}
		out = append(out, uint16(n))
	}
	if len(out) == 0 {
		return nil, errors.New("no ports provided")
	}
	return out, nil
}

func parseLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
