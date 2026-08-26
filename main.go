// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

// Command transparent-proxy is a low-overhead transparent L4 TCP proxy used to
// inject network faults against internal and external dependencies. Traffic is
// steered into it by an iptables REDIRECT/TPROXY rule; the proxy recovers the
// original destination, optionally matches by TLS SNI, applies a fault, and
// splices the connection through to the real upstream.
//
// It can either be orchestrated (rules installed out of band) or self-manage
// its interception with --intercept-*: in that mode a fail-open supervisor
// guarantees the rules are torn down on every exit path, so a proxy failure
// never leaves the target with rules pointing at a dead port.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/steadybit/transparent-proxy/internal/config"
	"github.com/steadybit/transparent-proxy/internal/fault"
	"github.com/steadybit/transparent-proxy/internal/interception"
	"github.com/steadybit/transparent-proxy/internal/metrics"
	"github.com/steadybit/transparent-proxy/internal/preflight"
	"github.com/steadybit/transparent-proxy/internal/proxy"
	"github.com/steadybit/transparent-proxy/internal/supervisor"
)

func main() {
	var (
		listen      = flag.String("listen", "0.0.0.0:3128", "address to accept redirected connections on")
		rulesPath   = flag.String("config", "", "path to a JSON fault-rules file (optional; empty = pure pass-through)")
		logLevel    = flag.String("log-level", "info", "log level: debug, info, warn, error")
		dialTimeout = flag.Duration("dial-timeout", 10*time.Second, "upstream connection timeout")
		mark        = flag.Uint("mark", uint(interception.DefaultMark), "SO_MARK stamped on upstream sockets for interception loop-protection (0 disables)")
		metricsAddr = flag.String("metrics-addr", "", "address to serve JSON metrics on (empty disables)")
		maxDuration = flag.Duration("max-duration", 0, "deadman: self-terminate and tear down after this long (0 disables)")

		prePorts = flag.String("preflight-ports", "", "comma-separated target ports to refuse-on-conflict against an existing mesh (defaults to --intercept-ports)")

		interceptCIDRs = flag.String("intercept-cidrs", "", "comma-separated destination CIDRs to capture; enables self-managed interception")
		interceptPorts = flag.String("intercept-ports", "", "comma-separated destination ports to capture (required with --intercept-cidrs)")
		excludeCIDRs   = flag.String("exclude-cidrs", "", "comma-separated destinations never to touch (agent/platform)")
		execID         = flag.String("exec-id", "default", "execution id used to name the interception chains")

		revert = flag.Bool("revert", false, "remove the interception rules for the given --exec-id/--intercept-* and exit (out-of-band teardown, idempotent)")

		// Single-rule fault flags — a convenience for orchestrators that inject
		// one fault, avoiding a JSON --config file. Appended to any --config rules.
		faultLatency = flag.Duration("fault-latency", 0, "single fault: latency added before connecting upstream")
		faultAbort   = flag.Float64("fault-abort-probability", 0, "single fault: probability [0,1] to reset the connection")
		faultStatus  = flag.Int("fault-http-status", 0, "single fault: injected HTTP status (L7, cleartext HTTP)")
		faultHosts   = flag.String("fault-hosts", "", "single fault: comma-separated host selectors (SNI/Host)")
		faultCIDRs   = flag.String("fault-cidrs", "", "single fault: comma-separated CIDR selectors")
	)
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: parseLevel(*logLevel)}))
	slog.SetDefault(logger)

	rules, err := loadRules(*rulesPath)
	if err != nil {
		logger.Error("failed to load config", slog.Any("err", err))
		os.Exit(1)
	}
	if fr, ok, ferr := buildFlagRule(*faultLatency, *faultAbort, *faultStatus, *faultHosts, *faultCIDRs); ferr != nil {
		logger.Error("invalid fault flags", slog.Any("err", ferr))
		os.Exit(2)
	} else if ok {
		rules = append(rules, fr)
	}
	if len(rules) > 0 {
		logger.Info("loaded fault rules", slog.Int("count", len(rules)))
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	m := metrics.New()
	srv := &proxy.Server{
		Listen:      *listen,
		Faults:      fault.NewEngine(rules),
		Logger:      logger,
		DialTimeout: *dialTimeout,
		Mark:        uint32(*mark),
		Metrics:     m,
	}

	// The metrics endpoint runs for the whole process lifetime.
	if *metricsAddr != "" {
		serveMetrics(ctx, logger, *metricsAddr, m)
	}

	// Validate the interception filter and whether self-managed mode is wanted.
	// The port is filled in after we bind (below); 0 is fine here because this
	// instance is only used for --revert, where the port is irrelevant.
	interceptor, wantIntercept, err := buildInterceptor(*interceptCIDRs, *interceptPorts, *excludeCIDRs, *execID, uint32(*mark), 0)
	if err != nil {
		logger.Error("invalid interception configuration", slog.Any("err", err))
		os.Exit(2)
	}

	// Out-of-band teardown: remove the rules and exit. An orchestrator calls
	// this (with the same exec-id/filter) to guarantee cleanup even if a prior
	// self-managed process was SIGKILLed and its in-process Guard never ran.
	if *revert {
		if !wantIntercept {
			logger.Error("--revert requires --intercept-cidrs and --intercept-ports")
			os.Exit(2)
		}
		if err := interceptor.Revert(ctx); err != nil {
			logger.Error("revert failed", slog.Any("err", err))
			os.Exit(1)
		}
		logger.Info("interception reverted", slog.String("exec_id", *execID))
		return
	}

	// Preflight: refuse to fight an existing mesh proxy. Ports default to the
	// intercept ports when not given explicitly.
	preflightSpec := *prePorts
	if preflightSpec == "" {
		preflightSpec = *interceptPorts
	}
	if preflightSpec != "" {
		if err := runPreflight(ctx, logger, preflightSpec); err != nil {
			logger.Error("preflight refusal", slog.Any("err", err))
			os.Exit(1)
		}
	}

	if wantIntercept {
		// Bind the proxy port ourselves, then target interception at exactly the
		// bound port — no pre-allocated port another process could steal between
		// allocation and bind. --listen may use :0 for an OS-chosen port.
		ln, lerr := net.Listen("tcp", *listen)
		if lerr != nil {
			logger.Error("failed to bind proxy listener", slog.Any("err", lerr))
			os.Exit(1)
		}
		port := uint16(ln.Addr().(*net.TCPAddr).Port)
		interceptor, _, err = buildInterceptor(*interceptCIDRs, *interceptPorts, *excludeCIDRs, *execID, uint32(*mark), port)
		if err != nil {
			logger.Error("invalid interception configuration", slog.Any("err", err))
			os.Exit(2)
		}
		guard := &supervisor.Guard{Interceptor: interceptor, Logger: logger, MaxDuration: *maxDuration}
		logger.Info("starting with self-managed interception (fail-open)",
			slog.String("exec_id", *execID), slog.Int("proxy_port", int(port)))
		err = guard.Run(ctx, func(ctx context.Context) error { return srv.Serve(ctx, ln) })
	} else {
		runCtx := ctx
		if *maxDuration > 0 {
			var cancel context.CancelFunc
			runCtx, cancel = context.WithTimeout(ctx, *maxDuration)
			defer cancel()
		}
		err = srv.Run(runCtx)
	}

	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		logger.Error("proxy stopped with error", slog.Any("err", err))
		os.Exit(1)
	}
	logger.Info("proxy stopped", slog.Any("metrics", m.Snapshot()))
}

func loadRules(path string) ([]fault.Rule, error) {
	if path == "" {
		return nil, nil
	}
	return config.Load(path)
}

// buildFlagRule assembles a single fault.Rule from the --fault-* flags. ok is
// false when no fault flag is set.
func buildFlagRule(latency time.Duration, abort float64, status int, hosts, cidrs string) (fault.Rule, bool, error) {
	if latency == 0 && abort == 0 && status == 0 {
		return fault.Rule{}, false, nil
	}
	if abort < 0 || abort > 1 {
		return fault.Rule{}, false, fmt.Errorf("fault-abort-probability must be within [0,1], got %v", abort)
	}
	if status != 0 && (status < 100 || status > 599) {
		return fault.Rule{}, false, fmt.Errorf("fault-http-status must be within [100,599], got %d", status)
	}
	r := fault.Rule{Name: "flag-rule", Latency: latency, AbortProbability: abort, HTTPStatus: status}
	for _, h := range strings.Split(hosts, ",") {
		if h = strings.TrimSpace(h); h != "" {
			r.Hosts = append(r.Hosts, h)
		}
	}
	prefixes, err := parseCIDRs(cidrs)
	if err != nil {
		return fault.Rule{}, false, fmt.Errorf("fault-cidrs: %w", err)
	}
	r.CIDRs = prefixes
	return r, true, nil
}

// interceptorAdapter bridges an interception.Config to supervisor.Interceptor.
type interceptorAdapter struct {
	cfg    interception.Config
	runner interception.CommandRunner
}

func (a interceptorAdapter) Apply(ctx context.Context) error  { return a.cfg.Apply(ctx, a.runner) }
func (a interceptorAdapter) Revert(ctx context.Context) error { return a.cfg.Revert(ctx, a.runner) }

// buildInterceptor assembles the interception for the given proxy port. The
// port is discovered by binding the listener first (see main), so interception
// targets the exact port the proxy bound — there is no pre-allocated port that
// another process could steal between allocation and bind. For --revert the
// port is irrelevant (chain names derive from the exec-id) and may be 0.
func buildInterceptor(cidrs, ports, excludes, execID string, mark uint32, proxyPort uint16) (supervisor.Interceptor, bool, error) {
	if cidrs == "" && ports == "" {
		return nil, false, nil
	}
	if cidrs == "" || ports == "" {
		return nil, false, errors.New("--intercept-cidrs and --intercept-ports must be set together")
	}

	include, err := parseCIDRs(cidrs)
	if err != nil {
		return nil, false, fmt.Errorf("intercept-cidrs: %w", err)
	}
	exclude, err := parseCIDRs(excludes)
	if err != nil {
		return nil, false, fmt.Errorf("exclude-cidrs: %w", err)
	}
	tcpPorts, err := parsePorts(ports)
	if err != nil {
		return nil, false, fmt.Errorf("intercept-ports: %w", err)
	}

	cfg := interception.Config{
		ExecutionID: execID,
		ProxyPort:   proxyPort,
		Mark:        mark,
		Filter: interception.Filter{
			Include: include,
			Exclude: exclude,
			Ports:   tcpPorts,
		},
	}
	return interceptorAdapter{cfg: cfg, runner: interception.ExecRunner{}}, true, nil
}

func runPreflight(ctx context.Context, logger *slog.Logger, spec string) error {
	ports, err := parsePorts(spec)
	if err != nil {
		return fmt.Errorf("invalid preflight ports: %w", err)
	}
	res, err := preflight.Detect(ctx, interception.ExecRunner{})
	if err != nil {
		return fmt.Errorf("preflight scan failed; cannot verify the namespace is clear: %w", err)
	}
	if f, conflict := res.Conflict(ports); conflict {
		return errors.New(f.Message())
	}
	logger.Info("preflight clean", slog.Any("backends", res.Backends))
	return nil
}

func serveMetrics(ctx context.Context, logger *slog.Logger, addr string, m *metrics.Metrics) {
	ms := &http.Server{Addr: addr, Handler: m.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = ms.Shutdown(shutCtx)
	}()
	go func() {
		if err := ms.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("metrics server stopped", slog.Any("err", err))
		}
	}()
	logger.Info("serving metrics", slog.String("addr", addr))
}

func parseCIDRs(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, c := range strings.Split(s, ",") {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, fmt.Errorf("invalid cidr %q: %w", c, err)
		}
		out = append(out, p)
	}
	return out, nil
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
