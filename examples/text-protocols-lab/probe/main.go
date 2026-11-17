// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Steadybit GmbH

// probe is the lab's stopwatch. It prints one line of key=value pairs for
// run.sh to check:
//
//	probe tcp -addr redis.test:6379 -send 'PING\r\n' -expect PONG
//	    connects, sends -send (Go escapes allowed) in one write, and reads
//	    until -expect arrives: ms=12 ok=1 got="+PONG\r\n"
//	probe exec -- redis-cli -h redis.test PING
//	    runs a real client and times it, with its last line of output:
//	    ms=15 exit=0 out="PONG"
//	probe lines -listen :7000
//	    a server for line-based protocols: answers "OK <line>\n" to each line,
//	    so a client's first line is answered as soon as it arrives.
package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fail(fmt.Errorf("usage: probe tcp|exec|lines ..."))
	}
	switch os.Args[1] {
	case "tcp":
		tcp(os.Args[2:])
	case "exec":
		run(os.Args[2:])
	case "lines":
		lines(os.Args[2:])
	default:
		fail(fmt.Errorf("unknown command %q", os.Args[1]))
	}
}

func tcp(args []string) {
	fs := flag.NewFlagSet("tcp", flag.ExitOnError)
	addr := fs.String("addr", "", "host:port")
	send := fs.String("send", "", "bytes to send in one write, with Go escapes (\\r\\n, \\x00)")
	expect := fs.String("expect", "", "read until this arrives")
	timeout := fs.Duration("timeout", 10*time.Second, "give up after")
	_ = fs.Parse(args)
	payload, err := strconv.Unquote(`"` + strings.ReplaceAll(*send, `"`, `\"`) + `"`)
	if err != nil {
		fail(fmt.Errorf("-send: %w", err))
	}

	start := time.Now()
	conn, err := net.DialTimeout("tcp", *addr, *timeout)
	if err != nil {
		report(start, "ok=0", "err="+quote(err.Error()))
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(start.Add(*timeout))
	if _, err := conn.Write([]byte(payload)); err != nil {
		report(start, "ok=0", "err="+quote(err.Error()))
		return
	}
	var got []byte
	buf := make([]byte, 4096)
	for !bytes.Contains(got, []byte(*expect)) {
		n, err := conn.Read(buf)
		got = append(got, buf[:n]...)
		if err != nil {
			report(start, "ok=0", "got="+quote(string(got)), "err="+quote(err.Error()))
			return
		}
	}
	report(start, "ok=1", "got="+quote(string(got)))
}

func run(args []string) {
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}
	if len(args) == 0 {
		fail(fmt.Errorf("exec needs a command"))
	}
	start := time.Now()
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	code := 0
	if err != nil {
		code = 1
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		}
	}
	// the last line: a client's result or error comes after its warnings
	outLines := strings.Split(strings.TrimSpace(string(out)), "\n")
	report(start, fmt.Sprintf("exit=%d", code), "out="+quote(outLines[len(outLines)-1]))
}

func lines(args []string) {
	fs := flag.NewFlagSet("lines", flag.ExitOnError)
	listen := fs.String("listen", ":7000", "address to listen on")
	_ = fs.Parse(args)
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		fail(err)
	}
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go func() {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(30 * time.Second))
			r := bufio.NewReader(c)
			for {
				line, err := r.ReadString('\n')
				if err != nil {
					return
				}
				fmt.Fprintf(c, "OK %s\n", strings.TrimRight(line, "\r\n"))
			}
		}()
	}
}

func report(start time.Time, fields ...string) {
	fmt.Printf("ms=%d %s\n", time.Since(start).Milliseconds(), strings.Join(fields, " "))
}

// quote keeps a value on one field: no spaces, escapes visible.
func quote(s string) string {
	if len(s) > 60 {
		s = s[:60] + "..."
	}
	return strings.ReplaceAll(strconv.Quote(s), " ", "_")
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "probe:", err)
	os.Exit(2)
}
