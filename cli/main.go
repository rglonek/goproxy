package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"goproxy/pkg/config"
	"goproxy/pkg/proxy"
)

const usage = `goproxy - a small reverse proxy

usage:
  goproxy -config <file>              serve
  goproxy -config <file> -check       load, validate and compile, then exit
  goproxy -config <file> explain <url> [method]
                                      say which rule would handle a request
  goproxy -version                    print version information

`

func main() {
	os.Exit(run())
}

func run() int {
	configFile := flag.String("config", "config.yaml", "Path to config file")
	versionFlag := flag.Bool("version", false, "Print version and exit")
	checkFlag := flag.Bool("check", false, "Load, validate and compile the config, then exit without binding any listener")
	flag.Usage = func() {
		fmt.Fprint(os.Stderr, usage)
		flag.PrintDefaults()
	}
	flag.Parse()

	if *versionFlag {
		fmt.Println(proxy.Version())
		return 0
	}
	args := flag.Args()
	if len(args) > 0 && args[0] == "version" {
		fmt.Println(proxy.Version())
		return 0
	}

	cfg, err := config.ParseFile(*configFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		if errors.Is(err, config.ErrLegacyConfig) {
			fmt.Fprintln(os.Stderr, "\nSee docs/MIGRATION.md for how each v0.x key maps onto the v2 schema.")
		}
		return 1
	}

	switch {
	case len(args) > 0 && args[0] == "explain":
		return explain(cfg, args[1:])
	case len(args) > 0:
		fmt.Fprintf(os.Stderr, "unexpected arguments: %v\n", args)
		return 1
	case *checkFlag:
		return check(cfg, *configFile)
	}
	return serve(cfg)
}

// check compiles the config without binding anything, creating anything or
// contacting anything.
func check(cfg *config.Config, path string) int {
	server, err := proxy.New(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		return 1
	}
	defer server.Routes().Close()
	for _, warning := range cfg.Unreachable() {
		fmt.Fprintln(os.Stderr, "warning:", warning)
	}
	rules := "rules"
	if len(cfg.Rules) == 1 {
		rules = "rule"
	}
	fmt.Printf("%s: ok, %d %s\n", path, len(cfg.Rules), rules)
	return 0
}

// explain answers "why is my rule not matching", which is the question a
// rules-in-order proxy generates most.
func explain(cfg *config.Config, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: goproxy -config <file> explain <url> [method]")
		return 1
	}
	target, err := url.Parse(args[0])
	if err != nil || target.Host == "" {
		fmt.Fprintf(os.Stderr, "explain: %q is not an absolute URL\n", args[0])
		return 1
	}
	method := http.MethodGet
	if len(args) > 1 {
		method = strings.ToUpper(args[1])
	}
	server, err := proxy.New(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		return 1
	}
	defer server.Routes().Close()

	path := target.Path
	if path == "" {
		path = "/"
	}
	fmt.Printf("%s %s\n", method, target)
	matched := false
	for _, decision := range server.Routes().Explain(target.Host, path, method) {
		verdict := "SKIP "
		if decision.Matched {
			verdict = "MATCH"
			matched = true
		}
		fmt.Printf("  %s %-20s %s\n", verdict, decision.Rule, decision.Reason)
		if decision.Matched {
			fmt.Printf("        %s\n", decision.Action)
		}
	}
	if !matched {
		fmt.Println("  no rule matched: this request would get a 404")
	}
	return 0
}

func serve(cfg *config.Config) int {
	server, err := proxy.Run(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "start:", err)
		return 1
	}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for received := range signals {
			if received == syscall.SIGHUP {
				// reload the config from the file it was loaded from; a config
				// that does not compile is rejected and the old one keeps
				// serving
				if err := server.ReloadFile(); err != nil {
					server.Logger().Error("config reload rejected", "error", err)
				}
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), cfg.Defaults.Timeouts.Shutdown.Or(config.DefaultShutdownTimeout))
			err := server.Shutdown(ctx)
			cancel()
			if err != nil {
				fmt.Fprintln(os.Stderr, "shutdown:", err)
			}
			return
		}
	}()

	if err := server.Wait(); err != nil {
		fmt.Fprintln(os.Stderr, "stopped:", err)
		return 1
	}
	return 0
}
