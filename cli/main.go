package main

import (
	"context"
	"flag"
	"fmt"
	"goproxy/pkg/proxy"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	os.Exit(run())
}

func run() int {
	configFile := flag.String("config", "config.yaml", "Path to config file")
	versionFlag := flag.Bool("version", false, "Print version and exit")
	checkFlag := flag.Bool("check", false, "Load, validate and compile the config, then exit without binding any listener")
	flag.Parse()

	if flag.NArg() > 0 {
		if flag.Args()[0] == "version" {
			fmt.Println(proxy.Version())
			return 0
		}
		fmt.Fprintf(os.Stderr, "Unexpected arguments: %v\n", flag.Args())
		return 1
	}

	if *versionFlag {
		fmt.Println(proxy.Version())
		return 0
	}

	config, err := proxy.ParseConfigFile(*configFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error parsing config file:", err)
		return 1
	}

	if *checkFlag {
		// compile without binding anything: this is the answer to "is this
		// config going to work", and it must not touch the network or create
		// directories
		if config.LogLevel < proxy.LogLevelWarn {
			// whatever the config says about logging, a check run has to show
			// what it found
			config.LogLevel = proxy.LogLevelWarn
		}
		if _, err := proxy.New(config); err != nil {
			fmt.Fprintln(os.Stderr, "Error in config file:", err)
			return 1
		}
		rules := "rules"
		if len(config.Rules) == 1 {
			rules = "rule"
		}
		fmt.Printf("%s: ok, %d %s\n", *configFile, len(config.Rules), rules)
		return 0
	}

	server, err := proxy.Run(config)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error running proxy:", err)
		return 1
	}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for sig := range signals {
			if sig == syscall.SIGHUP {
				// config reload is not implemented yet; reloading the
				// certificate is what a renewal needs and costs nothing
				if err := server.ReloadCertificates(); err != nil {
					fmt.Fprintln(os.Stderr, "Error reloading certificates:", err)
				}
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), config.ShutdownTimeout())
			err := server.Shutdown(ctx)
			cancel()
			if err != nil {
				fmt.Fprintln(os.Stderr, "Error shutting down proxy:", err)
			}
			return
		}
	}()

	if err := server.Wait(); err != nil {
		fmt.Fprintln(os.Stderr, "Proxy stopped:", err)
		return 1
	}
	return 0
}
