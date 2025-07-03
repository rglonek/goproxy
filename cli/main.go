package main

import (
	"flag"
	"fmt"
	"goproxy/pkg/proxy"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	version := "goproxy version 0.1.0"
	configFile := flag.String("config", "config.yaml", "Path to config file")
	versionFlag := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if flag.NArg() > 0 {
		if flag.Args()[0] == "version" {
			fmt.Println(version)
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "Unexpected arguments: %v\n", flag.Args())
		os.Exit(1)
	}

	if *versionFlag {
		fmt.Println(version)
		os.Exit(0)
	}

	config, err := proxy.ParseConfigFile(*configFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error parsing config file:", err)
		os.Exit(1)
	}

	p, err := proxy.Run(config)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error running proxy:", err)
		os.Exit(1)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		err := p.Shutdown(60 * time.Second)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error shutting down proxy:", err)
		}
	}()

	err = p.Wait()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error waiting for proxy:", err)
		os.Exit(1)
	}
}
