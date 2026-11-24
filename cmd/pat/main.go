// Command pat is the single binary: embedded kernel + terminal client.
// Use -serve to expose the same core over REST + SSE.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/pat-toolkit/pat/app"
	"github.com/pat-toolkit/pat/config"
	"github.com/pat-toolkit/pat/server"
	"github.com/pat-toolkit/pat/ui/cli"
)

func main() {
	var (
		oneShot     string
		experiment  string
		globalCfg   string
		projectCfg  string
		serve       bool
		listen      string
		backend     string
		showVersion bool
	)
	flag.StringVar(&oneShot, "c", "", "execute one command and exit (e.g. -c \"扫一下 192.168.56.10 的 445\")")
	flag.StringVar(&experiment, "e", "", "experiment id (default: generated PAT_<timestamp>)")
	flag.StringVar(&globalCfg, "global-config", "", "global config path (default ~/.config/pat/config.toml)")
	flag.StringVar(&projectCfg, "config", "", "project config path (default .pat/config.toml)")
	flag.BoolVar(&serve, "serve", false, "start REST+SSE server instead of the REPL")
	flag.StringVar(&listen, "listen", "", "server listen address (overrides config)")
	flag.StringVar(&backend, "backend", "", "force MSF backend: auto|rpc|rest|cli|mock")
	flag.BoolVar(&showVersion, "version", false, "print version")
	flag.Parse()

	if showVersion {
		fmt.Println("pat v0.1.0 (minimal demo)")
		return
	}
	if globalCfg == "" {
		home, _ := os.UserHomeDir()
		globalCfg = home + "/.config/pat/config.toml"
	}
	if projectCfg == "" {
		projectCfg = ".pat/config.toml"
	}
	cfg, err := config.Load(globalCfg, projectCfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "config error:", err)
		os.Exit(1)
	}
	if backend != "" {
		cfg.MSF.Backend = backend
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, "config error:", err)
		os.Exit(1)
	}
	a, err := app.New(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "init error:", err)
		os.Exit(1)
	}
	defer a.Close()

	ctx := context.Background()
	if err := a.StartSession(ctx, experiment); err != nil {
		fmt.Fprintln(os.Stderr, "session error:", err)
		os.Exit(1)
	}
	s := a.Sessions.Current()
	if serve {
		if listen != "" {
			cfg.Server.Listen = listen
		}
		fmt.Printf("[pat] REST+SSE listening on http://%s (session=%s experiment=%s)\n", cfg.Server.Listen, s.ID, s.ExperimentID)
		if err := server.Serve(ctx, a, cfg.Server.Listen); err != nil {
			fmt.Fprintln(os.Stderr, "server error:", err)
			os.Exit(1)
		}
		return
	}
	if oneShot != "" {
		if err := cli.OneShot(ctx, a, oneShot, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
		return
	}
	if err := cli.Run(ctx, a, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
