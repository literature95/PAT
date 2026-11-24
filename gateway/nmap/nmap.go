// Package nmap implements the embedded nmap CLI backend and a mock fallback.
package nmap

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/pat-toolkit/pat/config"
	"github.com/pat-toolkit/pat/core/perm"
)

type Runner interface {
	Name() string
	Scan(ctx context.Context, target, ports string) (string, error)
}

type CLI struct {
	path    string
	timeout time.Duration
	execCfg config.ExecConfig
}

func NewCLI(cfg *config.Config) *CLI {
	timeout := time.Duration(cfg.Exec.TimeoutSeconds) * time.Second
	return &CLI{path: "nmap", timeout: timeout, execCfg: cfg.Exec}
}

func (c *CLI) Name() string { return "nmap-cli" }

func (c *CLI) Scan(ctx context.Context, target, ports string) (string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", fmt.Errorf("empty scan target")
	}
	args := []string{}
	if p := strings.TrimSpace(ports); p != "" {
		args = append(args, "-p", p)
	}
	args = append(args, target)
	// The exact same wrapper/allow-deny guard is applied before spawning.
	command := "nmap " + strings.Join(args, " ")
	if _, err := perm.CheckExecPolicy(command, c.execCfg); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, c.path, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("nmap failed: %w", err)
	}
	return string(out), nil
}

type Mock struct{}

func (m *Mock) Name() string { return "nmap-mock" }
func (m *Mock) Scan(_ context.Context, target, ports string) (string, error) {
	return fmt.Sprintf("[mock nmap] target=%s ports=%s\nHost is up (mock).\nPORT   STATE SERVICE\n445/tcp open  microsoft-ds (mock)", target, ports), nil
}

func Select(cfg *config.Config) Runner {
	if cfg.MSF.Backend == "mock" {
		return &Mock{}
	}
	if _, err := exec.LookPath("nmap"); err == nil {
		return NewCLI(cfg)
	}
	return &Mock{}
}
