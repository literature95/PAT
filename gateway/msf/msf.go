// Package msf implements MSF backends. The CLI backend feeds only
// pre-rendered resource scripts to msfconsole and never concatenates a model-
// generated string into a console command (README §3.4 / §9).
package msf

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/pat-toolkit/pat/config"
)

// Backend is the contract consumed by core/tool (implicit interface).
type Backend interface {
	Name() string
	Search(context.Context, string) ([]string, error)
	Execute(context.Context, string, map[string]string) (string, error)
	Sessions(context.Context) ([]string, error)
	Console(context.Context, string) (string, error)
	Payload(context.Context, string, map[string]string) (string, error)
}

// CLI runs msfconsole with a temporary .rc script.
type CLI struct {
	path    string
	timeout time.Duration
}

func NewCLI(path string, timeout time.Duration) *CLI {
	if path == "" {
		path = "msfconsole"
	}
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	return &CLI{path: path, timeout: timeout}
}

func (c *CLI) Name() string { return "msf-cli" }

func (c *CLI) available() (string, error) {
	p, err := exec.LookPath(c.path)
	if err != nil {
		return "", fmt.Errorf("msfconsole %q not found on PATH: %w", c.path, err)
	}
	return p, nil
}

func (c *CLI) runRC(ctx context.Context, script string) (string, error) {
	bin, err := c.available()
	if err != nil {
		return "", err
	}
	f, err := os.CreateTemp("", "pat-msf-*.rc")
	if err != nil {
		return "", err
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(script + "\nexit-\n"); err != nil {
		f.Close()
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "-q", "-r", f.Name()).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("msfconsole failed: %w", err)
	}
	return string(out), nil
}

var moduleLine = regexp.MustCompile(`(?m)^\s*((?:exploit|auxiliary|post|payload|encoder|nop|evasion)/[^\s]+)\s*`)

func (c *CLI) Search(ctx context.Context, keyword string) ([]string, error) {
	if strings.TrimSpace(keyword) == "" {
		return nil, fmt.Errorf("empty search keyword")
	}
	// Only a sanitized single token reaches the resource script.
	kw := regexp.MustCompile(`[^\w./-]`).ReplaceAllString(keyword, "")
	out, err := c.runRC(ctx, "search "+kw)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var mods []string
	for _, m := range moduleLine.FindAllStringSubmatch(out, -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			mods = append(mods, m[1])
		}
	}
	return mods, nil
}

func (c *CLI) Execute(ctx context.Context, module string, opts map[string]string) (string, error) {
	if !moduleLine.MatchString(module) {
		return "", fmt.Errorf("invalid module name %q", module)
	}
	var b strings.Builder
	b.WriteString("use " + module + "\n")
	for _, k := range sortedKeys(opts) {
		if !regexp.MustCompile(`^[A-Za-z0-9_.-]+$`).MatchString(k) {
			return "", fmt.Errorf("invalid option name %q", k)
		}
		v := regexp.MustCompile(`[\r\n;]`).ReplaceAllString(opts[k], "")
		b.WriteString(fmt.Sprintf("set %s %s\n", k, v))
	}
	b.WriteString("run")
	return c.runRC(ctx, b.String())
}

func (c *CLI) Sessions(ctx context.Context) ([]string, error) {
	out, err := c.runRC(ctx, "sessions -l")
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	var res []string
	for _, l := range lines {
		if strings.Contains(l, "No active sessions") {
			continue
		}
		res = append(res, strings.TrimSpace(l))
	}
	return res, nil
}

// Console accepts only a path to an existing pre-rendered .rc file. Arbitrary
// model-generated command strings are rejected outright.
func (c *CLI) Console(ctx context.Context, command string) (string, error) {
	p := strings.TrimSpace(command)
	if p == "" || strings.ContainsAny(p, "\r\n;") {
		return "", fmt.Errorf("console requires a path to a pre-rendered .rc file")
	}
	info, err := os.Stat(p)
	if err != nil || info.IsDir() || !strings.HasSuffix(strings.ToLower(p), ".rc") {
		return "", fmt.Errorf("console requires an existing .rc file path, got %q", p)
	}
	bin, err := c.available()
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "-q", "-r", p).CombinedOutput()
	return string(out), err
}

func (c *CLI) Payload(ctx context.Context, typ string, opts map[string]string) (string, error) {
	name := regexp.MustCompile(`[^\w/-]`).ReplaceAllString(typ, "")
	if !strings.HasPrefix(name, "payload/") {
		name = "payload/" + name
	}
	var b strings.Builder
	b.WriteString("use " + name + "\n")
	for _, k := range sortedKeys(opts) {
		v := regexp.MustCompile(`[\r\n;]`).ReplaceAllString(opts[k], "")
		b.WriteString(fmt.Sprintf("set %s %s\n", k, v))
	}
	b.WriteString("generate")
	return c.runRC(ctx, b.String())
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}

// Mock is a deterministic in-memory backend for demos and CI.
type Mock struct{}

func (m *Mock) Name() string { return "msf-mock" }
func (m *Mock) Search(_ context.Context, keyword string) ([]string, error) {
	return []string{
		"auxiliary/scanner/portscan/tcp",
		"auxiliary/scanner/smb/smb_version",
		"exploit/windows/smb/ms17_010_eternalblue",
		"payload/windows/x64/meterpreter/reverse_tcp",
	}, nil
}
func (m *Mock) Execute(_ context.Context, module string, opts map[string]string) (string, error) {
	return fmt.Sprintf("[mock] module=%s opts=%v completed with no side effects", module, opts), nil
}
func (m *Mock) Sessions(_ context.Context) ([]string, error) {
	return []string{"No active sessions (mock)"}, nil
}
func (m *Mock) Console(_ context.Context, command string) (string, error) {
	return "[mock] console rc=" + command, nil
}
func (m *Mock) Payload(_ context.Context, typ string, opts map[string]string) (string, error) {
	return fmt.Sprintf("[mock] payload=%s opts=%v (not written to disk)", typ, opts), nil
}

// Select honours config.msf.backend and falls back to mock when msfconsole
// is unavailable. The chosen backend is reported through get_capabilities.
func Select(cfg *config.Config, timeout time.Duration) (Backend, string) {
	switch cfg.MSF.Backend {
	case "mock":
		return &Mock{}, "mock (configured)"
	case "cli":
		if _, err := exec.LookPath(cfg.MSF.MSFPath); err == nil {
			return NewCLI(cfg.MSF.MSFPath, timeout), "cli"
		}
		return &Mock{}, "mock (msfconsole not found)"
	default: // auto
		if _, err := exec.LookPath(cfg.MSF.MSFPath); err == nil {
			return NewCLI(cfg.MSF.MSFPath, timeout), "cli (auto)"
		}
		return &Mock{}, "mock (msfconsole not found)"
	}
}
