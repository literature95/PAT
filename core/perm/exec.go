// Package perm implements the four permission layers: environment gate,
// capability gate, scope enforcement and allow/deny/ask rules. It also owns
// the single exec-chain abstraction shared by policy checks and gateways.
package perm

import (
	"fmt"
	"path"
	"path/filepath"
	"strings"

	"github.com/pat-toolkit/pat/config"
)

// wrapperSpec describes how many tokens a wrapper consumes before the real
// binary appears. Ambiguous wrappers (taskset, chrt) are deliberately absent:
// failing closed is better than guessing.
type wrapperSpec struct {
	shortVal        string // short options that consume a following value
	longVal         []string
	skipPositionals int
	assignments     bool
}

var execWrappers = map[string]wrapperSpec{
	"sudo":        {shortVal: "ugCDhprtUT", longVal: []string{"user", "group", "chroot", "with-env"}},
	"doas":        {longVal: []string{"user"}},
	"proxychains4": {shortVal: "f", longVal: []string{"config"}},
	"proxychains":  {shortVal: "f", longVal: []string{"config"}},
	"env":          {assignments: true, longVal: []string{"unset", "chdir"}},
	"nice":         {skipPositionals: 1},
	"timeout":      {shortVal: "sk", skipPositionals: 1},
	"stdbuf":       {},
	"ionice":       {},
	"setsid":       {},
	"nohup":        {},
	"time":         {},
}

// splitCommand is a small shell-like tokenizer: it honours single and double
// quotes and backslash escapes, and rejects an unterminated quote (fail closed).
func splitCommand(s string) ([]string, error) {
	var out []string
	var cur strings.Builder
	var quote rune
	escaped := false
	hasToken := false
	for _, r := range s {
		switch {
		case escaped:
			cur.WriteRune(r)
			escaped = false
			hasToken = true
		case r == '\\':
			escaped = true
			hasToken = true
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote = r
			hasToken = true
		case r == ' ' || r == '\t' || r == '\n':
			if hasToken {
				out = append(out, cur.String())
				cur.Reset()
				hasToken = false
			}
		default:
			cur.WriteRune(r)
			hasToken = true
		}
	}
	if escaped || quote != 0 {
		return nil, fmt.Errorf("malformed command: unterminated quote or escape")
	}
	if hasToken {
		out = append(out, cur.String())
	}
	return out, nil
}

// CommandChain returns the basenames of every binary a command would run,
// peeling wrappers such as sudo/env/timeout/proxychains4. A dangling wrapper
// is an error: the command must not be allowed through on a guess.
func CommandChain(command string) ([]string, error) {
	tokens, err := splitCommand(command)
	if err != nil {
		return nil, err
	}
	if len(tokens) == 0 {
		return nil, fmt.Errorf("empty command")
	}
	chain := make([]string, 0, 3)
	for len(tokens) > 0 {
		name := filepath.Base(tokens[0])
		chain = append(chain, name)
		spec, ok := execWrappers[name]
		if !ok {
			break
		}
		tokens, err = consumeWrapper(spec, tokens[1:])
		if err != nil {
			return nil, err
		}
		if len(tokens) == 0 {
			return nil, fmt.Errorf("dangling wrapper %q with no target binary", name)
		}
	}
	return chain, nil
}

func consumeWrapper(spec wrapperSpec, rest []string) ([]string, error) {
	i := 0
	positionals := spec.skipPositionals
	advance := func(n int) error {
		if i+n > len(rest) {
			return fmt.Errorf("wrapper option is missing its value")
		}
		i += n
		return nil
	}
	for i < len(rest) {
		t := rest[i]
		if t == "--" {
			return rest[i+1:], nil
		}
		switch {
		case strings.HasPrefix(t, "--"):
			key := strings.SplitN(strings.TrimPrefix(t, "--"), "=", 2)[0]
			if contains(spec.longVal, key) && !strings.Contains(t, "=") {
				if err := advance(2); err != nil {
					return nil, err
				}
			} else {
				_ = advance(1)
			}
		case strings.HasPrefix(t, "-") && len(t) > 1:
			takesValue := false
			for _, r := range t[1:] {
				if strings.ContainsRune(spec.shortVal, r) {
					takesValue = true
				}
			}
			if takesValue && len(t) == 2 {
				if err := advance(2); err != nil {
					return nil, err
				}
			} else {
				_ = advance(1)
			}
		case spec.assignments && strings.Contains(t, "="):
			_ = advance(1)
		case positionals > 0:
			positionals--
			_ = advance(1)
		default:
			return rest[i:], nil
		}
	}
	if positionals > 0 {
		return nil, fmt.Errorf("wrapper is missing its positional argument")
	}
	return rest[i:], nil
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// MatchesAny is case-sensitive glob matching, shared by policy and gateways.
func MatchesAny(name string, patterns []string) bool {
	for _, p := range patterns {
		if ok, err := path.Match(p, name); err == nil && ok {
			return true
		}
	}
	return false
}

// CheckExecPolicy applies deny-first matching to every binary in the chain,
// then requires the final binary to match a non-empty allowlist.
func CheckExecPolicy(command string, cfg config.ExecConfig) (string, error) {
	chain, err := CommandChain(command)
	if err != nil {
		return "", err
	}
	for _, name := range chain {
		if MatchesAny(name, cfg.Denylist) {
			return "", fmt.Errorf("binary %q is denylisted", name)
		}
	}
	if len(cfg.Allowlist) == 0 {
		return "", fmt.Errorf("exec allowlist is empty; all execution is denied")
	}
	target := chain[len(chain)-1]
	if !MatchesAny(target, cfg.Allowlist) {
		return "", fmt.Errorf("binary %q is not in the exec allowlist", target)
	}
	return target, nil
}
