package perm

import (
	"fmt"
	"net"
	"strings"

	"github.com/pat-toolkit/pat/config"
)

// Scope enforces experiment-manifest targets, not a blanket RFC1918 allowlist.
// Literal IPs/CIDRs outside the manifest are rejected; unresolved hostnames
// are allowed with a warning.
type Scope struct {
	networks []*net.IPNet
	names    map[string]bool
	extra    []string
	mode     string
	enforce  bool
}

func NewScope(cfg config.LabConfig) (*Scope, error) {
	s := &Scope{names: make(map[string]bool), mode: cfg.EnvironmentMode, enforce: true, extra: cfg.ScopeExtra}
	for _, entry := range append(append([]string{}, cfg.Scope...), cfg.ScopeExtra...) {
		entry = strings.ToLower(strings.TrimSpace(entry))
		if entry == "" {
			continue
		}
		if _, network, err := net.ParseCIDR(entry); err == nil {
			s.networks = append(s.networks, network)
			continue
		}
		if ip := net.ParseIP(entry); ip != nil {
			bits := 128
			if ip.To4() != nil {
				bits = 32
			}
			s.networks = append(s.networks, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		s.names[entry] = true
	}
	return s, nil
}

// Check validates every target token. It returns warnings for unresolved
// hostnames and an error for out-of-scope IP/CIDR literals.
func (s *Scope) Check(targets []string) ([]string, error) {
	if !s.enforce {
		return nil, nil
	}
	var warnings []string
	for _, raw := range targets {
		token := normalizeTarget(raw)
		if token == "" {
			continue
		}
		if _, network, err := net.ParseCIDR(token); err == nil {
			if !s.isSubnetOfScope(network) {
				return nil, fmt.Errorf("target CIDR %s is not inside the experiment scope", token)
			}
			continue
		}
		if ip := net.ParseIP(token); ip != nil {
			if s.contains(ip) {
				continue
			}
			if ip.IsGlobalUnicast() && !ip.IsPrivate() && s.mode != "authorized_test" {
				return nil, fmt.Errorf("public target %s is rejected in %s mode; switch to authorized_test with explicit approval", token, s.mode)
			}
			return nil, fmt.Errorf("target %s is not in the experiment scope", token)
		}
		if s.names[token] {
			continue
		}
		if plausibleHostname(token) {
			warnings = append(warnings, fmt.Sprintf("hostname %q is unresolved; allowed with scopeWarning (scope not verified)", token))
			continue
		}
		// Unrecognized tokens are ignored rather than treated as an attack.
		warnings = append(warnings, fmt.Sprintf("target %q was ignored by scope classification", token))
	}
	return warnings, nil
}

func (s *Scope) contains(ip net.IP) bool {
	for _, n := range s.networks {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (s *Scope) isSubnetOfScope(network *net.IPNet) bool {
	for _, allowed := range s.networks {
		ones, bits := allowed.Mask.Size()
		aOnes, aBits := network.Mask.Size()
		if bits != aBits || ones > aOnes {
			continue
		}
		if allowed.Contains(network.IP) {
			return true
		}
	}
	return false
}

func normalizeTarget(raw string) string {
	t := strings.TrimSpace(raw)
	t = strings.Trim(t, "[]")
	if h, _, err := net.SplitHostPort(t); err == nil {
		return strings.ToLower(h)
	}
	// Bare host:port without brackets (e.g. 192.168.56.10:445).
	if i := strings.LastIndex(t, ":"); i > 0 && !strings.Contains(t[i+1:], ":") {
		if _, err := fmt.Sscanf(t[i+1:], "%d", new(int)); err == nil {
			return strings.ToLower(t[:i])
		}
	}
	return strings.ToLower(t)
}

func plausibleHostname(s string) bool {
	if len(s) < 2 || len(s) > 253 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '-' && r != '.' {
			return false
		}
	}
	return strings.Contains(s, ".") || strings.Contains(s, "-")
}

// Summary is exposed by /scope and get_capabilities.
func (s *Scope) Summary() map[string]any {
	return map[string]any{
		"enforced": s.enforce,
		"mode":     s.mode,
		"extra":    s.extra,
	}
}
