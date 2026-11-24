package perm

import (
	"strings"
	"testing"

	"github.com/pat-toolkit/pat/config"
	"github.com/pat-toolkit/pat/core/event"
)

func TestCommandChainStripsWrappers(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"nmap -p 445 192.168.56.10", []string{"nmap"}},
		{"sudo -u root proxychains4 -q nmap -sV 192.168.56.10", []string{"sudo", "proxychains4", "nmap"}},
		{"timeout 30 /usr/bin/nmap 192.168.56.10", []string{"timeout", "nmap"}},
		{"env FOO=bar nmap 192.168.56.10", []string{"env", "nmap"}},
		{"nice -n 10 nmap 127.0.0.1", []string{"nice", "nmap"}},
	}
	for _, tc := range cases {
		got, err := CommandChain(tc.in)
		if err != nil {
			t.Fatalf("%q: %v", tc.in, err)
		}
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Fatalf("%q: got %v want %v", tc.in, got, tc.want)
		}
	}
}

func TestCommandChainFailsClosed(t *testing.T) {
	for _, cmd := range []string{"sudo", "timeout", "sudo -u", "echo 'unterminated"} {
		if _, err := CommandChain(cmd); err == nil {
			t.Fatalf("%q should fail closed", cmd)
		}
	}
}

func TestExecPolicyDenyFirstAndEmptyAllowlist(t *testing.T) {
	cfg := config.Default().Exec
	cfg.Allowlist = []string{"nmap", "msfconsole"}
	cfg.Denylist = []string{"rm", "dd", "mkfs*"}
	if _, err := CheckExecPolicy("sudo rm -rf /tmp/x", cfg); err == nil {
		t.Fatal("denylist must apply to wrappers/targets")
	}
	if _, err := CheckExecPolicy("nmap 127.0.0.1", cfg); err != nil {
		t.Fatalf("allowed nmap rejected: %v", err)
	}
	if _, err := CheckExecPolicy("curl http://example.com", cfg); err == nil {
		t.Fatal("not-allowlisted binary should be denied")
	}
	cfg.Allowlist = nil
	if _, err := CheckExecPolicy("nmap 127.0.0.1", cfg); err == nil {
		t.Fatal("empty allowlist must deny everything")
	}
}

func TestScopeClassification(t *testing.T) {
	lab := config.Default().Lab
	lab.Scope = []string{"192.168.56.0/24"}
	s, err := NewScope(lab)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Check([]string{"192.168.56.10:445"}); err != nil {
		t.Fatalf("in-scope host rejected: %v", err)
	}
	if _, err := s.Check([]string{"192.168.56.0/25"}); err != nil {
		t.Fatalf("subnet of scope rejected: %v", err)
	}
	for _, target := range []string{"10.0.0.5", "8.8.8.8", "192.167.56.1", "192.168.57.0/24"} {
		if _, err := s.Check([]string{target}); err == nil {
			t.Fatalf("out-of-scope %q accepted", target)
		}
	}
	warnings, err := s.Check([]string{"host.example.internal"})
	if err != nil || len(warnings) == 0 {
		t.Fatalf("unresolved hostname should be allowed with warning: err=%v warnings=%v", err, warnings)
	}
	lab.EnvironmentMode = "authorized_test"
	s2, _ := NewScope(lab)
	if _, err := s2.Check([]string{"8.8.8.8"}); err == nil {
		t.Fatal("public IP outside scope must still be rejected even in authorized_test")
	}
}

func TestEngineFourLayers(t *testing.T) {
	cfg := config.Default()
	cfg.Capabilities.Execution = true
	cfg.Lab.Scope = []string{"192.168.56.0/24"}
	e, err := NewEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PAT_AUTHORIZED", "0")

	// Layer 1: env gate.
	r := e.Check(CheckRequest{Tool: "nmap_scan", Write: true, Capability: "execution", Targets: []string{"192.168.56.10"}})
	if r.Decision != Deny || r.Layer != "env" {
		t.Fatalf("env gate: %+v", r)
	}
	// Read-only tools pass env gate.
	r = e.Check(CheckRequest{Tool: "module_search", Actor: event.ActorHuman, Sub: "smb"})
	if r.Decision != Allow {
		t.Fatalf("read tool: %+v", r)
	}

	t.Setenv("PAT_AUTHORIZED", "1")
	// Layer 2: capability gate.
	r = e.Check(CheckRequest{Tool: "payload_generate", Write: true, Capability: "mutations", Sub: "windows/meterpreter"})
	if r.Decision != Deny || r.Layer != "capability" {
		t.Fatalf("capability gate: %+v", r)
	}
	// Layer 3: scope.
	r = e.Check(CheckRequest{Tool: "nmap_scan", Write: true, Capability: "execution", Targets: []string{"8.8.8.8"}})
	if r.Decision != Deny || r.Layer != "scope" {
		t.Fatalf("scope gate: %+v", r)
	}
	// Layer 3: exec policy.
	r = e.Check(CheckRequest{Tool: "nmap_scan", Write: true, Capability: "execution",
		Targets: []string{"192.168.56.10"}, Command: "sudo rm -rf /tmp/x"})
	if r.Decision != Deny || r.Layer != "exec" {
		t.Fatalf("exec gate: %+v", r)
	}
	// Layer 4: ask for exploits.
	r = e.Check(CheckRequest{Tool: "module_execute", Write: true, Capability: "execution",
		Sub: "exploit/windows/smb/ms17_010", Targets: []string{"192.168.56.10"}})
	if r.Decision != Ask || r.Layer != "rule" {
		t.Fatalf("ask rule: %+v", r)
	}
	// Default deny.
	r = e.Check(CheckRequest{Tool: "unknown_tool", Write: false})
	if r.Decision != Deny || r.Layer != "default" {
		t.Fatalf("default deny: %+v", r)
	}
}

func TestCallNameAndPattern(t *testing.T) {
	if got := CallName("module_execute", "exploit/windows/smb/ms17_010"); got != "module_execute(exploit/windows/smb/ms17_010)" {
		t.Fatal(got)
	}
	if !matchPattern("module_execute(exploit/*)", CallName("module_execute", "exploit/windows/smb/x")) {
		t.Fatal("glob should match")
	}
	if matchPattern("module_execute(exploit/*)", CallName("module_execute", "auxiliary/scanner/x")) {
		t.Fatal("glob must not match other families")
	}
}
