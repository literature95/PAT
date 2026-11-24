package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeCfg(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadThreeLayerMerge(t *testing.T) {
	dir := t.TempDir()
	global := writeCfg(t, dir, "global.toml", `
[lab]
environment_mode = "authorized_test"
scope = ["10.0.0.0/8"]
[capabilities]
execution = true
`)
	project := writeCfg(t, dir, "project.toml", `
[lab]
scope = ["192.168.56.0/24"]
[capabilities]
mutations = true
`)
	t.Setenv("PAT_EXPERIMENT_ID", "PAT_env_override")
	cfg, err := Load(global, project)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Lab.EnvironmentMode != "authorized_test" {
		t.Fatalf("global value lost: %q", cfg.Lab.EnvironmentMode)
	}
	if got := cfg.Lab.Scope; len(got) != 1 || got[0] != "192.168.56.0/24" {
		t.Fatalf("project layer did not override scope: %v", got)
	}
	if !cfg.Capabilities.Execution || !cfg.Capabilities.Mutations {
		t.Fatalf("capabilities from different layers were not merged: %+v", cfg.Capabilities)
	}
	if cfg.Lab.ExperimentID != "PAT_env_override" {
		t.Fatalf("env layer did not override: %q", cfg.Lab.ExperimentID)
	}
	if len(cfg.Sources) != 2 {
		t.Fatalf("sources: %v", cfg.Sources)
	}
}

func TestLoadMissingFilesUsesDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "none.toml"), "")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Safety.RequireEnvAuth != true || cfg.Safety.DefaultDryRun != true {
		t.Fatalf("safe defaults missing: %+v", cfg.Safety)
	}
	if cfg.Capabilities.Execution || cfg.Capabilities.Mutations {
		t.Fatal("dangerous capabilities must default to off")
	}
}

func TestValidateRejectsBadValues(t *testing.T) {
	c := Default()
	c.MSF.Backend = "bogus"
	if err := c.Validate(); err == nil {
		t.Fatal("expected backend validation error")
	}
	c = Default()
	c.Permission.Rules = []PermissionRule{{Pattern: "*", Action: "maybe"}}
	if err := c.Validate(); err == nil {
		t.Fatal("expected rule validation error")
	}
}

func TestAuthorizedGate(t *testing.T) {
	t.Setenv("PAT_AUTHORIZED", "1")
	if !Authorized() {
		t.Fatal("expected authorized")
	}
	t.Setenv("PAT_AUTHORIZED", "0")
	if Authorized() {
		t.Fatal("expected unauthorized")
	}
}
