// Package config loads the three-layer PAT configuration and returns an
// immutable instance shared by core and gateway. No gateway may read config
// on its own: the authorization gate must have a single source of truth.
package config

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

// Config is the fully merged configuration. Treat it as read-only after
// Load returns.
type Config struct {
	MSF          MSFConfig          `toml:"msf"`
	Model        ModelConfig        `toml:"model"`
	Safety       SafetyConfig       `toml:"safety"`
	Lab          LabConfig          `toml:"lab"`
	Capabilities CapabilitiesConfig `toml:"capabilities"`
	Exec         ExecConfig         `toml:"exec"`
	Permission   PermissionConfig   `toml:"permission"`
	Server       ServerConfig       `toml:"server"`

	// Sources records which files contributed to the final config, for /config.
	Sources []string `toml:"-"`
}

type MSFConfig struct {
	RPCHost string `toml:"rpc_host"`
	RPCPort int    `toml:"rpc_port"`
	Backend string `toml:"backend"` // auto | rpc | rest | cli | mock
	MSFPath string `toml:"msf_path"`
}

type ModelConfig struct {
	Provider          string `toml:"provider"` // openai | fake | anthropic | gemini
	Name              string `toml:"name"`
	APIKeyEnv         string `toml:"api_key_env"`
	BaseURL           string `toml:"base_url"`
	ConsentExternalLLM bool  `toml:"consent_external_llm"`
}

type SafetyConfig struct {
	ConfirmExploit   bool `toml:"confirm_exploit"`
	ConfirmPayload   bool `toml:"confirm_payload"`
	AllowAutoRecon   bool `toml:"allow_auto_recon"`
	RequireEnvAuth   bool `toml:"require_env_auth"`
	DefaultDryRun    bool `toml:"default_dry_run"`
}

type LabConfig struct {
	EnvironmentMode string   `toml:"environment_mode"` // isolated_lab | authorized_test
	ExperimentID    string   `toml:"experiment_id"`
	Scope           []string `toml:"scope"`
	ScopeExtra      []string `toml:"scope_extra"`
	ArtifactDir     string   `toml:"artifact_dir"`
	DBPath          string   `toml:"db_path"`
}

type CapabilitiesConfig struct {
	Execution          bool `toml:"execution"`
	Mutations          bool `toml:"mutations"`
	Batch              bool `toml:"batch"`
	CredentialInjection bool `toml:"credential_injection"`
	CredentialReveal   bool `toml:"credential_reveal"`
	MCP                bool `toml:"mcp"`
}

type ExecConfig struct {
	Allowlist      []string `toml:"allowlist"`
	Denylist       []string `toml:"denylist"`
	Concurrency    int      `toml:"concurrency"`
	TimeoutSeconds int      `toml:"timeout_seconds"`
}

type PermissionRule struct {
	Pattern string `toml:"pattern"`
	Action  string `toml:"action"` // allow | ask | deny
	Note    string `toml:"note"`
}

type PermissionConfig struct {
	Rules []PermissionRule `toml:"rules"`
}

type ServerConfig struct {
	Listen string `toml:"listen"`
}

// Default returns an isolated-lab configuration with a conservative
// read-only posture. Writes require an explicit environment gate.
func Default() *Config {
	return &Config{
		MSF: MSFConfig{
			RPCHost: "127.0.0.1", RPCPort: 55553, Backend: "auto", MSFPath: "msfconsole",
		},
		Model: ModelConfig{
			Provider: "fake", Name: "demo", APIKeyEnv: "PAT_API_KEY",
			BaseURL: "https://api.openai.com/v1", ConsentExternalLLM: false,
		},
		Safety: SafetyConfig{
			ConfirmExploit: true, ConfirmPayload: true, AllowAutoRecon: true,
			RequireEnvAuth: true, DefaultDryRun: true,
		},
		Lab: LabConfig{
			EnvironmentMode: "isolated_lab",
			Scope:           []string{"192.168.56.0/24"},
			ArtifactDir:     ".pat/artifacts",
			DBPath:          ".pat/events.db",
		},
		Capabilities: CapabilitiesConfig{},
		Exec: ExecConfig{
			Allowlist: []string{"nmap", "msfconsole"}, Denylist: []string{"rm", "dd", "mkfs*"},
			Concurrency: 3, TimeoutSeconds: 300,
		},
		Permission: PermissionConfig{Rules: []PermissionRule{
			{Pattern: "module_search(*)", Action: "allow"},
			{Pattern: "session_list(*)", Action: "allow"},
			{Pattern: "get_capabilities(*)", Action: "allow"},
			{Pattern: "nmap_scan(*)", Action: "ask"},
			{Pattern: "module_execute(auxiliary/scanner/*)", Action: "allow"},
			{Pattern: "module_execute(exploit/*)", Action: "ask"},
			{Pattern: "payload_generate(*)", Action: "ask"},
			{Pattern: "console(*)", Action: "deny"},
			{Pattern: "cleanup(*)", Action: "ask"},
			{Pattern: "audit_export(*)", Action: "allow"},
		}},
		Server: ServerConfig{Listen: "127.0.0.1:8088"},
	}
}

// Load merges global -> project -> environment. Later layers override only
// keys that are explicitly present.
func Load(globalPath, projectPath string) (*Config, error) {
	cfg := Default()
	var sources []string
	for _, p := range []string{globalPath, projectPath} {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("stat config %s: %w", p, err)
		}
		if _, err := toml.DecodeFile(p, cfg); err != nil {
			return nil, fmt.Errorf("decode config %s: %w", p, err)
		}
		sources = append(sources, p)
	}
	applyEnv(cfg)
	cfg.Sources = sources
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// LoadDefault uses the conventional paths.
func LoadDefault() (*Config, error) {
	home, _ := os.UserHomeDir()
	global := filepath.Join(home, ".config", "pat", "config.toml")
	return Load(global, filepath.Join(".pat", "config.toml"))
}

func (c *Config) Validate() error {
	if c.Lab.EnvironmentMode != "isolated_lab" && c.Lab.EnvironmentMode != "authorized_test" {
		return fmt.Errorf("lab.environment_mode must be isolated_lab or authorized_test, got %q", c.Lab.EnvironmentMode)
	}
	if c.MSF.Backend != "auto" && c.MSF.Backend != "rpc" && c.MSF.Backend != "rest" &&
		c.MSF.Backend != "cli" && c.MSF.Backend != "mock" {
		return fmt.Errorf("msf.backend must be auto|rpc|rest|cli|mock, got %q", c.MSF.Backend)
	}
	if c.Exec.Concurrency < 1 {
		c.Exec.Concurrency = 3
	}
	if c.Exec.TimeoutSeconds < 1 {
		c.Exec.TimeoutSeconds = 300
	}
	for _, r := range c.Permission.Rules {
		switch r.Action {
		case "allow", "ask", "deny":
		default:
			return fmt.Errorf("invalid permission action %q for %q", r.Action, r.Pattern)
		}
	}
	return nil
}

func applyEnv(c *Config) {
	set := func(k string, dst *string) {
		if v, ok := os.LookupEnv(k); ok && v != "" {
			*dst = v
		}
	}
	set("PAT_LLM_BASE", &c.Model.BaseURL)
	set("PAT_LLM_MODEL", &c.Model.Name)
	set("PAT_EXPERIMENT_ID", &c.Lab.ExperimentID)
	if v, ok := os.LookupEnv("PAT_MSF_URL"); ok && v != "" {
		// PAT_MSF_URL is a full URL; store only host/port, never a URL in a host field.
		if u, err := url.Parse(v); err == nil {
			if h := u.Hostname(); h != "" {
				c.MSF.RPCHost = h
			}
			if p := u.Port(); p != "" {
				if n, err := strconv.Atoi(p); err == nil {
					c.MSF.RPCPort = n
				}
			}
		}
	}
	if v, ok := os.LookupEnv("PAT_SCOPE_EXTRA"); ok && v != "" {
		for _, s := range strings.Split(v, ",") {
			if s = strings.TrimSpace(s); s != "" {
				c.Lab.ScopeExtra = append(c.Lab.ScopeExtra, s)
			}
		}
	}
	// PAT_MSF_PASS / PAT_MSF_USER are read directly from the environment by
	// the MSF gateway at call time. They are never copied into config, events
	// or audit exports.
	if v, ok := os.LookupEnv("PAT_LLM_PROVIDER"); ok && v != "" {
		c.Model.Provider = v
	}
	if v, ok := os.LookupEnv("PAT_CAP_EXECUTION"); ok {
		if b, err := strconv.ParseBool(v); err == nil {
			c.Capabilities.Execution = b
		}
	}
}

// Authorized reports the environment-level authorization gate.
func Authorized() bool { return os.Getenv("PAT_AUTHORIZED") == "1" }
