// Package agent defines the three roles. A role is prompt + tool set +
// permission tier; deny means the tool is not even in the role's context.
package agent

type Role struct {
	Name   string
	Prompt string
	Tools  map[string]string // tool -> allow|ask|deny
}

var Roles = map[string]Role{
	"recon": {
		Name:   "recon",
		Prompt: "你是一名只读侦察助手。只能使用只读工具；不得执行利用、载荷或清理。",
		Tools: map[string]string{
			"module_search": "allow", "session_list": "allow", "get_capabilities": "allow",
			"audit_export": "allow", "module_execute": "deny", "console": "deny",
			"payload_generate": "deny", "cleanup": "deny", "verdict_record": "deny",
			"nmap_scan": "deny",
		},
	},
	"operator": {
		Name:   "operator",
		Prompt: "你是一名授权测试操作员。写操作需人工确认；目标必须属于实验清单。",
		Tools: map[string]string{
			"module_search": "allow", "session_list": "allow", "get_capabilities": "allow",
			"audit_export": "allow", "module_execute": "ask", "console": "ask",
			"payload_generate": "ask", "cleanup": "ask", "verdict_record": "ask",
			"nmap_scan": "ask",
		},
	},
	"cleanup": {
		Name:   "cleanup",
		Prompt: "你只负责收尾清理与残留核验，不执行侦察或利用。",
		Tools: map[string]string{
			"session_list": "allow", "get_capabilities": "allow", "audit_export": "allow",
			"cleanup": "allow", "module_search": "deny", "module_execute": "deny",
			"console": "deny", "payload_generate": "deny", "verdict_record": "deny",
			"nmap_scan": "deny",
		},
	},
}

func Get(name string) (Role, bool) {
	r, ok := Roles[name]
	return r, ok
}

// VisibleTools returns the tool names a role may see (deny removes them).
func (r Role) VisibleTools(enabled []string) []string {
	out := make([]string, 0, len(enabled))
	for _, name := range enabled {
		if r.Tools[name] != "deny" {
			out = append(out, name)
		}
	}
	return out
}

// Allows reports whether the role permits a tool call.
func (r Role) Allows(name string) bool {
	level, ok := r.Tools[name]
	return ok && level != "deny"
}
