package app

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/pat-toolkit/pat/config"
	"github.com/pat-toolkit/pat/core/agent"
	"github.com/pat-toolkit/pat/core/event"
	"github.com/pat-toolkit/pat/core/provider"
	"github.com/pat-toolkit/pat/core/util"
)

// Command handles the "/" command mode. It returns text to render.
func (a *App) Command(ctx context.Context, line string) (string, error) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return "", nil
	}
	cmd := strings.TrimPrefix(fields[0], "/")
	args := fields[1:]
	c := a.Context(ctx, event.ActorHuman)

	switch cmd {
	case "help", "h", "?":
		return helpText(), nil
	case "capabilities":
		res, err := a.Executor.Run(c, "get_capabilities", nil, "")
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("%s\nbackend=%s role=%s\nregistered=%s\ngated=%s",
			res.Output, a.BackendInfo, a.Role.Name,
			strings.Join(a.Registry.Names(), ", "), gatedNames(a)), nil
	case "scope":
		s := a.Perm.Scope()
		b, _ := json.MarshalIndent(s.Summary(), "", "  ")
		return fmt.Sprintf("scope targets (实验清单):\n  %s\n", strings.Join(a.Config.Lab.Scope, ", ")) +
			fmt.Sprintf("scope extra: %s\n%s\n", strings.Join(a.Config.Lab.ScopeExtra, ", "), string(b)), nil
	case "search":
		if len(args) == 0 {
			return "", fmt.Errorf("用法：/search <keyword>")
		}
		res, err := a.Executor.Run(c, "module_search", map[string]string{"keyword": strings.Join(args, " ")}, "")
		if err != nil {
			return "", err
		}
		return res.Output, nil
	case "sessions", "jobs":
		res, err := a.Executor.Run(c, "session_list", nil, "")
		if err != nil {
			return "", err
		}
		return res.Output, nil
	case "use":
		if len(args) == 0 {
			return "", fmt.Errorf("用法：/use <module>")
		}
		a.CurrentModule = args[0]
		return fmt.Sprintf("已选择模块：%s（用 /set 设置参数，/plan 预览）", a.CurrentModule), nil
	case "set":
		if len(args) < 2 {
			return "", fmt.Errorf("用法：/set <opt> <val>")
		}
		a.CurrentArgs[args[0]] = strings.Join(args[1:], " ")
		return fmt.Sprintf("%s = %s", args[0], a.CurrentArgs[args[0]]), nil
	case "show":
		if len(args) == 0 || args[0] != "options" {
			return "用法：/show options", nil
		}
		return showOptions(a), nil
	case "plan":
		return a.plan(ctx, args)
	case "run":
		id := ""
		if len(args) > 0 {
			id = args[0]
		}
		if a.LastPlan == nil && a.CurrentModule != "" {
			if _, err := a.plan(ctx, nil); err != nil {
				return "", err
			}
		}
		return a.RunPlan(ctx, id, event.ActorHuman)
	case "approve":
		if len(args) == 0 {
			return "", fmt.Errorf("用法：/approve <requestId> [y|n]")
		}
		approve := len(args) < 2 || strings.EqualFold(args[1], "y") || strings.EqualFold(args[1], "yes")
		if err := a.Approvals.Resolve(ctx, args[0], approve, event.ActorHuman); err != nil {
			return "", err
		}
		state := "denied"
		if approve {
			state = "approved"
		}
		return fmt.Sprintf("%s: %s（再执行 /run %s）", args[0], state, a.lastTool()), nil
	case "audit":
		format := "csv"
		path := ""
		if len(args) > 0 {
			format = args[0]
		}
		if len(args) > 1 {
			path = args[1]
		}
		res, err := a.Executor.Run(c, "audit_export", map[string]string{"format": format, "path": path}, "")
		if err != nil {
			return "", err
		}
		return res.Output, nil
	case "cleanup":
		res, err := a.Executor.Run(c, "cleanup", nil, "")
		if err != nil {
			return "", err
		}
		return res.Output, nil
	case "payload":
		if len(args) == 0 {
			return "", fmt.Errorf("用法：/payload <type>")
		}
		res, err := a.Executor.Plan(c, "payload_generate", map[string]string{"type": args[0], "LHOST": a.CurrentArgs["LHOST"], "LPORT": a.CurrentArgs["LPORT"]})
		if err != nil {
			return "", err
		}
		a.LastPlan = &PendingPlan{Tool: "payload_generate", Args: map[string]string{"type": args[0], "LHOST": a.CurrentArgs["LHOST"], "LPORT": a.CurrentArgs["LPORT"]}, Preview: res.Preview}
		run, err := a.Executor.Run(c, "payload_generate", a.LastPlan.Args, "")
		if err != nil {
			return "", err
		}
		return res.Preview + "\n" + run.Preview, nil
	case "verdict":
		if len(args) < 1 {
			return "", fmt.Errorf("用法：/verdict <confirmed|false_positive|unable> [executionId]")
		}
		execID := ""
		if len(args) > 1 {
			execID = args[1]
		}
		res, err := a.Executor.Run(c, "verdict_record", map[string]string{
			"verdict": args[0], "execution_id": execID, "note": "recorded via /verdict",
		}, "")
		if err != nil {
			return "", err
		}
		return res.Output, nil
	case "config":
		return configText(a), nil
	case "events":
		n := 20
		if len(args) > 0 {
			if _, err := fmt.Sscanf(args[0], "%d", &n); err != nil {
				return "", fmt.Errorf("用法：/events [n]")
			}
		}
		return eventText(a, n), nil
	case "role":
		if len(args) == 0 {
			return "可用角色：recon / operator / cleanup；当前：" + a.Role.Name, nil
		}
		r, ok := agent.Get(args[0])
		if !ok {
			return "", fmt.Errorf("未知角色 %q", args[0])
		}
		a.Role = r
		return "已切换角色：" + r.Name, nil
	case "model":
		if len(args) == 0 {
			return "当前 provider：" + a.Provider.Name(), nil
		}
		a.Config.Model.Provider = args[0]
		pr, err := provider.New(a.Config)
		if err != nil {
			a.Config.Model.Provider = "fake"
			return "", err
		}
		a.Provider = pr
		return "已切换 provider：" + pr.Name(), nil
	case "clear":
		a.Messages = nil
		a.LastPlan = nil
		a.CurrentArgs = map[string]string{}
		return "上下文已清空", nil
	default:
		return "", fmt.Errorf("未知命令 %q；用 /help 查看帮助", cmd)
	}
}

func (a *App) plan(ctx context.Context, args []string) (string, error) {
	c := a.Context(ctx, event.ActorHuman)
	name := ""
	var planArgs map[string]string
	if len(args) > 0 {
		name = args[0]
		planArgs = map[string]string{}
		for _, kv := range args[1:] {
			parts := strings.SplitN(kv, "=", 2)
			if len(parts) == 2 {
				planArgs[parts[0]] = parts[1]
			}
		}
	} else if a.CurrentModule != "" {
		name = "module_execute"
		planArgs = make(map[string]string, len(a.CurrentArgs)+1)
		for k, v := range a.CurrentArgs {
			planArgs[k] = v
		}
		planArgs["module"] = a.CurrentModule
	} else if a.LastPlan != nil {
		name = a.LastPlan.Tool
		planArgs = a.LastPlan.Args
	} else {
		return "", fmt.Errorf("没有可规划的模块；先用 /use <module> 或给出工具名")
	}
	res, err := a.Executor.Plan(c, name, planArgs)
	if err != nil {
		return "", err
	}
	a.LastPlan = &PendingPlan{Tool: name, Args: planArgs, Preview: res.Preview}
	t, _ := a.Registry.PlanSpec(name)
	var preview strings.Builder
	preview.WriteString(res.Preview)
	if t != nil {
		if targets := t.Targets(planArgs); len(targets) > 0 {
			warnings, err := a.Perm.Scope().Check(targets)
			if err != nil {
				return preview.String() + "\n✗ 作用域校验失败：" + err.Error(), nil
			}
			fmt.Fprintf(&preview, "\n▸ 作用域：%s ✓（在实验清单内）", strings.Join(targets, ", "))
			for _, warning := range warnings {
				fmt.Fprintf(&preview, "\n⚠ %s", warning)
			}
		}
	}
	// A write operation creates an approval request up front (no side effects).
	if t != nil && (t.Write || t.Execution) {
		run, err := a.Executor.Run(c, name, planArgs, "")
		if err != nil {
			return "", err
		}
		a.LastPlan.RequestID = run.RequestID
		return preview.String() + "\n" + run.Preview, nil
	}
	return preview.String(), nil
}

func (a *App) lastTool() string {
	if a.LastPlan == nil {
		return "<none>"
	}
	return a.LastPlan.Tool
}

func gatedNames(a *App) string {
	var names []string
	for _, s := range a.Registry.Gated(a.Config) {
		names = append(names, s.Name+"("+s.Capability+")")
	}
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ", ")
}

func showOptions(a *App) string {
	if a.CurrentModule == "" {
		return "尚未选择模块（/use <module>）"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Module: %s\n", a.CurrentModule)
	keys := make([]string, 0, len(a.CurrentArgs))
	for k := range a.CurrentArgs {
		keys = append(keys, k)
	}
	for _, k := range keys {
		fmt.Fprintf(&b, "  %s = %s\n", k, a.CurrentArgs[k])
	}
	if len(keys) == 0 {
		b.WriteString("  (未设置参数；用 /set RHOSTS <ip>)\n")
	}
	return b.String()
}

func configText(a *App) string {
	var b strings.Builder
	b.WriteString("配置来源：\n")
	if len(a.Config.Sources) == 0 {
		b.WriteString("  (defaults + environment)\n")
	}
	for _, s := range a.Config.Sources {
		b.WriteString("  " + s + "\n")
	}
	s := a.Sessions.Current()
	experiment := ""
	if s != nil {
		experiment = s.ExperimentID
	}
	b.WriteString(fmt.Sprintf("backend=%s environment=%s experiment=%s\n",
		a.Config.MSF.Backend, a.Config.Lab.EnvironmentMode, experiment))
	b.WriteString(fmt.Sprintf("authorized(PAT_AUTHORIZED=1)=%v dry_run=%v\n",
		config.Authorized(), a.Config.Safety.DefaultDryRun))
	return b.String()
}

func eventText(a *App, n int) string {
	s := a.Sessions.Current()
	id := ""
	if s != nil {
		id = s.ID
	}
	events, err := a.Store.List(context.Background(), id)
	if err != nil {
		return err.Error()
	}
	if n > len(events) {
		n = len(events)
	}
	start := len(events) - n
	if start < 0 {
		start = 0
	}
	var b strings.Builder
	for _, e := range events[start:] {
		payload, _ := json.Marshal(e.Payload)
		fmt.Fprintf(&b, "#%d %s [%s] %s %s %s\n", e.Seq, e.Type, e.Actor, e.Tool, e.RequestID, util.SafeText(string(payload), 200))
	}
	if b.Len() == 0 {
		return "(无事件)"
	}
	return b.String()
}

func helpText() string {
	return `PAT — Penetration AI Toolkit（最小 demo）
命令模式（/）与自然语言汇入同一权限引擎与事件总线。

  /help                      帮助
  /search <keyword>          搜索 MSF 模块
  /use <module>              选择模块
  /set <opt> <val>           设置模块参数（如 RHOSTS、LHOST、LPORT）
  /show options              查看参数
  /plan [tool] [k=v ...]     只读规划 + dry-run 预览（永远可用，无副作用）
  /run [requestId]           执行已批准的计划（需三重闸门）
  /approve <requestId> [y|n] 批准/拒绝待确认项
  /capabilities              能力、后端、作用域自报
  /scope                     实验清单
  /sessions /jobs            MSF 会话
  /payload <type>            生成载荷（确认门内）
  /verdict <label> [execId]  记录裁决（confirmed|false_positive|unable）
  /cleanup                   收尾清理 + 残留核验
  /audit [csv|md] [path]     审计导出
  /events [n]                查看事件流
  /config                    配置来源与生效值
  /role <recon|operator|cleanup>
  /model <fake|openai>
  /clear /quit

自然语言示例：扫一下 192.168.56.10 的 445
写操作需要 PAT_AUTHORIZED=1 + isolated_lab + 逐 tool call 确认。`
}
