# PAT 架构（本仓库实际实现）

本文件描述**当前 Go 实现**，与 `README.md` 的 v2 目标架构对齐。当前交付是最小可运行纵切面：P0 内核 + P1 持久化/审计 + P2 的轻量 REST/SSE 适配。

## 分层

```text
ui/cli (REPL) ─┐
server (REST+SSE) ─┼─▶ app (唯一装配点) ─▶ core/{session,loop,agent,tool,perm,provider,audit,event,bus,util}
cmd/pat ───────┘                              │
                                              └─▶ gateway/{msf,nmap} （只实现 core/tool 定义的接口）
```

**边界纪律**

1. `core/` 不 import `gateway/`、`server/`、`ui/`、`app/`；网关实现 core 声明的接口。
2. `ui/` 与 `server/` 都只调用 `app`，二者互不 import。前端之间不共享状态，状态在 app/core 中。
3. `config.Load()` 返回的配置由 core 与 gateway 共享；网关不得自行读配置文件绕过授权闸门。
4. 能力门控是**注册时不注册**：`capabilities.execution=false` 时 `nmap_scan` / `module_execute` / `console` 根本不在注册表里，模型看不到调用机会。规划接口 `PlanSpec` 始终可用（只读、无副作用）。

## 一次输入的执行路径

```text
用户输入 ─┬─ "/..." ─▶ app.Command ─┐
          └─ 其他   ─▶ provider.Complete ─▶ app.HandleMessage ─┤
                                                               ├─▶ perm.Engine.Check
                                                               ├─▶ tool.Executor.Plan（永远可用，写 tool.planned）
                                                               └─▶ tool.Executor.Run
                                                                     ├ allow → Execute
                                                                     ├ ask   → approval.requested(requestId)，不执行
                                                                     └ deny  → error.raised，不执行
```

无论参数由人填还是模型填，都走同一个 `perm.Engine` 与 `event.Emitter`。不存在人工模式绕过检查的捷径。

## 权限四层（core/perm）

1. **环境闸门**：写操作要求 `PAT_AUTHORIZED=1`（`Safety.RequireEnvAuth`）。
2. **能力闸门**：工具所需 capability 未启用 → 拒绝；注册表中已不存在该工具。
3. **作用域**：实验清单内的 IP/CIDR/名字；清单外 IP 字面量拒绝，`isolated_lab` 下公网 IP 直接拒绝；未解析主机名放行但给 `scopeWarnings`。
4. **规则**：`allow/deny/ask` 首条命中，默认 deny。
   - 外部进程另经 `CheckExecPolicy`：剥掉 `sudo/env/timeout/proxychains4` 等包装器后对真实二进制做 case-sensitive glob 匹配；denylist 对链上**每个**二进制生效，空 allowlist = 全拒，悬空包装器 = fail closed。

## 事件溯源

`core/event` 用 SQLite（modernc，纯 Go）append-only 存储：`events` 表 + SHA-256 哈希链（`hash = sha256(prev_hash + canonical(payload))`）。派生状态（待审批、工具计数、当前裁决）只放在视图里，不落表。`PRAGMA user_version` 写死 schema 版本；旧库直接拒绝，视图每次初始化无条件重建。

## 网关

- `gateway/msf`：`Backend` 接口 + `cliBackend`（临时 `.rc` 脚本喂给 `msfconsole -q -r`）+ `mockBackend`。`console()` 只接受已存在的 `.rc` 文件路径，绝不拼接模型输出的字符串。RPC/REST 后端在目标架构中，本实现保留接口与 `backend` 配置项，未实现真实 RPC。
- `gateway/nmap`：`nmap` CLI subprocess，执行前复用同一个 `CheckExecPolicy`；未安装 nmap 时降级到 mock。

## 已知限制（不是安全边界）

- 单进程只维护一个当前 session；SSE 订阅按 session id 过滤。
- HTTP Server 默认只监听 `127.0.0.1`，没有认证层；不要暴露到公网。
- CLI 后端解析 msfconsole 终端回显，属于 best-effort；主路径在生产中应为 msfrpcd RPC。
- 这些护栏是防误用与可审计性保障，不构成沙箱或安全边界。
