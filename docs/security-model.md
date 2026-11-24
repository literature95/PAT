# PAT 安全模型（本实现）

> 仅用于已获授权的安全测试、防御研究与教学。禁止在未授权资产上使用。

## 授权闸门（三者缺一即只读）

1. **环境**：写操作要求 `PAT_AUTHORIZED=1`。未设置时 `perm.Engine` 在第一层直接 deny，任何工具调用（包括模型发起的）都不会到达网关。
2. **配置**：`lab.environment_mode` 必须是 `isolated_lab`（默认）或显式 `authorized_test`。`isolated_lab` 下公网 IP 字面量直接拒绝。
3. **会话**：每个写操作/执行工具调用生成 `approval.requested(requestId)`，需人工 `/approve <requestId>` 或 `POST /api/v1/approvals/{requestId}`。未批准时 `/run` 只返回待审批提示，不产生任何 RPC/子进程调用。

`config.Load()` 是唯一配置入口；core 与 gateway 共用同一实例。

## 威胁与缓解

| 威胁 | 缓解 |
|---|---|
| 提示注入（MSF 描述、回显、文档） | 工具输出经 `core/util.SafeText` 统一剥离 OSC/CSI/控制字符并截断；`MarkupEscape` 处理标记语法；模型只能调用注册表中声明过的工具，OpenAI adapter 丢弃未登记的工具名。 |
| 模型越权 | 所有执行经 `perm.Engine` 四层；`ask` 必须拿到 human approval；审批 `requestId` 与 tool call 一一绑定，`Approvals.Get(id).Tool` 必须匹配目标工具；远程 SSE 审批也回写事件总线。 |
| 目标误指 | 作用域基于实验清单（IP/CIDR/名字），不是泛 RFC1918 allowlist；CIDR 必须是清单网络的子网；执行前 `CommandChain` 剥掉 `sudo/env/timeout/proxychains4` 等包装器再对真实二进制做匹配，deny 优先，空 allowlist 全拒，悬空包装器 fail closed。`/plan` 预览解析后的模块全名、RHOSTS、LHOST/LPORT。 |
| 凭据泄露 | API Key 只从环境变量读取，不写配置/事件；MSF 凭据只从 `PAT_MSF_PASS` 读取；`optsFrom` 中的敏感参数不进审计 payload 的原文渲染路径。 |
| 审计抵赖 | events 表 append-only，哈希链链式校验（`VerifyChain`）；导出带 experimentId 与时间戳；actor 区分 human/agent/system。 |
| 多前端审批串号 | SSE 只推送对应 session 的事件；`requestId` 与工具名双重校验；同一 Manager 被 CLI 与 HTTP 共用。 |
| 数据外发 | `model.provider=openai` 且 `consent_external_llm=false` 时直接拒绝启动 provider；默认 provider 为本地 fake。 |
| 分发安全 | `install.ps1` 只做下载/校验/解压/搬移，不执行下载的脚本；`irm | iex` 只运行仓库内已审阅的脚本，载荷是带校验和的单二进制。推荐的正式分发仍是单二进制 + 签名。 |

## 明确不是安全边界

- CLI 后端需要解析 msfconsole 终端回显，属于 best-effort 降级路径；生产主路径应为 msfrpcd RPC（本 demo 未实现）。
- HTTP Server 无认证，默认只监听 loopback；不要绑定到 `0.0.0.0` 或公网。
- 作用域/allowlist/denylist 是防误操作护栏，不是进程隔离、沙箱或权限提升防护。
- 本 demo 不连接公网资产，也不做端到端靶场验收。
