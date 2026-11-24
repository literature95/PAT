# PAT — Penetration AI Toolkit

AI 版 msfconsole：`/` 命令 + 自然语言 Agent 双模式，Go 单二进制 TUI。

> 仅用于已获授权的安全测试、防御研究与教学场景，禁止在未授权资产上使用。详见 `docs/security-model.md`。

---

## 0. 现状与定位（2026-11）

本文既是 **v2 目标架构说明**，也是**当前 Go 最小可运行 demo 的实现说明**。下半部分的功能计划表保留原始排期，实际交付状态以本节为准。

| 文档 | 定位 |
|---|---|
| 本文 `README.md` | v2 目标架构 + 当前实现状态 |
| `docs/architecture.md` | **当前 Go 代码**的真实分层与边界 |
| `docs/security-model.md` | 当前实现的安全不变量与已知限制 |
| `docs/schema.sql` | 事件库参考 DDL（由测试校验与代码一致） |
| `api/openapi.json` · `api/events.md` | Server API / 事件契约 |

**已交付（本轮）**：单 module Go 工程；`core/{session,loop,agent,tool,perm,provider,audit,event,bus,util}`；四层权限引擎（环境闸门 / 能力门控 / 作用域 / allow-deny-ask，默认 deny）；append-only SQLite 事件溯源 + 哈希链 + 视图重放；能力关闭时工具**不注册**；plan 永远免费、execute 单独审批（`requestId` 与工具一一绑定）；审计 CSV/Markdown 导出；清理残留核验；证据→裁决闭环；MSF / nmap 的 CLI 内嵌后端 + mock 降级；fake LLM provider（无需 API Key）与 OpenAI adapter；REST + SSE Server；终端 `pat` REPL；`install.ps1` 安装器与单元测试。

**未实现（保留为后续阶段）**：真实 msfrpcd MessagePack RPC / REST 后端、Bubble Tea 富 TUI、MCP stdio、go-plugin/WASM 插件、蓝队 Sysmon 遥测映射、自定义命令模板、多会话并发。详见 `docs/architecture.md` 的「已知限制」。

> 工具链：§1 的目标架构写 Go 1.22+；当前依赖解析出的 `go.mod` 要求 **Go 1.26+**（本机用 1.27.4 构建/测试通过）。

**状态图例**：✅ 已在 Go 代码中实现 · 🚧 部分实现（接口/骨架） · 🔲 规划中 · ✅* 仅为靶场原型（非 Go）。

### 立即运行

```powershell
# 一次性构建安装（install.ps1 只下载/校验/解压/搬移，不执行下载的载荷）
irm https://raw.githubusercontent.com/literature95/PAT/main/install.ps1 | iex
# 或在仓库内：
powershell -ExecutionPolicy Bypass -File .\install.ps1 -BuildFrom .

pat -c "/help"
pat -c "扫一下 192.168.56.10 的 445"
PAT_AUTHORIZED=1 pat          # 交互 REPL；写操作需确认
pat -serve -listen 127.0.0.1:8088
```

写操作需同时满足：`PAT_AUTHORIZED=1` + `lab.environment_mode=isolated_lab` + `/approve <requestId>`。未确认时不会产生任何 RPC / 子进程调用。

**阅读顺序**：§0 → §3（设计）→ §8/§9（安全）→ §11（借鉴）→ §4/§12（排期）。

---

## 1. 技术栈

| 层 | 选型 | 说明 |
|---|---|---|
| 语言 | Go 1.22+ | 单二进制分发，无运行时依赖 |
| TUI | Bubble Tea + Bubbles + Lipgloss | Charm 生态，组件与样式分离 |
| 内核 Server | net/http + chi · SSE | REST + 事件流，多前端共用 |
| 存储 | SQLite（modernc.org/sqlite） | 会话/消息/审计/权限规则，纯 Go 无 CGO |
| LLM 接入 | 自建 Provider 抽象 | OpenAI 兼容优先，Anthropic / Gemini adapter |
| MSF 对接 | msfrpcd · MessagePack RPC（`vmihailenco/msgpack/v5`）为主，REST / CLI 为可替换后端 | 模块搜索/执行/会话/控制台透传；后端可探活降级，见 §3.4 |
| MSF CLI 后端 | `msfconsole -r <rc>` / `-x` 子进程（仅 fallback） | 只喂预渲染的 resource 脚本，不解析终端回显 |
| 配置 | TOML，三层合并 | 全局 `~/.config/pat/` → 项目 `.pat/` → 环境变量 |
| 扩展（P3） | 插件（go-plugin / WASM）+ MCP | 事件钩子 + 外部工具接入 |

---

## 2. 项目结构

```text
pat/
├── go.work                    # 多 module 工作区（是否必要见 §13）
├── api/
│   ├── openapi.json           # Server API 契约（契约先行）
│   └── events.md              # 事件总线事件类型定义
├── cmd/
│   ├── pat/                   # 入口：启动内核(可内嵌) + 挂载 TUI
│   └── pat-tui/               # 纯 TUI 客户端（连接远程 patd）
├── core/                      # 内核，零 UI 依赖
│   ├── session/               # 会话/消息模型 + SQLite 仓储 + 事件溯源
│   ├── loop/                  # Agent loop 状态机（stream/stop/continue）
│   ├── agent/                 # 角色定义（recon/operator/cleanup）
│   ├── tool/                  # 工具注册表：Schema、惰性 init、执行拦截
│   ├── perm/                  # 权限引擎（能力门控 + 作用域 + allow/deny/ask）
│   ├── provider/              # LLM 抽象 + openai/anthropic/gemini adapter
│   ├── audit/                 # 审计导出（事件流 → CSV/Markdown 台账）
│   └── bus/                   # 事件总线（进程内 + SSE 对外）
├── gateway/
│   ├── msf/                   # msfrpcd 客户端（RPC / REST / CLI 三种 Backend）
│   └── toolnmap/              # 示例：外部工具接入（同一 Tool 接口）
├── server/                    # HTTP 层：REST + SSE，暴露 core 能力
├── ui/
│   └── tui/                   # Bubble Tea 客户端（只调 server API）
├── config/                    # 配置加载与三层合并
└── docs/
    ├── architecture.md
    └── security-model.md
```

**边界纪律**：

1. `core/` 零 UI 依赖，TUI/Web/CLI 只是不同客户端；
2. `ui/` 不直连 `gateway/`，一切经 server API，权限在内核侧强制；
3. `api/` 契约先行，SDK 客户端由契约生成，供脚本/CI 使用；
4. **共享核心即契约**：TUI、CLI、MCP 前端都只是 `core/` 的薄适配层，前端层之间禁止互相 import（见 §11.1）；
5. **契约要可执行**：`api/openapi.json` 不是文档摆设，必须有契约哨兵测试冻结 API / 工具清单并逐条走真实适配路径（见 §10）。

---

## 3. 框架设计

### 3.1 分层

```text
┌─────────────────────────────────────────────────────────┐
│ 客户端层   TUI · Web 面板 · CLI 单次(pat -c) · MCP/SDK   │
└──────────────────────────┬──────────────────────────────┘
                REST + SSE / stdio JSON-RPC
┌──────────────────────────▼──────────────────────────────┐
│ patd 内核（本地 Server）                                  │
│  API 层：/session /tool /permission /approval /audit /event │
│  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────────────┐   │
│  │Session │ │Agent   │ │Tool    │ │Permission      │   │
│  │SQLite  │ │Loop    │ │Registry│ │能力门控+作用域  │   │
│  └────────┘ └───┬────┘ └───┬────┘ └───────┬────────┘   │
│  ┌────────┐ ┌───▼──────────▼──────────────▼─────────┐   │
│  │Audit   │ │ Provider 抽象层(LLM) │ Tool 执行层     │   │
│  │事件溯源 │ └──────────────────────┴────────┬───────┘   │
│  └────────┘                                 │           │
└─────────────────────────────────────────────┼───────────┘
                             msfrpcd · MCP · 插件工具
```

### 3.2 双模式汇合

```text
用户输入 ──┬─ "/" 前缀 ──▶ 命令路由 ──┐
          └─ 其他 ─────▶ Agent loop ─┴─▶ Permission 检查 ─▶ Tool 执行层 ─▶ msfrpcd
                                     （人填参数 / 模型填参数，执行与审计同一套）
```

关键点：无论参数由人填还是模型填，**都必须经过同一套权限引擎与事件总线**，不存在「人工模式绕过检查」的捷径。

### 3.3 核心子系统

- **Session / 事件**：会话、消息、工具调用、确认决策全部追加写入 SQLite（事件溯源），一个机制支撑 `/undo`、审计导出、复盘台账。
- **Permission 引擎**：四层串联——环境闸门（`PAT_AUTHORIZED=1`）→ 能力门控（工具是否注册）→ 作用域校验（目标是否在实验清单内）→ allow/deny/ask 规则（首条命中，默认 deny）。`ask` 走确认框并带 `requestId`。
- **Agent 角色**：`recon`（只读工具集）/ `operator`（全工具，写操作 ask）/ `cleanup`（仅清理类）——角色 = 提示词 + 工具集 + 权限档位，见 §3.7。
- **Provider 抽象**：统一消息 schema，屏蔽模型厂商差异；模型元数据本地目录，不依赖外网；数据外发前需一次性同意（§11.9）。
- **Agent loop**：显式状态机 `idle → planning → awaiting_approval → executing → observing → done | cancelled | failed`；每一步写入事件总线，支持 stop / continue、超时与 token 预算；审批 `requestId` 与 tool call 一一对应，避免多轮对话串号。

### 3.4 MSF 后端选型：内置命令行能不能用？

结论：**可以用，但只能作为 fallback，不能作为主路径**。四种接法的取舍：

| 方案 | 可行性 | 评价 |
|---|---|---|
| msfrpcd + MessagePack RPC | ✅ 推荐主路径 | 结构化方法（`module.search` / `module.execute` / `session.list` / `console.create` / `console.write` / `console.read`），天然支持多客户端与审计。控制台透传本来就走 RPC 的 `console.*`，不必再单独开一个终端。代价是要单独跑 `msfrpcd`，MessagePack 是唯一新增依赖。 |
| MSF REST API（:8080） | ✅ 次选 | 现有 `PAT_control.ps1` 已在探活 `/api/v1/health` 与 `/api/v1/sessions`。但依赖 `thin / sinatra / rack`，靶场实测因网络受限装不上 gem，只能作为「就绪即切换」的可选后端。 |
| msfconsole 子进程 + `.rc` resource 脚本 | ⚠ 仅 fallback | 现项目正是这么做的：`msfconsole -r handler_x.rc` 起 handler，`sessions -i <sid> -C "<cmd>"` 下发指令，`msfconsole -x "jobs -K"` 收尾。优点是零额外依赖、能覆盖 RPC 未暴露的控制台命令；缺点是每次新建 Ruby 进程启动慢、回显难解析、并发会话难管理。 |
| 把 MSF 作为 Ruby 库内联进进程 | ❌ 不采用 | `require 'msf/base'` 直接驱动 `Msf::Simple::Framework` 能力最强，但必须带 Ruby 运行时，和「Go 单二进制、无运行时依赖」的立项目标直接冲突。 |

落地建议：`gateway/msf` 定义 `Backend` 接口（`Search / Execute / Sessions / Console / Close`），实现 `rpcBackend`、`restBackend`、`cliBackend` 三种；启动时按 `config.msf.backend` 或 REST → RPC → CLI 顺序探活选一个，并把实际使用的后端写入事件总线。CLI 后端只允许执行预渲染的 `.rc` 文件，**禁止把模型输出的字符串直接拼成 msfconsole 命令**（见 §9）。

需要强调：msfrpcd 的 `console.*` 本身就是「远程 msfconsole」，所以「内置命令行」能力已被主路径覆盖；保留 CLI 后端只是为了覆盖 RPC 未暴露的个别命令和降级场景。

### 3.5 事件存储与事件目录

事件存储是审计、撤销、复盘、遥测映射的唯一数据源。**只追加，不 UPDATE / DELETE**。

```sql
CREATE TABLE events (
    seq           INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id      TEXT NOT NULL UNIQUE,
    session_id    TEXT NOT NULL,
    experiment_id TEXT,
    actor         TEXT NOT NULL CHECK (actor IN ('human', 'agent', 'system')),
    type          TEXT NOT NULL,
    tool          TEXT,
    request_id    TEXT,                 -- 审批与工具调用一一对应
    payload       TEXT NOT NULL,        -- JSON；敏感字段写入前脱敏
    prev_hash     TEXT NOT NULL,        -- 前一条事件哈希，链式校验
    hash          TEXT NOT NULL,
    created_at    TEXT NOT NULL
);
CREATE INDEX idx_events_session ON events(session_id, seq);
CREATE INDEX idx_events_type ON events(type);
CREATE INDEX idx_events_request ON events(request_id);

-- 派生状态一律用视图计算，不落表（见 §11.7）
CREATE VIEW v_pending_approvals AS
    SELECT * FROM events WHERE type = 'approval.requested' ...;
```

事件目录（详见 `api/events.md`）：

| 事件类型 | 触发时机 | 关键字段 |
|---|---|---|
| `session.started` / `session.ended` | 会话生命周期 | `session_id`, `experiment_id` |
| `user.message` | 命令或自然语言输入 | `actor`, `text` |
| `plan.created` | Agent 产出计划 | `steps[]` |
| `tool.planned` | dry-run 预览，**无副作用** | `tool`, `args`, `preview` |
| `approval.requested` | 进入确认门 | `request_id`, `risk` |
| `approval.resolved` | 人工批准/拒绝 | `request_id`, `decision` |
| `tool.executed` | 实际执行 | `tool`, `backend`, `args` |
| `tool.result` | 回显与产物引用 | `artifact_id`, `summary` |
| `artifact.registered` | 产物落盘登记 | `path`, `sha256` |
| `verdict.recorded` | confirmed / false_positive / unable | `evidence[]` |
| `audit.exported` | `/audit` 导出 | `format`, `row_count` |
| `error.raised` | 异常与拒绝 | `code`, `message` |

### 3.6 Server API 端点

契约源文件：`api/openapi.json`。所有端点在内核侧强制权限，客户端不得自行判定。

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/v1/sessions` | 新建会话（携带 `experiment_id`） |
| GET | `/api/v1/sessions/{id}/events` | 事件流（SSE） |
| POST | `/api/v1/sessions/{id}/messages` | 输入命令或自然语言 |
| POST | `/api/v1/tools/{name}/plan` | 只读规划 / dry-run，永远可用 |
| POST | `/api/v1/tools/{name}/execute` | 执行，需审批 `request_id` |
| GET / POST | `/api/v1/approvals/{requestId}` | 待审批查询 / 批准拒绝 |
| GET | `/api/v1/capabilities` | 当前启用的能力、后端、作用域（自报能力） |
| GET | `/api/v1/scope` | 实验清单内的目标与补充项 |
| GET / POST | `/api/v1/permissions/rules` | 规则查看 / 更新 |
| GET | `/api/v1/audit` | 导出 CSV / Markdown |
| POST | `/api/v1/experiments/{id}/cleanup` | 清理并返回残留核验报告 |

### 3.7 角色 × 工具矩阵

角色 = 提示词 + 工具集 + 权限档位。`allow` 自动放行，`ask` 需确认，`deny` 拒绝（且工具不出现在该角色上下文中）。

| 工具 | recon | operator | cleanup |
|---|---|---|---|
| `module_search` | allow | allow | deny |
| `session_list` | allow | allow | allow |
| `module_execute(exploit/*)` | deny | ask | deny |
| `module_execute(auxiliary/scanner/*)` | allow | allow | deny |
| `console(*)` | deny | ask | deny |
| `payload_generate` | deny | ask | deny |
| `cleanup(*)` | deny | ask | allow |
| `audit_export` | allow | allow | allow |

---

## 4. 功能计划表

| # | 功能 | 阶段 | 状态 | 说明 |
|---|---|---|---|---|
| 1 | 双模式交互骨架（命令路由 + Agent loop） | P0 | ✅ | `/` 命令与自然语言汇入同一执行层 |
| 2 | msfrpcd 工具层封装 | P0 | ✅ | search / execute / sessions / console |
| 3 | **三重**授权闸门 + 默认 dry-run | P0 | ✅ | `PAT_AUTHORIZED=1` + 环境判定 + 会话确认；危险动作先预览 |
| 4 | 权限规则引擎 | P1 | 🔲 | 能力门控 + 作用域 + allow/deny/ask |
| 5 | Session SQLite 事件溯源 | P1 | 🔲 | 追加写入 + 哈希链 + 视图重放 |
| 6 | 操作审计导出（`/audit`） | P1 | 🔲 | 事件流 → CSV/Markdown 台账 |
| 7 | 自定义命令（`commands/*.md`） | P1 | 🔲 | `$ARGUMENTS` 占位符模板 |
| 8 | 载荷生成（`/payload`） | P1 | 🔲 | 危险动作，走确认门 |
| 9 | 实验收尾（`/cleanup` 清理 + 残留核验） | P1 | 🔲 | 收尾流程标准化 |
| 10 | 多模型接入（Anthropic / Gemini 原生） | P1 | 🔲 | Provider adapter |
| 11 | Server API 对外 + SDK | P2 | 🔲 | 契约冻结，脚本/CI 集成 |
| 12 | 角色系统（recon/operator/cleanup） | P2 | 🔲 | 提示词 + 工具集 + 权限三件套 |
| 13 | 手机/远程审批（SSE） | P2 | 🔲 | 同一 API 换前端，`requestId` 不串号 |
| 14 | 插件 + MCP 接入 | P3 | 🔲 | 事件钩子 + 外部工具 |
| 15 | 蓝队遥测映射（工具调用 → 检出对照） | P3 | 🔲 | 攻防一体差异化 |
| 16 | MCP 能力门控（只读默认，执行/变更按需注册） | P2 | 🔲 | 未开开关的工具根本不注册 |
| 17 | 作用域强制 + 执行白/黑名单 | P1 | 🔲 | 目标须在实验清单内；包装器剥壳后匹配真实二进制，deny 优先 |
| 18 | 执行 → 证据 → 裁决闭环 | P2 | 🔲 | tool call → artifact → verdict + evidence，按 executionId 幂等 |
| 19 | 后台任务与批量 plan/execute 分离 | P2 | 🔲 | plan 永远可用，execute 双开关；并发上限 + 取消 |

阶段定义：**P0** 跑通双模式 → **P1** 产品化（权限/持久化/审计）→ **P2** 平台化（API/SDK/多前端）→ **P3** 生态。阶段依赖与退出标准见 §12、§10。

---

## 5. 配置

`~/.config/pat/config.toml`（全局） → 项目 `.pat/config.toml` → 环境变量，三层依次覆盖；配置由 `config.Load()` 返回不可变实例，`core` 与 `gateway` 共用（§8.2）。

```toml
[msf]
rpc_host = "127.0.0.1"
rpc_port = 55553
backend = "auto"                   # auto | rpc | rest | cli

[model]
provider = "openai"                # openai | anthropic | gemini | 任意 OpenAI 兼容
name = "gpt-4o"
api_key_env = "PAT_API_KEY"        # Key 只从环境变量读取，不落盘
consent_external_llm = false       # 数据外发前需一次性告知并同意

[safety]
confirm_exploit = true             # 执行 exploit 前强制确认
confirm_payload = true             # 生成载荷前强制确认
allow_auto_recon = true            # 允许 Agent 自动执行只读侦察
require_env_auth = true            # 要求 PAT_AUTHORIZED=1 才允许写操作
default_dry_run = true             # 默认只规划不执行

[lab]
environment_mode = "isolated_lab"  # isolated_lab | authorized_test
experiment_id = ""                 # 留空则每次会话生成
scope_extra = []                   # 额外允许的 IP/CIDR/主机名

[capabilities]
# 能力开关：关闭时对应工具根本不注册（见 §11.2）
execution = false
mutations = false
batch = false
credential_injection = false
credential_reveal = false
mcp = false

[exec]
allowlist = ["nmap", "msfconsole"] # 空列表 = 全拒
denylist = ["rm", "dd", "mkfs*"]   # 永远优先
concurrency = 3
timeout_seconds = 300

# 权限规则：从上到下首条命中生效；未命中一律 deny（默认拒绝）
[[permission.rules]]
pattern = "module_search(*)"
action = "allow"

[[permission.rules]]
pattern = "session_list(*)"
action = "allow"

[[permission.rules]]
pattern = "module_execute(exploit/*)"
action = "ask"

[[permission.rules]]
pattern = "payload_generate(*)"
action = "ask"

[[permission.rules]]
pattern = "console(*)"
action = "deny"
```

### 环境变量

| 变量 | 说明 | 默认 |
|---|---|---|
| `PAT_AUTHORIZED` | 环境级授权闸门，`1` 才允许写操作 | 未设置（只读） |
| `PAT_API_KEY` | 模型 API Key | — |
| `PAT_MSF_URL` | msfrpcd 地址 | `http://127.0.0.1:55553/api/` |
| `PAT_MSF_USER` / `PAT_MSF_PASS` | msfrpcd 凭据 | `msf` / — |
| `PAT_LLM_BASE` | OpenAI 兼容端点 | `https://api.openai.com/v1` |
| `PAT_LLM_MODEL` | 模型名 | `gpt-4o` |
| `PAT_EXPERIMENT_ID` | 覆盖配置中的实验标签 | — |
| `PAT_SCOPE_EXTRA` | 覆盖补充作用域（逗号分隔） | — |

---

## 6. 命令速查

| 命令 | 说明 |
|---|---|
| `/search <keyword>` | 搜索 MSF 模块 |
| `/use <module>` / `/set <opt> <val>` / `/show options` | 选择模块 / 设参 / 查参 |
| `/plan <目标>` | 只读规划 + dry-run 预览，**无副作用，永远可用** |
| `/run` | 对已批准的计划执行；需过三重闸门 |
| `/approve <requestId>` | 批准 / 拒绝待确认项 |
| `/capabilities` | 查看当前启用的能力、后端与作用域 |
| `/scope` | 查看 / 补充实验清单内的目标 |
| `/payload <type>` | 生成载荷（确认门内） |
| `/sessions` / `/jobs` | 会话 / 后台任务 |
| `/cleanup` | 收尾清理 + 残留核验报告 |
| `/audit` | 审计日志查看 / 导出 |
| `/config` | 查看配置来源与生效值 |
| `/clear` / `/model <name>` / `/help` | 清上下文 / 切模型 / 帮助 |

自定义命令：`~/.config/pat/commands/*.md`，文件名即命令名，支持 `$ARGUMENTS`。

---

## 7. 快速开始

```bash
# 前置：启动 msfrpcd（MSF 6.x，仅监听本地）
msfrpcd -P <password> -S -f

# 配置（Key 只走环境变量）
export PAT_MSF_PASS=<password>
export PAT_API_KEY=sk-...
export PAT_LLM_MODEL=gpt-4o

# 构建（Windows 产物为 bin/pat.exe；Makefile 与下面等价）
make build && ./bin/pat.exe
# 或：go build -o bin/pat.exe ./cmd/pat

# 默认只读；写操作需要显式授权
set PAT_AUTHORIZED=1 && ./bin/pat.exe
# PowerShell: $env:PAT_AUTHORIZED=1; .\bin\pat.exe

# 单次任务（规划示例，目标须在实验清单内）
./bin/pat.exe -c "扫一下 192.168.56.10 的 445"
```

命令模式：

```text
pat » /use auxiliary/scanner/portscan/tcp
pat » /set RHOSTS 192.168.56.10
pat » /plan
▸ 预览：module_execute(auxiliary/scanner/portscan/tcp, RHOSTS=192.168.56.10)
pat » /approve <requestId>
pat » /run
```

自然语言：

```text
pat » 扫一下 192.168.56.0/24 的 445，列出存活主机
▸ 计划：module_search(smb) → module_execute(auxiliary/scanner/smb/smb_version)
▸ 作用域：192.168.56.0/24 ✓（在实验清单内）
⚠ 即将执行扫描，确认？[y/N]
```

---

## 8. 从靶场骨架继承的安全不变量

这些不是「借鉴」，而是现有脚本已经验证过、Go 内核必须原样保留的约束：

1. **三重授权闸门，缺一即只读**：环境变量 `PAT_AUTHORIZED=1` + 配置 `environment_mode=isolated_lab` + 会话内显式确认。现有脚本用 `-ConfirmLab` 实现第三重，Go 里改为逐 tool call 的审批，但三者都不能省。
2. **配置单一真源**：`common/PAT_LabConfig.ps1` 的 `Read-LabConfig` / `Assert-IsolatedLab` 被所有脚本 dot-source，避免每个模块自己判断环境。Go 侧对应 `config.Load()` 返回不可变实例，`core` 与 `gateway` 共用，禁止各网关自行读配置绕过闸门。
3. **统一实验标签**：`PAT_` 前缀同时用于 WMI 对象命名、Sysmon 规则关键字和清理匹配——一个标识符把「攻击动作」和「检测/清理」串起来。Go 里抽象为 `experimentId` / `campaignTag`，贯穿 session、事件、审计导出和 `/cleanup`。
4. **清理幂等 + 依赖顺序 + 二次核验**：`remove_wmi_sub.ps1` 按 Binding → Consumer → Filter 删除，删完再查一遍确认零残留才返回成功。`/cleanup` 必须返回「残留核验报告」，而不是「我执行过删除」。
5. **复盘台账作为审计格式**：`notes/experiment_log.md` 的「实验编号 / 前置快照 / 变更内容 / 运行现象 / 检出表现 / 清理确认」六段式，直接作为 `/audit` 导出 CSV/Markdown 的字段模板。
6. **遥测对照初版**：`sysmon_rules.xml` + `audit_check.ps1` 已覆盖 Event ID 1（进程创建）、3（网络连接）、11（文件创建）、18/19/20/21（WMI），以及 PowerShell / WMI-Activity / Security 通道。这就是 P3「蓝队遥测映射」的种子表，不用从零设计。
7. **探活与自动降级**：`Get-MsfRestHealth` 失败时退回本地 handler。Go 网关照搬这个模式，并在事件里记录「本次用了哪个后端」，便于复盘时解释行为差异。

---

## 9. 威胁模型（必须写进 docs/security-model.md）

- **提示注入**：MSF 模块描述、会话回显、网页/文档等工具输出都是不可信数据，绝不拼进 system prompt；工具返回值要做长度截断与字符转义。Agent 只能调用注册表里已声明 schema 的工具，永远不能执行「模型生成的任意字符串」。
- **模型越权**：所有工具调用必经 `perm` 引擎；`ask` 必须在关键路径上拿到 human approval，审批请求带 `sessionId + requestId`，远程 SSE 审批同样回写事件总线。模型无法自证授权，也无法跳过确认门。
- **目标误指**：dry-run 预览必须展示解析后的模块全名、`RHOSTS`、`LHOST/LPORT`。作用域不是泛泛的 RFC1918 allowlist，而是「本次实验清单内的主机/CIDR + 显式补充项」——清单外的 IP/CIDR 字面量（含目标文件里的条目）直接拒绝，未解析的裸主机名可放行但要给 `scopeWarnings`。执行前先剥掉 `sudo` / `env` / `timeout` / `proxychains4` 等包装器，再对真实二进制名做 allow/deny 通配匹配：deny 永远优先，空 allowlist 等于全拒。文档要写明这是护栏、不是安全边界。
- **凭据泄露**：API Key 只从环境变量读取；MSF 凭据、会话回显中的敏感字段不进事件日志与审计导出，导出前统一脱敏。
- **审计可抵赖性**：SQLite 使用 WAL + append-only，事件带前一条哈希形成链式校验；导出文件带 `experimentId` 与时间戳，避免事后补写无法被发现。
- **多前端审批串号**：审批请求与 tool call 一一绑定，SSE 只把待审批事件推给对应会话的订阅者。
- **数据外发**：把 finding / 目标 / 端口发给外部 LLM 前，需要一次性数据路径告知与可撤销的同意记录（§11.9）。
- **分发安全**：`irm | iex` 拉远程脚本执行不应作为主要分发方式；单二进制 + 校验和 / 签名才是 v2 的默认路径。现有安装脚本只做「下载解压搬移」、不执行载荷的边界要继续保持。

---

## 10. 测试与验收

- **单元测试**：权限引擎四层串联（能力关 → 作用域 → allow/deny/ask → 默认 deny）、三层配置合并优先级、事件重放一致性、后端探活选择顺序。
- **集成测试**：mock msfrpcd（假 MessagePack 服务）、fake LLM provider（固定 `tool_call` 序列）、临时 SQLite。目标是让核心逻辑在无 MSF、无 API Key 的 CI 里可跑。
- **契约哨兵**：冻结 Server API / MCP 工具清单（`EXPECTED_*` 集合），逐条经真实适配路径打 seed 数据库；故意增删工具必须在同一次改动里更新测试。再加一个文档一致性测试，防止 README 里的表格数、状态、路径悄悄漂移。
- **不可信文本注入**：单独一类测试，喂入带终端转义序列、标记语法、超长回显的 MSF 输出，确认渲染前已转义/截断（§11.8）。
- **靶场联调**：把现有 PowerShell 脚本当 fixture，验证 dry-run 不产生副作用、清理后二次查询残留为 0、`/audit` 导出字段与台账模板一致。
- **阶段退出标准**：
  - **P0**：输入「扫 192.168.56.10 的 445」→ 产出计划 + dry-run 预览 + 一个确认门；未确认时不产生任何 RPC 调用。
  - **P1**：进程重启后 session 可从事件重放；能力关闭时工具不在注册表中；作用域外目标与 deny 规则无法被模型以任何话术绕过。
  - **P2**：TUI 与远程审批两个客户端经同一 API 看到同一事件流，`requestId` 不串号；执行与产物、裁决可互相反查。
  - **P3**：至少 3 类 Sysmon 事件能反查到具体工具调用，映射表回填台账。
- **明确不测**：不在真实公网资产上做端到端验收；「实验文档」里的 frp + 公网 ECS 场景视为高风险例外，不作为 PAT 默认验收环境。

---

## 11. 从 Cerno 借鉴的工程约定

`D:\Documents\Desktop\cerno-main` 是同类终端工具（漏洞复核 + nmap/NetExec/nuclei/MSF 编排）里成熟度很高的一份参考，它踩过的坑正好是 PAT 计划里还没写的部分。最值得直接搬的：

1. **共享核心 / 薄适配层**：Cerno 的 TUI 与 MCP 前端都只是 `core/` 上的薄一层，`core/` 里没有 print、没有 prompt；MCP 层禁止 import TUI 层。PAT 已有 `core/` 零 UI 依赖的纪律，但应进一步规定「前端层之间禁止互相 import」，并把 `server/` 也当适配层而非业务逻辑所在地。
2. **能力门控 = 不注册，而非运行时拒绝**：Cerno 的 `mcp_allow_execution` / `mcp_allow_mutations` / `mcp_allow_batch` / `mcp_allow_cred_injection` / `mcp_allow_cred_reveal` 决定工具是否注册，启动时读一次。PAT 的权限引擎除 allow/deny/ask 规则外，应加一层「能力开关」：危险工具在开关关闭时根本不进注册表，模型连调用机会都没有；再提供 `get_capabilities` 让客户端自报可用能力，避免靠失败调用来试探。
3. **plan 永远免费，execute 单独开门**：Cerno 的 `plan_batch`（dry run）始终可用，`execute_batch` 要 execution + batch 双开关，且每条命令仍过策略 / 凭据 / 超时检查。PAT 的 `/run` 应拆成同构两段：规划工具只读、可反复调用；执行工具独立鉴权，批量执行再加一道开关与并发上限。
4. **作用域强制**：Cerno 拒绝落在「导入数据集主机 + `mcp_scope_extra`」之外的 IP/CIDR，而不是泛泛的私网判断。PAT 在 `PAT_AUTHORIZED` 之外加这层基于实验清单的校验，正好补上 §9 的目标误指。
5. **执行 → 证据 → 裁决闭环**：`tool_executions` → `artifacts` → `finding_verdicts` → `verdict_evidence`，按 `executionId` 幂等；verdict（`confirmed` / `false_positive` / `unable`）与 review state 分开存。PAT 的审计不要只记「执行了什么」，还要记「产物在哪、证明了什么、谁裁决的」——这才是 P3 蓝队遥测映射真正需要的数据基础。
6. **归因不可混淆**：Cerno 的每个 finding id 都带来源前缀（`operator:` 人工 / `agent:` 模型），`completed_by` / `created_by` 记录是哪个通道做的。PAT 的事件也要带 `actor=human|agent`，模型断言与人工确认在审计里分开呈现——直接回应「模型无法自证授权」。
7. **SQLite 工程纪律**：派生值一律用视图算、不落表；FK + CHECK + UNIQUE 约束齐全；schema 版本写进 `PRAGMA user_version`，旧库直接拒绝；视图每次初始化都重建（`CREATE VIEW IF NOT EXISTS` 不会更新已存在的视图）；另存一份参考 `schema.sql` 由测试校验与代码一致。PAT 的事件溯源应照搬，尤其是 append-only + 视图重放 + schema 版本。
8. **不可信文本要有回归测试**：Cerno 对扫描输出一律 `safe_text()`，并有 `test_markup_injection.py` 防终端转义 / 标记注入。PAT 的 MSF 回显同理，应作为独立测试类别，而不是靠「记得转义」。
9. **数据外发要同意**：Cerno 的 Claude Assistant 默认关闭，首次使用展示数据路径告知并持久化同意。PAT 把 finding / 目标 / 端口发给外部 LLM 前，也应有一次性告知与可撤销的同意记录。
10. **文档漂移要能被测出来**：Cerno 的 README 示例由渲染器生成、测试用 `--check` 防陈旧，另有文档一致性测试防止表格计数漂移——这正是 PAT 当前 README 与真实代码脱节的解决办法。建议把 §0 的「现状」说明做成可执行检查，而不是靠人记得更新。

---

## 12. 里程碑与依赖关系

按依赖推进，不要跳阶段；每阶段的退出标准见 §10。

| 阶段 | 主要交付 | 前置依赖 | 退出标准 |
|---|---|---|---|
| P0 | 双模式骨架 + Agent loop + `perm` 引擎四层 + mock 网关 | — | §10 P0 |
| P1 | 事件存储 / 审计导出 / 作用域 / 能力门控 / 清理核验 | P0 | §10 P1 |
| P2 | Server API + MCP + 多前端远程审批 + 证据链 + 批量任务 | P1 | §10 P2 |
| P3 | 插件 / go-plugin 或 WASM / 蓝队遥测映射 | P2 | §10 P3 |

依赖关系：

```text
P0 内核与权限  ──▶  P1 持久化与审计  ──▶  P2 平台化与多前端  ──▶  P3 生态
     │                    │                     │
   mock 网关         靶场脚本当 fixture     契约哨兵测试
```

**一条贯穿原则**：P0 就要把权限引擎和事件总线的接口定死，后面所有功能都挂在这两个接口上；否则 P1/P2 会反复返工。

---

## 13. 待决问题（Open Questions）

这些问题尚未定案，建议在对应阶段开始前拍板，并把结论写回本文与 `docs/architecture.md`。

| # | 问题 | 备选 | 建议 | 何时决定 |
|---|---|---|---|---|
| 1 | `go.work` 多 module 是否必要 | 多 module / 单 module + `internal/` | 初期用单 module，`cmd/` 拆分就够了；多 module 徒增发布复杂度 | P0 |
| 2 | 插件机制 | go-plugin / WASM | 先用进程内 Tool 接口 + 外部二进制，P3 再评估 WASM 沙箱 | P3 |
| 3 | 事件流协议 | SSE / WebSocket | 审批是「一问一答 + 回写」，SSE + POST 足够；WebSocket 留到需要双向高频时 | P2 |
| 4 | schema 迁移策略 | 旧库直接拒绝 / 自动迁移 | 参考 Cerno：旧库拒绝 + 明确重建指引，避免半迁移脏数据；事件库尤其敏感 | P1 |
| 5 | 敏感字段脱敏规则由谁定义 | 硬编码 / 规则表 | 做成可配置规则表，并由测试覆盖，避免凭「记得脱敏」 | P1 |
| 6 | 靶场脚本最终定位 | fixture / 子命令 / 独立仓库 | 先当集成测试 fixture；稳定后再决定是否暴露为 `pat lab` 子命令 | P1 |
| 7 | 远程审批的认证与防重放 | 会话令牌 / 签名请求 | 审批链接带签名 + 过期时间 + `requestId` 幂等，防止重放与串号 | P2 |
| 8 | MCP stdio 与 Server API 如何共用权限引擎 | 两套实现 / 同一 `core/perm` | 必须共用同一个 `core/perm`，MCP 只是另一种适配层 | P2 |

---

## 14. License

MIT · 提交前请阅读 `docs/security-model.md`（授权闸门与威胁模型）。
