# PAT 事件目录（api/events.md）

事件存储是审计、撤销、复盘的唯一数据源。只追加，不 UPDATE / DELETE。字段定义见 `core/event/types.go`，参考 DDL 见 `docs/schema.sql`。

| 事件类型 | 触发时机 | 关键字段 |
|---|---|---|
| `session.started` / `session.ended` | 会话生命周期 | `session_id`, `experiment_id` |
| `user.message` | 命令或自然语言输入 | `actor`, `text` |
| `plan.created` | Agent 产出计划 | `steps[]` |
| `tool.planned` | dry-run 预览，**无副作用** | `tool`, `args`, `preview` |
| `approval.requested` | 进入确认门 | `request_id`, `tool`, `args`, `risk` |
| `approval.resolved` | 人工批准/拒绝 | `request_id`, `decision` |
| `tool.executed` | 实际执行 | `tool`, `backend`, `args`, `approved_by` |
| `tool.result` | 回显与摘要 | `tool`, `execution_id`, `summary`, `warnings` |
| `artifact.registered` | 产物登记 | `path`, `tool` |
| `verdict.recorded` | confirmed / false_positive / unable | `verdict`, `note`（裁决入库同时由 `tool.result` 关联 execution_id） |
| `audit.exported` | `/audit` 导出 | `format`, `row_count`, `path` |
| `error.raised` | 异常与拒绝 | `code`, `layer`, `message`, `tool` |

派生视图：`v_pending_approvals`（未决审批）、`v_tool_counts`（工具调用计数）、`v_current_verdict`（当前裁决）。
