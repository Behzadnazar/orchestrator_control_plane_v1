# Live Deny Proof Summary

- generated_at: 2026-03-24T08:59:47+00:00
- created_rowid: 13
- created_task_id: live-deny-a198ff23cee0
- deny_returncode: 1

## DB Snapshot

- rowid: 13
- task_id: live-deny-a198ff23cee0
- task_type: frontend.write_component
- status_after_deny_attempt: blocked

## Deny stderr

```
{
  "ok": false,
  "error_type": "ApprovalGateError",
  "error": "actor not authorized for approval: actor=ci-bot, roles=['automation'], required=['frontend_reviewer', 'human_approver', 'platform_admin']",
  "ts": "2026-03-24T08:59:47+00:00"
}
```

## Governance Audit Tail

- {"event_type": "execution_denied_by_policy_runner", "owner_agent": "memory_agent", "payload_preview_keys": ["json_value", "path"], "reasons": ["path escapes project root: /tmp/evil.json"], "task_type": "memory.write_json", "ts": "2026-03-24T08:57:03+00:00"}
- {"actor": "behzad", "count": 0, "event_type": "blocked_tasks_listed", "ts": "2026-03-24T08:57:17+00:00"}
- {"event_type": "execution_denied_by_policy_runner", "owner_agent": "memory_agent", "payload_preview_keys": ["json_value", "path"], "reasons": ["path escapes project root: /tmp/evil.json"], "task_type": "memory.write_json", "ts": "2026-03-24T08:57:26+00:00"}
- {"actor": "behzad", "count": 1, "event_type": "blocked_tasks_listed", "ts": "2026-03-24T08:59:40+00:00"}
- {"actor": "ci-bot", "event_type": "approval_denied_by_policy", "owner_agent": "frontend_agent", "reasons": ["actor not authorized for approval: actor=ci-bot, roles=['automation'], required=['frontend_reviewer', 'human_approver', 'platform_admin']"], "rowid": 13, "task_id": "live-deny-a198ff23cee0", "task_type": "frontend.write_component", "ts": "2026-03-24T08:59:47+00:00"}