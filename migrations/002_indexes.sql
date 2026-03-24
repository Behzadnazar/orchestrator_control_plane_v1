CREATE INDEX IF NOT EXISTS idx_tasks_status_priority_created_at
ON tasks(status, priority, created_at);

CREATE INDEX IF NOT EXISTS idx_events_entity_type_entity_id_created_at
ON events(entity_type, entity_id, created_at);

CREATE INDEX IF NOT EXISTS idx_heartbeats_status_last_seen
ON heartbeats(status, last_seen);
