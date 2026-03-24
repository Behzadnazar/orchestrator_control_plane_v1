# Immutable Audit Chain Verification Report

- Generated at (UTC): `2026-03-20T10:26:33+00:00`
- Index path: `artifacts/audit/immutable_audit_index.jsonl`
- Overall status: **PASS**
- Legacy raw-line links allowed: **False**
- Contract rule: `previous_entry_sha256 must equal previous entry's entry_sha256`
- Total entries: **3**
- OK entries: **3**
- Failed entries: **0**
- Output directory: `artifacts/audit/verification/O2_growth_chain_after_milestone`

## Entry Matrix

| Line | Type | Milestone | RC | Entry Hash | Previous Link | Link Mode | Record Exists | Record SHA256 | Entry OK |
|---:|---|---|---|---|---|---|---|---|---|
| 1 | milestone_record | M1_freeze_gate | None | OK | OK | entry_sha256 | OK | OK | OK |
| 2 | release_candidate_record | M1_freeze_gate | RC1 | OK | OK | entry_sha256 | OK | OK | OK |
| 3 | milestone_record | O2_growth_freeze | None | OK | OK | entry_sha256 | OK | OK | OK |

## Detailed Results

### Line 1 — milestone_record

- Milestone: `M1_freeze_gate`
- Release candidate: `None`
- Entry OK: **YES**
- Declared link mode: `entry_sha256`
- Resolved link mode: `entry_sha256`
- Record path: `artifacts/audit/milestone_records/M1_freeze_gate/signed_milestone_record.json`
- Recorded entry SHA256: `5bed7697e5ecbb6d5efd87a660135425ff0016df82cdbc8a33eae4550cc846ad`
- Computed entry SHA256: `5bed7697e5ecbb6d5efd87a660135425ff0016df82cdbc8a33eae4550cc846ad`
- Recorded previous entry SHA256: `None`
- Expected previous entry SHA256: `None`
- Expected previous raw-line SHA256: `None`
- Recorded record SHA256: `40d4fda522f46bd5a8fc1a5dc750c225d07a4e369694b61ea59cdc49b645b057`
- Computed record SHA256: `40d4fda522f46bd5a8fc1a5dc750c225d07a4e369694b61ea59cdc49b645b057`

### Line 2 — release_candidate_record

- Milestone: `M1_freeze_gate`
- Release candidate: `RC1`
- Entry OK: **YES**
- Declared link mode: `entry_sha256`
- Resolved link mode: `entry_sha256`
- Record path: `artifacts/audit/release_candidate_records/RC1/release_candidate_record.json`
- Recorded entry SHA256: `b1796898db1db09d86c5cca8ffbfbae2143012bed20a4f9014e7073a5ab271a2`
- Computed entry SHA256: `b1796898db1db09d86c5cca8ffbfbae2143012bed20a4f9014e7073a5ab271a2`
- Recorded previous entry SHA256: `5bed7697e5ecbb6d5efd87a660135425ff0016df82cdbc8a33eae4550cc846ad`
- Expected previous entry SHA256: `5bed7697e5ecbb6d5efd87a660135425ff0016df82cdbc8a33eae4550cc846ad`
- Expected previous raw-line SHA256: `b11664df343a82db2d1667c4de1c39285e52047002ea071a25906390a9156429`
- Recorded record SHA256: `efa5013f20c3b02dee740a25fd2a6c57275f087f0f9aff6014d37f75697a557d`
- Computed record SHA256: `efa5013f20c3b02dee740a25fd2a6c57275f087f0f9aff6014d37f75697a557d`

### Line 3 — milestone_record

- Milestone: `O2_growth_freeze`
- Release candidate: `None`
- Entry OK: **YES**
- Declared link mode: `entry_sha256`
- Resolved link mode: `entry_sha256`
- Record path: `artifacts/audit/milestone_records/O2_growth_freeze/signed_milestone_record.json`
- Recorded entry SHA256: `59ca75ba79fcfe45cf04e3833c9cf5058aad7949dc23b2818e612dcc07f15ffb`
- Computed entry SHA256: `59ca75ba79fcfe45cf04e3833c9cf5058aad7949dc23b2818e612dcc07f15ffb`
- Recorded previous entry SHA256: `b1796898db1db09d86c5cca8ffbfbae2143012bed20a4f9014e7073a5ab271a2`
- Expected previous entry SHA256: `b1796898db1db09d86c5cca8ffbfbae2143012bed20a4f9014e7073a5ab271a2`
- Expected previous raw-line SHA256: `2b6ad9f37ad524b4ef6f0df182920c8256c39c592b18c39917cfdd3bdee69e29`
- Recorded record SHA256: `fff45ffae8fe17f52d19405754b63e0138fb5fdc34801de2faf6aabeb62242f2`
- Computed record SHA256: `fff45ffae8fe17f52d19405754b63e0138fb5fdc34801de2faf6aabeb62242f2`
