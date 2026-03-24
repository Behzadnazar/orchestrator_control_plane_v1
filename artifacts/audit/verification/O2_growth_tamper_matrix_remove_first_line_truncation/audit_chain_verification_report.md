# Immutable Audit Chain Verification Report

- Generated at (UTC): `2026-03-20T10:26:46+00:00`
- Index path: `artifacts/audit/immutable_audit_index.jsonl`
- Overall status: **FAIL**
- Legacy raw-line links allowed: **False**
- Contract rule: `previous_entry_sha256 must equal previous entry's entry_sha256`
- Total entries: **3**
- OK entries: **2**
- Failed entries: **1**
- Output directory: `artifacts/audit/verification/O2_growth_tamper_matrix_remove_first_line_truncation`

## Entry Matrix

| Line | Type | Milestone | RC | Entry Hash | Previous Link | Link Mode | Record Exists | Record SHA256 | Entry OK |
|---:|---|---|---|---|---|---|---|---|---|
| 1 | release_candidate_record | M1_freeze_gate | RC1 | OK | FAIL | entry_sha256 | OK | OK | FAIL |
| 2 | milestone_record | O2_growth_freeze | None | OK | OK | entry_sha256 | OK | OK | OK |
| 3 | release_candidate_record | O2_growth_freeze | RC2 | OK | OK | entry_sha256 | OK | OK | OK |

## Detailed Results

### Line 1 — release_candidate_record

- Milestone: `M1_freeze_gate`
- Release candidate: `RC1`
- Entry OK: **NO**
- Declared link mode: `entry_sha256`
- Resolved link mode: `entry_sha256`
- Record path: `artifacts/audit/release_candidate_records/RC1/release_candidate_record.json`
- Recorded entry SHA256: `b1796898db1db09d86c5cca8ffbfbae2143012bed20a4f9014e7073a5ab271a2`
- Computed entry SHA256: `b1796898db1db09d86c5cca8ffbfbae2143012bed20a4f9014e7073a5ab271a2`
- Recorded previous entry SHA256: `5bed7697e5ecbb6d5efd87a660135425ff0016df82cdbc8a33eae4550cc846ad`
- Expected previous entry SHA256: `None`
- Expected previous raw-line SHA256: `None`
- Recorded record SHA256: `efa5013f20c3b02dee740a25fd2a6c57275f087f0f9aff6014d37f75697a557d`
- Computed record SHA256: `efa5013f20c3b02dee740a25fd2a6c57275f087f0f9aff6014d37f75697a557d`

### Line 2 — milestone_record

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
- Expected previous raw-line SHA256: `b15f02f05bd38dad9c2852f33a77bdc0b56207dea92bc5a66b0a9243399d1735`
- Recorded record SHA256: `fff45ffae8fe17f52d19405754b63e0138fb5fdc34801de2faf6aabeb62242f2`
- Computed record SHA256: `fff45ffae8fe17f52d19405754b63e0138fb5fdc34801de2faf6aabeb62242f2`

### Line 3 — release_candidate_record

- Milestone: `O2_growth_freeze`
- Release candidate: `RC2`
- Entry OK: **YES**
- Declared link mode: `entry_sha256`
- Resolved link mode: `entry_sha256`
- Record path: `artifacts/audit/release_candidate_records/RC2/release_candidate_record.json`
- Recorded entry SHA256: `b9b7801437f2f2f14c9d90a233795a8f81ace73f6cb3edda1c77d105d2b6c871`
- Computed entry SHA256: `b9b7801437f2f2f14c9d90a233795a8f81ace73f6cb3edda1c77d105d2b6c871`
- Recorded previous entry SHA256: `59ca75ba79fcfe45cf04e3833c9cf5058aad7949dc23b2818e612dcc07f15ffb`
- Expected previous entry SHA256: `59ca75ba79fcfe45cf04e3833c9cf5058aad7949dc23b2818e612dcc07f15ffb`
- Expected previous raw-line SHA256: `855f1d74d553a6ecfc2f341c4a6171bafb69ab0725581deaabba5014efd2e168`
- Recorded record SHA256: `d4f549ab41b29a45f9f9c72f80eef661efabbfa885dbdc993fc0310fecdaba75`
- Computed record SHA256: `d4f549ab41b29a45f9f9c72f80eef661efabbfa885dbdc993fc0310fecdaba75`
