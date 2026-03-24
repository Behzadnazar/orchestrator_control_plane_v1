# Immutable Audit Chain Verification Report

- Generated at (UTC): `2026-03-20T10:30:29+00:00`
- Index path: `artifacts/audit/immutable_audit_index.jsonl`
- Overall status: **FAIL**
- Legacy raw-line links allowed: **False**
- Contract rule: `previous_entry_sha256 must equal previous entry's entry_sha256`
- Total entries: **5**
- OK entries: **4**
- Failed entries: **1**
- Output directory: `artifacts/audit/verification/O3_independent_tamper_matrix_remove_first_line_truncation`

## Entry Matrix

| Line | Type | Milestone | RC | Entry Hash | Previous Link | Link Mode | Record Exists | Record SHA256 | Entry OK |
|---:|---|---|---|---|---|---|---|---|---|
| 1 | release_candidate_record | M1_freeze_gate | RC1 | OK | FAIL | entry_sha256 | OK | OK | FAIL |
| 2 | milestone_record | O2_growth_freeze | None | OK | OK | entry_sha256 | OK | OK | OK |
| 3 | release_candidate_record | O2_growth_freeze | RC2 | OK | OK | entry_sha256 | OK | OK | OK |
| 4 | milestone_record | O3_independent_freeze | None | OK | OK | entry_sha256 | OK | OK | OK |
| 5 | release_candidate_record | O3_independent_freeze | RC3 | OK | OK | entry_sha256 | OK | OK | OK |

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

### Line 4 — milestone_record

- Milestone: `O3_independent_freeze`
- Release candidate: `None`
- Entry OK: **YES**
- Declared link mode: `entry_sha256`
- Resolved link mode: `entry_sha256`
- Record path: `artifacts/audit/milestone_records/O3_independent_freeze/signed_milestone_record.json`
- Recorded entry SHA256: `fb88bea11982596ec2bd84da385ed177d1ee656f86ba0ba4fc31741f43b95b51`
- Computed entry SHA256: `fb88bea11982596ec2bd84da385ed177d1ee656f86ba0ba4fc31741f43b95b51`
- Recorded previous entry SHA256: `b9b7801437f2f2f14c9d90a233795a8f81ace73f6cb3edda1c77d105d2b6c871`
- Expected previous entry SHA256: `b9b7801437f2f2f14c9d90a233795a8f81ace73f6cb3edda1c77d105d2b6c871`
- Expected previous raw-line SHA256: `1ad14a140eeb336bc5dc01a80f4f116463f751f5f2a3a646db9d9074dfe29538`
- Recorded record SHA256: `efc0ad96005cdb35e0fbd4b5fa70bacae6a04630ca37671f38495589f9e95553`
- Computed record SHA256: `efc0ad96005cdb35e0fbd4b5fa70bacae6a04630ca37671f38495589f9e95553`

### Line 5 — release_candidate_record

- Milestone: `O3_independent_freeze`
- Release candidate: `RC3`
- Entry OK: **YES**
- Declared link mode: `entry_sha256`
- Resolved link mode: `entry_sha256`
- Record path: `artifacts/audit/release_candidate_records/RC3/release_candidate_record.json`
- Recorded entry SHA256: `bfabe5d6afa1b2970006e3dc3589788108430204b47febf0c2d76a52abf4df37`
- Computed entry SHA256: `bfabe5d6afa1b2970006e3dc3589788108430204b47febf0c2d76a52abf4df37`
- Recorded previous entry SHA256: `fb88bea11982596ec2bd84da385ed177d1ee656f86ba0ba4fc31741f43b95b51`
- Expected previous entry SHA256: `fb88bea11982596ec2bd84da385ed177d1ee656f86ba0ba4fc31741f43b95b51`
- Expected previous raw-line SHA256: `c2f69e024f6ad13bb2d510ba38e08f3b860b3aba3b4fc7d7c18a613a416d25da`
- Recorded record SHA256: `a58c3be2e80cd7b956ec6a20c1368af21c718e5813c21b9b14c40d7dedc8e318`
- Computed record SHA256: `a58c3be2e80cd7b956ec6a20c1368af21c718e5813c21b9b14c40d7dedc8e318`
