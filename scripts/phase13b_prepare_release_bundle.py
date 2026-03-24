#!/usr/bin/env python3
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "config/phase13b_github_real.json"
BUILD_DIR = ROOT / "artifacts/phase13b_real/build"
DIST_DIR = ROOT / "dist"

BUILD_DIR.mkdir(parents=True, exist_ok=True)
DIST_DIR.mkdir(parents=True, exist_ok=True)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_config() -> dict:
    return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))


def matches_any(rel_path: str, globs: Iterable[str]) -> bool:
    return any(fnmatch.fnmatch(rel_path, pattern) for pattern in globs)


def iter_files(include_paths: list[str], exclude_globs: list[str]) -> list[Path]:
    collected: list[Path] = []
    for item in include_paths:
        p = ROOT / item
        if not p.exists():
            raise FileNotFoundError(f"missing include path: {p}")
        if p.is_file():
            rel = str(p.relative_to(ROOT))
            if not matches_any(rel, exclude_globs):
                collected.append(p)
            continue
        for path in sorted(p.rglob("*")):
            if not path.is_file():
                continue
            rel = str(path.relative_to(ROOT))
            if matches_any(rel, exclude_globs):
                continue
            collected.append(path)
    unique = sorted({str(p): p for p in collected}.values(), key=lambda x: str(x.relative_to(ROOT)))
    return unique


def make_manifest(files: list[Path]) -> list[dict]:
    items = []
    for path in files:
        rel = str(path.relative_to(ROOT))
        items.append({
            "path": rel,
            "sha256": sha256_file(path),
            "bytes": path.stat().st_size
        })
    return items


def write_manifest(manifest: list[dict]) -> None:
    out = {
        "generated_at": utc_now(),
        "files_count": len(manifest),
        "files": manifest
    }
    (BUILD_DIR / "bundle_manifest.json").write_text(
        json.dumps(out, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )


def build_tarball(files: list[Path], target: Path) -> None:
    with tarfile.open(target, "w:gz", compresslevel=9) as tar:
        for path in files:
            rel = str(path.relative_to(ROOT))
            info = tar.gettarinfo(str(path), arcname=rel)
            info.uid = 0
            info.gid = 0
            info.uname = "root"
            info.gname = "root"
            info.mtime = 0
            with path.open("rb") as f:
                tar.addfile(info, f)


def build_spdx_json(manifest: list[dict], bundle_name: str) -> dict:
    created = utc_now().replace("+00:00", "Z")
    document_namespace = f"https://spdx.example.invalid/{bundle_name}-{created}"
    files = []
    relationships = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": "SPDXRef-Package-bundle"
        }
    ]

    for idx, item in enumerate(manifest, start=1):
        spdx_id = f"SPDXRef-File-{idx:05d}"
        files.append({
            "SPDXID": spdx_id,
            "fileName": item["path"],
            "checksums": [
                {
                    "algorithm": "SHA256",
                    "checksumValue": item["sha256"]
                }
            ]
        })
        relationships.append({
            "spdxElementId": "SPDXRef-Package-bundle",
            "relationshipType": "CONTAINS",
            "relatedSpdxElement": spdx_id
        })

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": bundle_name,
        "documentNamespace": document_namespace,
        "creationInfo": {
            "created": created,
            "creators": [
                "Tool: phase13b_prepare_release_bundle.py"
            ]
        },
        "packages": [
            {
                "name": bundle_name,
                "SPDXID": "SPDXRef-Package-bundle",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "supplier": "NOASSERTION"
            }
        ],
        "files": files,
        "relationships": relationships
    }


def write_release_notes(bundle_name: str, manifest: list[dict]) -> None:
    notes = [
        f"# {bundle_name}",
        "",
        f"- generated_at: {utc_now()}",
        f"- files_count: {len(manifest)}",
        "",
        "## Included roots",
        "",
    ]
    cfg = load_config()
    for item in cfg["release_bundle"]["include_paths"]:
        notes.append(f"- {item}")
    notes.append("")
    notes.append("## Security posture")
    notes.append("")
    notes.append("- bundle tarball generated deterministically")
    notes.append("- SHA256 written alongside tarball")
    notes.append("- SPDX JSON generated for SBOM attestation")
    notes.append("- intended for GitHub artifact provenance + SBOM attestation workflow")
    notes.append("")
    (DIST_DIR / "phase13b-release-notes.md").write_text("\n".join(notes), encoding="utf-8")


def write_summary(bundle_path: Path, manifest: list[dict], spdx_path: Path, sha_path: Path) -> None:
    summary = {
        "ok": True,
        "generated_at": utc_now(),
        "bundle_path": str(bundle_path.relative_to(ROOT)),
        "bundle_sha256": sha256_file(bundle_path),
        "bundle_bytes": bundle_path.stat().st_size,
        "manifest_path": str((BUILD_DIR / "bundle_manifest.json").relative_to(ROOT)),
        "sbom_path": str(spdx_path.relative_to(ROOT)),
        "sha256_path": str(sha_path.relative_to(ROOT)),
        "files_count": len(manifest)
    }
    (BUILD_DIR / "build_summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )


def verify_only() -> None:
    cfg = load_config()
    files = iter_files(cfg["release_bundle"]["include_paths"], cfg["release_bundle"]["exclude_globs"])
    result = {
        "ok": True,
        "generated_at": utc_now(),
        "files_count": len(files),
        "first_files": [str(p.relative_to(ROOT)) for p in files[:20]]
    }
    print(json.dumps(result, indent=2, ensure_ascii=False))


def build() -> None:
    cfg = load_config()
    files = iter_files(cfg["release_bundle"]["include_paths"], cfg["release_bundle"]["exclude_globs"])
    manifest = make_manifest(files)
    write_manifest(manifest)

    bundle_name = "phase13b-release-bundle"
    bundle_path = DIST_DIR / f"{bundle_name}.tar.gz"
    sha_path = DIST_DIR / f"{bundle_name}.sha256"
    spdx_path = DIST_DIR / f"{bundle_name}.spdx.json"

    build_tarball(files, bundle_path)
    bundle_sha = sha256_file(bundle_path)
    sha_path.write_text(f"{bundle_sha}  {bundle_path.name}\n", encoding="utf-8")

    spdx_doc = build_spdx_json(manifest, bundle_name)
    spdx_path.write_text(json.dumps(spdx_doc, indent=2, ensure_ascii=False), encoding="utf-8")

    write_release_notes(bundle_name, manifest)
    write_summary(bundle_path, manifest, spdx_path, sha_path)

    print(json.dumps({
        "ok": True,
        "generated_at": utc_now(),
        "bundle_path": str(bundle_path.relative_to(ROOT)),
        "bundle_sha256": bundle_sha,
        "files_count": len(manifest),
        "sbom_path": str(spdx_path.relative_to(ROOT))
    }, indent=2, ensure_ascii=False))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()

    if args.verify_only:
        verify_only()
    else:
        build()


if __name__ == "__main__":
    main()
