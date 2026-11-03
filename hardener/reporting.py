"""Stable, deliberately small report contract."""

import hashlib
import json
import uuid
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

from hardener import __version__
from hardener.validation import DATA

STATUSES = ("pass", "fail", "not_applicable", "error", "excluded", "unsupported", "skipped")


def source_digest():
    digest = hashlib.sha256()
    root = DATA.parent
    for path in sorted(root.rglob("*")):
        if path.is_file() and path.suffix in {".py", ".yml", ".yaml", ".json", ".cfg"}:
            digest.update(str(path.relative_to(root)).encode())
            digest.update(path.read_bytes())
    return digest.hexdigest()


def make_report(mode, target, profile, profile_digest, catalog, evidence):
    records = []
    for item in profile["controls"]:
        cid = item["id"]
        if not item["enabled"]:
            record = {
                "id": cid,
                "status": "excluded",
                "observed": None,
                "expected": catalog[cid]["summary"],
                "changed": False,
                "reason": item.get("reason", "Explicitly excluded"),
                "reboot_required": False,
            }
        elif mode == "preflight" and evidence.get("preflight_passed"):
            record = {
                "id": cid,
                "status": "skipped",
                "observed": None,
                "expected": catalog[cid]["summary"],
                "changed": False,
                "reason": "Preflight only. Control state was not assessed.",
                "reboot_required": False,
            }
        else:
            record = evidence.get("records", {}).get(cid)
            if not record:
                record = {
                    "id": cid,
                    "status": "error",
                    "observed": None,
                    "expected": catalog[cid]["summary"],
                    "changed": None if mode == "apply" else False,
                    "reason": "No control evidence. Preflight or execution did not complete.",
                    "reboot_required": catalog[cid]["reboot_required"],
                }
        records.append(record)
    counts = Counter(r["status"] for r in records)
    return {
        "report_schema_version": 1,
        "run_id": str(uuid.uuid4()),
        "timestamp_utc": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "mode": mode,
        "target": target,
        "platform": "rocky-10-server" if evidence.get("preflight_passed") else "unverified",
        "profile_id": profile["id"],
        "profile_revision": profile["revision"],
        "profile_sha256": profile_digest,
        "engine_version": __version__,
        "engine_sha256": source_digest(),
        "catalog_version": __version__,
        "preflight_passed": evidence.get("preflight_passed", False),
        "changed_tasks": evidence.get("changed_tasks", 0),
        "summary": {s: counts[s] for s in STATUSES},
        "controls": records,
        "errors": evidence.get("errors", []),
    }


def write_report(report, output):
    directory = Path(output)
    directory.mkdir(parents=True, exist_ok=True)
    text = [
        f"{report['mode']} {report['target']}",
        f"preflight_passed={report['preflight_passed']} changed_tasks={report['changed_tasks']}",
    ]
    text += [
        f"{r['id']}: {r['status']} changed={r['changed']} "
        f"evidence={r['observed']} reason={r['reason']}"
        for r in report["controls"]
    ]
    text += [f"error: {e['task']} ({e['kind']})" for e in report["errors"]]
    summary = "\n".join(text) + "\n"
    (directory / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    (directory / "summary.txt").write_text(summary)
    return summary


def exit_code(evidence, report, process_code):
    if any(e.get("kind") == "execution" for e in evidence.get("errors", [])):
        return 4
    if not evidence.get("preflight_passed"):
        return 3
    if process_code or evidence.get("errors") or report["summary"]["error"]:
        return 4
    if report["summary"]["fail"]:
        return 5
    return 0
