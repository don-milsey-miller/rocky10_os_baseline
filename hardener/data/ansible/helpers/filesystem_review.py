"""Bounded local metadata reviews. No file contents or automatic repairs."""

import grp
import json
import os
import pwd
import stat
import subprocess
import sys
import time
from pathlib import Path

LOCAL_TYPES = {"xfs", "ext4", "tmpfs"}
KINDS = {"world-writable-review", "unowned-files-review", "privileged-files-review"}


def canonical_scope(value):
    path = Path(value)
    if not path.is_absolute() or str(path) != value or ".." in path.parts:
        raise ValueError("Use canonical absolute scan directories")
    if path.resolve(strict=True) != path or not path.is_dir():
        raise ValueError("Scan directories must exist without symbolic links")
    return path


def unsafe_metadata(kind, info, capability, known_uids, known_gids, approved=False):
    if kind == "world-writable-review":
        return (
            not stat.S_ISLNK(info.st_mode)
            and bool(info.st_mode & 0o002)
            and (not stat.S_ISDIR(info.st_mode) or not info.st_mode & stat.S_ISVTX)
        )
    if kind == "unowned-files-review":
        return info.st_uid not in known_uids or info.st_gid not in known_gids
    if kind == "privileged-files-review":
        return (
            stat.S_ISREG(info.st_mode)
            and (bool(info.st_mode & 0o6000) or capability)
            and not approved
        )
    raise ValueError("Unknown metadata review")


def assess(kind, parameters):
    if kind not in KINDS:
        raise ValueError("Unknown review")
    roots = [canonical_scope(value) for value in parameters["paths"]]
    if len(set(roots)) != len(roots) or any(a in b.parents for a in roots for b in roots if a != b):
        raise ValueError("Scan directories must not overlap")
    approved = set(parameters.get("approved_paths", []))
    uids, gids = set(), set()
    unknown_uids, unknown_gids = set(), set()
    count, findings, boundaries = 0, [], 0
    deadline = time.monotonic() + 30
    for root in roots:
        result = subprocess.run(
            ["findmnt", "-J", "-T", str(root), "-o", "FSTYPE"],
            capture_output=True,
            text=True,
            check=True,
            timeout=10,
        )
        if json.loads(result.stdout)["filesystems"][0]["fstype"] not in LOCAL_TYPES:
            raise ValueError("Only supported local filesystems may be scanned")
        device = root.stat().st_dev
        pending = [root]
        while pending:
            path = pending.pop()
            if time.monotonic() > deadline or count >= parameters["max_entries"]:
                raise ValueError(
                    "Scan limit reached. Narrow scope or raise the explicit entry limit"
                )
            info = path.lstat()
            if info.st_dev != device:
                boundaries += 1
                continue
            count += 1
            if kind == "unowned-files-review":
                for value, known, unknown, lookup in (
                    (info.st_uid, uids, unknown_uids, pwd.getpwuid),
                    (info.st_gid, gids, unknown_gids, grp.getgrgid),
                ):
                    if value not in known and value not in unknown:
                        try:
                            lookup(value)
                            known.add(value)
                        except KeyError:
                            unknown.add(value)
            capability = False
            if kind == "privileged-files-review" and stat.S_ISREG(info.st_mode):
                capability = "security.capability" in os.listxattr(path, follow_symlinks=False)
            if unsafe_metadata(kind, info, capability, uids, gids, str(path) in approved):
                findings.append(str(path))
            if stat.S_ISDIR(info.st_mode):
                # os.walk would suppress traversal errors by default.
                with os.scandir(path) as entries:
                    for entry in entries:
                        if count + len(pending) >= parameters["max_entries"]:
                            raise ValueError(
                                "Scan limit reached. Narrow scope or raise the explicit entry limit"
                            )
                        pending.append(Path(entry.path))
    return {
        "matches": not findings,
        "entries_checked": count,
        "mount_boundaries_skipped": boundaries,
        "finding_count": len(findings),
        "finding_paths": sorted(findings)[:40],
        "findings_truncated": len(findings) > 40,
        "scope": [str(root) for root in roots],
    }


def main():
    try:
        print(json.dumps(assess(sys.argv[1], json.loads(sys.argv[2]))))
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        # Inspection failures are execution errors, never empty successful scans.
        print(
            json.dumps(
                {
                    "error": "Incomplete metadata inspection. Check scope, permissions and scan limits."
                }
            )
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
