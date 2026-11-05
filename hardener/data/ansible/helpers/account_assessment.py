"""Assess local identities without exposing authentication material."""

import json
import os
import stat
import subprocess
import sys
from collections import Counter
from pathlib import Path


def records(text, fields):
    rows = [row.split(":") for row in text.splitlines() if row]
    if any(len(row) != fields or not row[0] for row in rows):
        raise ValueError("Malformed local identity database")
    return rows


def duplicates(values):
    return sum(n - 1 for n in Counter(values).values() if n > 1)


def assess(kind, passwd, group, shadow):
    users, groups, secrets = records(passwd, 7), records(group, 4), records(shadow, 9)
    uids, gids = [int(r[2]) for r in users], [int(r[2]) for r in groups]
    if any(n < 0 for n in uids + gids):
        raise ValueError("Invalid identity number")
    if kind == "unique-identities":
        result = {
            "duplicate_user_names": duplicates([r[0] for r in users]),
            "duplicate_uids": duplicates(uids),
            "duplicate_group_names": duplicates([r[0] for r in groups]),
            "duplicate_gids": duplicates(gids),
            "duplicate_shadow_names": duplicates([r[0] for r in secrets]),
        }
        return {"matches": not any(result.values()), **result}
    if kind == "root-only-uid-zero":
        result = {
            "root_records": sum(r[0] == "root" and int(r[2]) == 0 for r in users),
            "other_uid_zero": sum(r[0] != "root" and int(r[2]) == 0 for r in users),
        }
        return {"matches": result == {"root_records": 1, "other_uid_zero": 0}, **result}
    if kind == "no-empty-passwords":
        names = {r[0] for r in users}
        result = {
            "empty_password_records": sum(not r[1] for r in secrets if r[0] in names),
            "empty_passwd_fields": sum(not r[1] for r in users),
            "missing_shadow_records": len(names - {r[0] for r in secrets}),
            "duplicate_shadow_names": duplicates([r[0] for r in secrets]),
        }
        return {"matches": not any(result.values()), **result}
    raise ValueError("Unknown assessment")


def path_integrity(value, inspect=None):
    inspect = inspect or (lambda p: p.stat())
    entries, unsafe = value.split(":"), 0
    for entry in entries:
        path = Path(entry)
        if not entry or not path.is_absolute():
            unsafe += 1
            continue
        try:
            resolved = path.resolve(strict=True)
            for candidate in {path, resolved, *resolved.parents, *path.parents}:
                info = inspect(candidate)
                if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                    raise ValueError("Unsafe command search directory")
        except (OSError, ValueError):
            unsafe += 1
    return {"matches": unsafe == 0, "path_entries": len(entries), "unsafe_path_entries": unsafe}


def main():
    kind = sys.argv[1]
    if kind == "root-path-integrity":
        result = subprocess.run(
            ["/usr/bin/su", "--login", "root", "--command", "/usr/bin/env -0"],
            capture_output=True,
            check=True,
            timeout=15,
            env={**os.environ, "LC_ALL": "C"},
        )
        values = [r[5:].decode() for r in result.stdout.split(b"\0") if r.startswith(b"PATH=")]
        if len(values) != 1:
            raise ValueError("Root login PATH unavailable")
        evidence = path_integrity(values[0])
    else:
        evidence = assess(
            kind,
            Path("/etc/passwd").read_text(),
            Path("/etc/group").read_text(),
            Path("/etc/shadow").read_text(),
        )
    print(json.dumps(evidence))


if __name__ == "__main__":
    main()
