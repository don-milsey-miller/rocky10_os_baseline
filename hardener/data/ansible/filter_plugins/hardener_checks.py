"""Read-only interpretation of the configuration needed by the M2 controls."""

import configparser
import fnmatch
from pathlib import PurePosixPath

KEY = "fs/protected_hardlinks"
MANAGED = "99-rocky10-hardener.conf"


def sysctl_state(text, key=KEY, desired="1"):
    key = key.replace(".", "/")
    """Interpret systemd's already ordered and shadow-resolved --cat-config output."""
    source = ""
    explicit = []
    globbed = []
    excluded = False
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("# /"):
            source = line[2:].strip()
        if not line or line.startswith(("#", ";")):
            continue
        if "=" not in line:
            if line.lstrip("-").replace(".", "/") == key:
                excluded = True
            continue
        name, value = (part.strip() for part in line.split("=", 1))
        name = name.lstrip("-").replace(".", "/")
        item = {"source": source, "value": value}
        if name == key:
            explicit.append(item)
        elif fnmatch.fnmatchcase(key, name):
            globbed.append(item)
    effective = explicit or ([] if excluded else globbed)
    blockers = [
        entry["source"]
        for entry in explicit
        if PurePosixPath(entry["source"]).name > MANAGED and entry["value"] != str(desired)
    ]
    return {
        "persistent": effective[-1]["value"] if effective else None,
        "blockers": sorted(set(blockers)),
    }


def dnf_editable(text):
    """Refuse ambiguous input before lineinfile can edit the wrong section."""
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    try:
        parser.read_string(text)
    except configparser.Error:
        return False
    if "main" not in parser or parser.defaults():
        return False
    return not any(
        "localpkg_gpgcheck" in parser[section] for section in parser.sections() if section != "main"
    )


def backup_state(results):
    """Expose metadata only. Missing standard backups are not invented."""
    state = []
    for item in results:
        info = item["stat"]
        if not info.get("exists"):
            continue
        state.append(
            {
                "path": item["backup"]["path"],
                "uid": info.get("uid"),
                "gid": info.get("gid"),
                "mode": info.get("mode"),
                "ok": bool(
                    info.get("isreg")
                    and info.get("nlink") == 1
                    and info.get("uid") == 0
                    and info.get("gid") == 0
                    and info.get("mode") == item["backup"]["mode"]
                ),
            }
        )
    return state


class FilterModule:
    def filters(self):
        return {
            "hardener_sysctl_state": sysctl_state,
            "hardener_dnf_editable": dnf_editable,
            "hardener_backup_state": backup_state,
        }
