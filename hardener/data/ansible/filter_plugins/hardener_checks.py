"""Read-only interpretation of the configuration needed by the M2 controls."""

import configparser
import fnmatch
from pathlib import PurePosixPath

KEY = "fs/protected_hardlinks"
MANAGED = "99-rocky10-hardener.conf"


def sysctl_state(text):
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
            if line.lstrip("-").replace(".", "/") == KEY:
                excluded = True
            continue
        name, value = (part.strip() for part in line.split("=", 1))
        name = name.lstrip("-").replace(".", "/")
        item = {"source": source, "value": value}
        if name == KEY:
            explicit.append(item)
        elif fnmatch.fnmatchcase(KEY, name):
            globbed.append(item)
    effective = explicit or ([] if excluded else globbed)
    blockers = [
        entry["source"]
        for entry in explicit
        if PurePosixPath(entry["source"]).name > MANAGED and entry["value"] != "1"
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


class FilterModule:
    def filters(self):
        return {"hardener_sysctl_state": sysctl_state, "hardener_dnf_editable": dnf_editable}
