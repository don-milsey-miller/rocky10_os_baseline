"""Read-only interpretation of the configuration needed by the M2 controls."""

import configparser
import fnmatch
import re
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


def repository_edit(text, repositories, path, option):
    """Edit only one boolean option in explicit sections, preserving other text."""
    if option not in {"gpgcheck", "repo_gpgcheck", "sslverify"}:
        raise ValueError("Unsupported repository option")
    parser = configparser.ConfigParser(interpolation=None, strict=True)
    parser.read_string(text)
    if parser.defaults():
        raise ValueError("Inherited repository defaults are ambiguous")
    sections = {r["id"] for r in repositories if r["path"] == path}
    if not sections <= set(parser.sections()):
        raise ValueError("Repository section missing")
    lines = text.splitlines(keepends=True)
    for section in sorted(sections):
        start = next(
            i
            for i, line in enumerate(lines)
            if re.fullmatch(r"\s*\[" + re.escape(section) + r"\]\s*(?:[#;].*)?", line.strip())
        )
        end = next(
            (i for i in range(start + 1, len(lines)) if re.match(r"\s*\[", lines[i])), len(lines)
        )
        matches = [
            i
            for i in range(start + 1, end)
            if re.match(r"\s*" + re.escape(option) + r"\s*=", lines[i], re.IGNORECASE)
        ]
        if len(matches) > 1:
            raise ValueError("Ambiguous repository option")
        if matches:
            lines[matches[0]] = option + "=True\n"
        else:
            if not lines[start].endswith("\n"):
                lines[start] += "\n"
            lines.insert(start + 1, option + "=True\n")
    return "".join(lines)


def chrony_edit(text, policy):
    """Replace only source selection, preserving unrelated clock configuration."""
    lines = []
    for line in text.splitlines(keepends=True):
        words = line.split()
        if words and words[0] in {"include", "confdir", "refclock"}:
            raise ValueError("Unsupported chrony source configuration")
        if words and words[0] in {"server", "pool", "peer", "sourcedir"}:
            continue
        lines.append(line)
    result = "".join(lines)
    if result and not result.endswith("\n"):
        result += "\n"
    return result + "".join(
        f"{policy['source_type']} {source} iburst\n" for source in policy["sources"]
    )


def rotation_policy(policy):
    """Render a fixed directive vocabulary. No profile-supplied scripts."""
    lines = [
        " ".join(policy["paths"]) + " {",
        "    " + policy["frequency"],
        "    rotate " + str(policy["retain"]),
        "    missingok",
        "    notifempty",
        "    compress",
        "    delaycompress",
        "    create " + policy["mode"],
    ]
    if policy["reopen"] == "rsyslog":
        lines += [
            "    sharedscripts",
            "    postrotate",
            "        /usr/bin/systemctl kill --kill-whom=main -s HUP rsyslog.service",
            "    endscript",
        ]
    return "\n".join(lines + ["}", ""])


class FilterModule:
    def filters(self):
        return {
            "hardener_sysctl_state": sysctl_state,
            "hardener_dnf_editable": dnf_editable,
            "hardener_backup_state": backup_state,
            "hardener_repository_edit": repository_edit,
            "hardener_chrony_edit": chrony_edit,
            "hardener_rotation_policy": rotation_policy,
        }
