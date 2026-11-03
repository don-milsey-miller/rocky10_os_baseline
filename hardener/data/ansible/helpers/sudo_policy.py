"""Validate local sudo policy without expanding existing administrative grants."""

import json
import os
import pwd
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

MAIN = Path("/etc/sudoers")
DROP = Path("/etc/sudoers.d")
NAMES = {
    "pty": "99-rocky10-hardener-pty",
    "timeout": "99-rocky10-hardener-timeout",
}


def run(argv):
    return subprocess.run(
        argv,
        check=False,
        capture_output=True,
        text=True,
        timeout=15,
        env={**os.environ, "LC_ALL": "C"},
    )


def metadata(path):
    info = path.lstat()
    safe = path.resolve() == path and stat.S_ISREG(info.st_mode) and info.st_nlink == 1
    safe &= "system.posix_acl_access" not in os.listxattr(path, follow_symlinks=False)
    mode = format(stat.S_IMODE(info.st_mode), "04o")
    return {
        "path": str(path),
        "safe": bool(safe),
        "uid": info.st_uid,
        "gid": info.st_gid,
        "mode": mode,
        "matches": safe and info.st_uid == 0 and info.st_gid == 0 and mode == "0440",
    }


def active_lines(text):
    return [
        line.strip()
        for line in text.splitlines()
        if line.strip()
        and (
            not line.lstrip().startswith("#")
            or line.lstrip().startswith(("#include", "#includedir"))
        )
    ]


def plugin_configuration_supported(text):
    permitted = {
        "Plugin sudoers_policy sudoers.so",
        "Plugin sudoers_io sudoers.so",
        "Plugin sudoers_audit sudoers.so",
        "Set disable_coredump true",
        "Set disable_coredump false",
    }
    return all(" ".join(row.split()) in permitted for row in active_lines(text))


def sources_supported(text):
    for line in text.splitlines():
        row = line.split("#", 1)[0].strip()
        match = re.match(r"^sudoers\s*:\s*(.*)$", row)
        if match and match[1].strip() != "files":
            return False
    return True


def layout(content):
    rows = active_lines(content[MAIN])
    includes = [row for row in rows if row.startswith(("#include", "@include"))]
    if len(includes) != 1 or includes[0] not in (
        "#includedir /etc/sudoers.d",
        "@includedir /etc/sudoers.d",
    ):
        return False
    if rows[-1] != includes[0]:
        return False
    for path, text in content.items():
        if path != MAIN and any(
            row.startswith(("#include", "@include")) for row in active_lines(text)
        ):
            return False
    sudo_conf = Path("/etc/sudo.conf")
    if sudo_conf.exists() and not plugin_configuration_supported(sudo_conf.read_text()):
        return False
    return sources_supported(Path("/etc/nsswitch.conf").read_text())


def native(path, user=None):
    args = ["/usr/bin/cvtsudoers", "-c", "/dev/null", "-e", "-f", "json"]
    if user:
        args += ["-M", "-p", "-m", "user=" + user]
    result = run(args + [str(path)])
    result.check_returncode()
    return json.loads(result.stdout)


def user_state(document):
    """Support only existing unrestricted ALL=(ALL) ALL local admin grants.

    This excludes command denials, additional tags, host/runas restrictions, and
    nonstandard authentication defaults. Existing direct grants are only retagged.
    """
    defaults = {"authenticate": True, "timestamp_timeout": None}
    supported = True
    for item in document.get("Defaults", []):
        for option in item["Options"]:
            relevant = set(option) & {
                "authenticate",
                "timestamp_timeout",
                "exempt_group",
                "rootpw",
                "targetpw",
                "runaspw",
                "group_plugin",
            }
            if relevant and any(
                not (set(binding) <= {"username", "usergroup"})
                for binding in item.get("Binding", [])
            ):
                supported = False
            for key in relevant:
                if (
                    key in {"exempt_group", "rootpw", "targetpw", "runaspw", "group_plugin"}
                    and option[key]
                ):
                    supported = False
                else:
                    defaults[key] = option[key]
    authenticated = None
    rules = document.get("User_Specs", [])
    supported &= bool(rules)
    for rule in rules:
        supported &= rule.get("Host_List") == [{"hostname": "ALL"}]
        supported &= all(
            len(item) == 1 and set(item) <= {"username", "usergroup"}
            for item in rule.get("User_List", [])
        )
        for command in rule.get("Cmnd_Specs", []):
            supported &= command.get("Commands") == [{"command": "ALL"}]
            supported &= command.get("runasusers") == [{"username": "ALL"}]
            supported &= "runasgroups" not in command
            supported &= set(command) <= {"Commands", "runasusers", "Options"}
            options = {
                key: value for item in command.get("Options", []) for key, value in item.items()
            }
            supported &= set(options) <= {"authenticate", "setenv"}
            supported &= options.get("setenv", True) is True
            authenticated = options.get("authenticate", defaults["authenticate"])
    return {
        "supported": bool(supported),
        "authenticated": authenticated is True,
        "timeout": defaults["timestamp_timeout"],
    }


def pty_state(document):
    value = None
    conflict = False
    for item in document.get("Defaults", []):
        for option in item["Options"]:
            if "use_pty" not in option:
                continue
            if item.get("Binding"):
                conflict |= option["use_pty"] is False
            else:
                value = option["use_pty"]
    return {"matches": value is True and not conflict, "scoped_conflict": bool(conflict)}


def edit(text, kind, parameters):
    """Preserve prior entries for unselected users in the managed policy file."""
    lines = []
    selected = set(parameters.get("users", []))
    for line in text.splitlines(keepends=True):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            lines.append(line)
            continue
        if kind == "pty":
            if stripped not in {"Defaults use_pty", "Defaults !use_pty"}:
                raise ValueError("Unexpected policy in managed PTY file")
            continue
        pattern = r"Defaults:([a-z_][a-z0-9_-]*[$]?)\s+timestamp_timeout=-?[0-9]+(?:\.[0-9]+)?"
        match = re.fullmatch(pattern, stripped)
        if not match:
            raise ValueError("Unexpected policy in managed user file")
        if match[1] not in selected:
            lines.append(line)
    output = "".join(lines)
    if output and not output.endswith("\n"):
        output += "\n"
    if kind == "pty":
        return output + "Defaults use_pty\n"
    for user in parameters["users"]:
        output += f"Defaults:{user} timestamp_timeout={parameters['minutes']}\n"
    return output


def authentication_edits(content, users):
    """Retag existing direct grants only. Never add a grant or copy group privileges."""
    result = dict(content)
    pattern = re.compile(
        r"^(\s*([a-z_][a-z0-9_-]*[$]?)\s+ALL\s*=\s*\(ALL\)\s*)"
        r"(?:(?:NO)?PASSWD:\s*)?ALL(\s*(?:#.*)?)$"
    )
    for path, text in content.items():
        output = []
        for line in text.splitlines(keepends=True):
            body = line.rstrip("\r\n")
            match = pattern.fullmatch(body)
            if match and match[2] in users:
                line = match[1] + "PASSWD: ALL" + match[3] + line[len(body) :]
            output.append(line)
        result[path] = "".join(output)
    return result


def inspect(kind, parameters, context, candidate=False):
    paths = [
        MAIN,
        *sorted(p for p in DROP.iterdir() if "." not in p.name and not p.name.endswith("~")),
    ]
    configuration_paths = paths + (
        [Path("/etc/sudo.conf")] if Path("/etc/sudo.conf").exists() else []
    )
    rows = [metadata(path) for path in configuration_paths]
    safe = all(row["safe"] for row in rows)
    safe &= DROP.resolve() == DROP and DROP.is_dir() and DROP.stat().st_uid == 0
    safe &= not (DROP.stat().st_mode & 0o022)
    if not safe:
        return {
            "safe": False,
            "layout_supported": False,
            "files": rows,
            "matches": False,
            "candidate_valid": False,
            "eligible": False,
            "users": [],
        }
    content = {path: path.read_text() for path in paths}
    supported = layout(content)
    full = native(MAIN)
    states = []
    eligible = True
    local_names = {line.split(":", 1)[0] for line in Path("/etc/passwd").read_text().splitlines()}
    for user in parameters.get("users", []):
        local = user in local_names and pwd.getpwnam(user).pw_uid != 0
        if not local or user == context["user"]:
            eligible = False
        state = (
            user_state(native(MAIN, user))
            if local
            else {"supported": False, "authenticated": False, "timeout": None}
        )
        states.append({"user": user, **state})
        eligible &= state["supported"]
    pty = pty_state(full)
    if kind == "authentication":
        compliant = bool(states) and all(
            state["supported"] and state["authenticated"] for state in states
        )
    elif kind == "timeout":
        compliant = bool(states) and all(
            state["supported"]
            and state["authenticated"]
            and state["timeout"] is not None
            and float(state["timeout"]) == parameters["minutes"]
            for state in states
        )
    elif kind == "pty":
        compliant = pty["matches"]
        eligible &= not pty["scoped_conflict"]
    else:
        compliant = all(row["matches"] for row in rows)
    result = {
        "safe": bool(safe),
        "layout_supported": supported,
        "files": rows,
        "matches": compliant,
        "eligible": bool(eligible),
        "users": states,
        "scoped_pty_conflict": pty["scoped_conflict"],
        "candidate_valid": False,
    }
    if candidate and supported and safe and eligible and kind in {*NAMES, "authentication"}:
        proposed_content = dict(content)
        if kind == "authentication":
            proposed_content = authentication_edits(content, parameters["users"])
        else:
            managed = DROP / NAMES[kind]
            proposed_content[managed] = edit(content.get(managed, ""), kind, parameters)
        with tempfile.TemporaryDirectory(prefix="hardener-sudo-") as temporary:
            root = Path(temporary)
            drop = root / "sudoers.d"
            drop.mkdir(mode=0o700)
            for path, text in proposed_content.items():
                if path != MAIN:
                    (drop / path.name).write_text(text)
                    (drop / path.name).chmod(0o440)
            main = root / "sudoers"
            main.write_text(proposed_content[MAIN].replace(str(DROP), str(drop)))
            main.chmod(0o440)
            valid = run(["/usr/sbin/visudo", "-c", "-f", str(main)]).returncode == 0
            if valid:
                if kind == "pty":
                    valid = pty_state(native(main))["matches"]
                else:
                    for user in parameters["users"]:
                        state = user_state(native(main, user))
                        valid &= state["supported"]
                        valid &= (
                            state["authenticated"]
                            if kind == "authentication"
                            else (
                                state["timeout"] is not None
                                and float(state["timeout"]) == parameters["minutes"]
                            )
                        )
            result["candidate_valid"] = bool(valid)
            if valid:
                if kind == "authentication":
                    result["candidates"] = [
                        {"path": str(path), "content": text}
                        for path, text in proposed_content.items()
                        if text != content[path]
                    ]
                else:
                    result["candidate"] = proposed_content[managed]
    return result


if __name__ == "__main__":
    print(
        json.dumps(
            inspect(
                sys.argv[1],
                json.loads(sys.argv[2]),
                json.loads(sys.argv[3]),
                sys.argv[4] == "candidate",
            )
        )
    )
