"""CLI coordinator. Profiles are data, inventory is trusted operator configuration."""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from hardener import recovery
from hardener.reporting import exit_code, make_report, write_report
from hardener.validation import (
    DATA,
    ValidationError,
    effective_parameters,
    load_catalog,
    load_profile,
    validate,
)


def run_command(argv, env, timeout=300):
    return subprocess.run(
        argv, check=False, capture_output=True, text=True, env=env, timeout=timeout
    )


def inventory_target(inventory, target, env):
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", target) or target in {"all", "ungrouped"}:
        raise ValidationError("Target must be one literal inventory host, never a pattern")
    inventory = Path(inventory).resolve()
    if not inventory.is_file():
        raise ValidationError("Explicit inventory file does not exist")
    result = run_command(["ansible-inventory", "-i", str(inventory), "--list"], env)
    try:
        hosts = json.loads(result.stdout)["_meta"]["hostvars"]
    except (ValueError, KeyError) as exc:
        raise ValidationError("Inventory could not be read") from exc
    if result.returncode or target not in hosts:
        raise ValidationError("Target is not an explicit inventory host")
    if hosts[target].get("ansible_connection", "ssh") != "ssh":
        raise ValidationError("Only SSH targets are allowed")
    return inventory


def execute(args, profile, digest, catalog):
    env = os.environ.copy()
    env.update(
        ANSIBLE_CONFIG=str(DATA / "ansible.cfg"),
        ANSIBLE_STDOUT_CALLBACK="hardener_json",
        ANSIBLE_CALLBACK_PLUGINS=str(DATA / "ansible" / "callback_plugins"),
        ANSIBLE_NOCOLOR="1",
        ANSIBLE_HOST_KEY_CHECKING="True",
    )
    selected = validate(profile, catalog, mode=args.mode)
    inventory = inventory_target(args.inventory, args.target, env)
    print(
        f"Target: {args.target}. Mode: {args.mode}. Controls: {', '.join(selected) or '(none)'}.",
        flush=True,
    )
    selections = {item["id"]: item for item in profile["controls"]}
    controls = []
    for cid in selected:
        control = dict(catalog[cid])
        control["implementation"] = {
            mode: str(DATA / path) for mode, path in control["implementation"].items()
        }
        control["effective_parameters"] = effective_parameters(
            control, selections[cid].get("parameters", {})
        )
        controls.append(control)
    variables = {
        "hardener_target": args.target,
        "hardener_mode": args.mode,
        "hardener_expected_os": [profile["target"]["os"]],
        "hardener_selected": selected,
        "hardener_controls": controls,
    }
    if recovery.needs_recovery(args.mode, controls):
        try:
            variables["hardener_recovery"] = recovery.read_receipt(
                getattr(args, "recovery_evidence", None), inventory, args.target
            )
        except recovery.RecoveryError as exc:
            evidence = {
                "errors": [
                    {
                        "task": "Require tested independent recovery",
                        "kind": "failed",
                        "code": "recovery-required",
                        "reason": str(exc),
                    }
                ]
            }
            print(
                write_report(
                    make_report(args.mode, args.target, profile, digest, catalog, evidence),
                    args.output,
                ),
                end="",
            )
            return 3
    evidence = {}
    code = 4
    with tempfile.TemporaryDirectory(prefix="hardener-") as tmp:
        variables_file = Path(tmp) / "variables.json"
        variables_file.write_text(json.dumps(variables))
        try:
            process = run_command(
                [
                    "ansible-playbook",
                    "-i",
                    str(inventory),
                    "--limit",
                    args.target,
                    str(DATA / "ansible" / "run.yml"),
                    "--extra-vars",
                    "@" + str(variables_file),
                ],
                env,
            )
            code = process.returncode
            evidence = json.loads(process.stdout)
            if not isinstance(evidence, dict):
                raise TypeError("Invalid callback output")
        except (OSError, subprocess.TimeoutExpired, ValueError, TypeError):
            evidence = {
                "errors": [
                    {"task": "Ansible execution or evidence unavailable", "kind": "execution"}
                ]
            }
    report = make_report(args.mode, args.target, profile, digest, catalog, evidence)
    print(write_report(report, args.output), end="")
    return exit_code(evidence, report, code)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Profile-driven Rocky Linux 10 and RHEL 10 server hardening"
    )
    parser.add_argument(
        "mode", choices=["validate", "preflight", "audit", "apply", "verify", "recovery-test"]
    )
    parser.add_argument("--profile")
    parser.add_argument(
        "--recovery-evidence",
        help="Authenticated recovery-test receipt for high-impact apply/preflight",
    )
    parser.add_argument("--inventory")
    parser.add_argument("--target")
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    if args.mode != "validate" and not all((args.inventory, args.target, args.output)):
        parser.error("--inventory, --target and --output are required for target operations")
    if args.mode != "recovery-test" and not args.profile:
        parser.error("--profile is required except for recovery-test")
    try:
        if args.mode == "recovery-test":
            env = os.environ.copy()
            env.update(
                ANSIBLE_CONFIG=str(DATA / "ansible.cfg"),
                ANSIBLE_STDOUT_CALLBACK="hardener_json",
                ANSIBLE_CALLBACK_PLUGINS=str(DATA / "ansible/callback_plugins"),
                ANSIBLE_NOCOLOR="1",
                ANSIBLE_HOST_KEY_CHECKING="True",
            )
            inventory = inventory_target(args.inventory, args.target, env)
            return recovery.rehearse(inventory, args.target, args.output, env)
        catalog = load_catalog()
        profile, digest = load_profile(args.profile, catalog)
        if args.mode == "validate":
            print(f"Valid profile: {profile['id']} revision {profile['revision']}")
            return 0
        return execute(args, profile, digest, catalog)
    except recovery.RecoveryError as exc:
        print("Recovery failed: " + str(exc), file=sys.stderr)
        return 3
    except ValidationError as exc:
        print(f"Validation failed: {exc}", file=sys.stderr)
        return 2
    except (OSError, subprocess.TimeoutExpired):
        print(
            "Execution failed. Check local paths, Ansible installation and connectivity.",
            file=sys.stderr,
        )
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
