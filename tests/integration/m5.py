"""Exercise engine contracts using an isolated engine copy and disposable guest files."""

import argparse
import copy
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

from hardener.validation import DATA, load_catalog

ROOT = Path(__file__).resolve().parents[2]


def run(argv, expected=0, **kwargs):
    result = subprocess.run(argv, capture_output=True, text=True, check=False, **kwargs)
    if result.returncode != expected:
        raise AssertionError(
            f"{argv[0]}: expected {expected}, got {result.returncode}\n"
            f"{result.stdout}\n{result.stderr}"
        )
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--disposable", action="store_true", required=True)
    args = parser.parse_args()
    inventory = Path(args.inventory).resolve()
    out = Path(args.output).resolve()
    out.mkdir(parents=True, exist_ok=False)
    host = json.loads(run(["ansible-inventory", "-i", str(inventory), "--list"]))["_meta"][
        "hostvars"
    ][args.target]
    ssh = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "ControlMaster=no",
        "-o",
        "ControlPath=none",
        "-p",
        str(host.get("ansible_port", 22)),
        f"{host['ansible_user']}@{host['ansible_host']}",
    ]
    remote_dir = run(ssh + ["mktemp -d /var/tmp/hardener-m5-XXXXXXXX"]).strip()
    assert remote_dir.startswith("/var/tmp/hardener-m5-")
    ids = ["a.child", "b.grandchild", "m.independent", "z.parent"]
    try:
        with tempfile.TemporaryDirectory(prefix="hardener-m5-") as tmp:
            fixture = Path(tmp)
            shutil.copytree(
                DATA.parent, fixture / "hardener", ignore=shutil.ignore_patterns("__pycache__")
            )
            data = fixture / "hardener/data"
            base = copy.deepcopy(next(iter(load_catalog().values())))
            params = {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "value": {"type": "integer", "minimum": 0, "maximum": 9, "default": 7},
                    "flag": {"type": "boolean", "default": True},
                },
            }
            for cid in ids:
                c = copy.deepcopy(base)
                c.update(
                    id=cid,
                    requires={"a.child": ["z.parent"], "b.grandchild": ["a.child"]}.get(cid, []),
                    conflicts_with=[],
                    parameters=params,
                )
                c["implementation"] = {
                    mode: f"ansible/tasks/{cid}.{mode}.yml" for mode in ["audit", "apply", "verify"]
                }
                (data / f"catalog/{cid}.yaml").write_text(yaml.safe_dump(c))
                path = remote_dir + "/" + cid
                expected = "{{ control.effective_parameters.value }}:{{ control.effective_parameters.flag | lower }}"
                record = {
                    "id": "{{ control.id }}",
                    "status": "{{ 'pass' if fixture_state.stdout == fixture_expected else 'fail' }}",
                    "observed": "{{ fixture_state.stdout }}",
                    "expected": expected,
                    "changed": "{{ hardener_changed }}",
                    "reason": None,
                    "reboot_required": False,
                }
                for mode in ["audit", "verify"]:
                    argv = (
                        ["/usr/bin/cat", path]
                        if mode == "audit"
                        else [
                            "/usr/bin/python3",
                            "-c",
                            "from pathlib import Path; import sys; print(Path(sys.argv[1]).read_text(),end='')",
                            path,
                        ]
                    )
                    tasks = [
                        {
                            "name": "Inspect fixture effective state",
                            "ansible.builtin.command": {"argv": argv},
                            "register": "fixture_state",
                            "failed_when": False,
                            "changed_when": False,
                        },
                        {
                            "name": "Resolve expected fixture parameters",
                            "ansible.builtin.set_fact": {"fixture_expected": expected},
                        },
                        {
                            "name": "Record fixture evidence",
                            "ansible.builtin.set_fact": {"hardener_record": record},
                        },
                    ]
                    (data / c["implementation"][mode]).write_text(yaml.safe_dump(tasks))
                apply = [
                    {
                        "name": "Apply resolved fixture parameters",
                        "ansible.builtin.copy": {"dest": path, "content": expected, "mode": "0600"},
                        "register": "fixture_write",
                    },
                    {
                        "name": "Retain fixture change evidence",
                        "ansible.builtin.set_fact": {
                            "hardener_changed": "{{ fixture_write.changed }}"
                        },
                    },
                ]
                (data / c["implementation"]["apply"]).write_text(yaml.safe_dump(apply))
            profile = {
                "schema_version": 1,
                "id": "m5-fixture",
                "revision": 1,
                "target": {"os": "rocky", "major_version": 10, "role": "server"},
                "controls": [{"id": cid, "enabled": True} for cid in ids],
            }
            env = {**os.environ, "PYTHONPATH": str(fixture)}

            def execute(mode, name, expected=0):
                source = out / "profile.yaml"
                source.write_text(yaml.safe_dump(profile))
                log = run(
                    [
                        sys.executable,
                        "-m",
                        "hardener.cli",
                        mode,
                        "--profile",
                        str(source),
                        "--inventory",
                        str(inventory),
                        "--target",
                        args.target,
                        "--output",
                        str(out / name),
                    ],
                    expected,
                    cwd=fixture,
                    env=env,
                    timeout=300,
                )
                (out / (name + ".txt")).write_text(log)
                return json.loads((out / name / "report.json").read_text())

            execute("audit", "before", 5)
            assert execute("apply", "defaults")["summary"]["pass"] == 4
            assert execute("apply", "defaults-rerun")["changed_tasks"] == 0
            for item in profile["controls"]:
                item["parameters"] = {"value": 0, "flag": False}
            assert execute("apply", "overrides")["summary"]["pass"] == 4
            assert execute("verify", "overrides-verify")["summary"]["pass"] == 4
            assert execute("apply", "overrides-rerun")["changed_tasks"] == 0
            parent = data / "ansible/tasks/z.parent.apply.yml"
            original = parent.read_text()
            parent.write_text(
                yaml.safe_dump(
                    [
                        {
                            "name": "Controlled prerequisite failure",
                            "ansible.builtin.fail": {"msg": "private-failure-sentinel"},
                        }
                    ]
                )
            )
            for item in profile["controls"]:
                item["parameters"]["value"] = 2
            failed = execute("apply", "dependency-error", 4)
            rows = {r["id"]: r for r in failed["controls"]}
            assert rows["z.parent"]["status"] == "error"
            assert rows["a.child"]["status"] == rows["b.grandchild"]["status"] == "skipped"
            assert rows["m.independent"]["status"] == "pass"
            assert "private-failure-sentinel" not in json.dumps(failed)
            for cid in ["a.child", "b.grandchild", "z.parent"]:
                assert (
                    run(ssh + ["sudo cat " + shlex.quote(remote_dir + "/" + cid)]).strip()
                    == "0:false"
                )
            parent.write_text(yaml.safe_dump([]))
            failed = execute("apply", "dependency-verify-fail", 5)
            rows = {r["id"]: r for r in failed["controls"]}
            assert rows["z.parent"]["status"] == "fail"
            assert rows["a.child"]["status"] == rows["b.grandchild"]["status"] == "skipped"
            parent.write_text(original)
            assert execute("apply", "recovered")["summary"]["pass"] == 4
            assert execute("apply", "recovered-rerun")["changed_tasks"] == 0
            # Inject an access probe failure in the temporary engine only.
            guard = data / "ansible/control.yml"
            guard.write_text(
                guard.read_text().replace("argv: [/usr/bin/id, -u]", "argv: [/usr/bin/false]")
            )
            for item in profile["controls"]:
                item["parameters"]["value"] = 3
            stopped = execute("apply", "administrative-access-lost", 4)
            assert stopped["changed_tasks"] == 0
            for cid in ids:
                assert (
                    run(ssh + ["sudo cat " + shlex.quote(remote_dir + "/" + cid)]).strip()
                    == "2:false"
                )
            print(
                json.dumps(
                    {
                        "m5": "pass",
                        "defaults": True,
                        "explicit_zero_false": True,
                        "dependency_error": True,
                        "dependency_verification_failure": True,
                        "transitive_skip": True,
                        "independent_control": True,
                        "idempotence": True,
                    }
                )
            )
    finally:
        run(ssh + ["sudo rm -rf -- " + shlex.quote(remote_dir)])


if __name__ == "__main__":
    main()
