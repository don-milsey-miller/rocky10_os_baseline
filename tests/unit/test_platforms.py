"""Distribution selection and fail-closed guest admission contracts."""

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from jinja2 import Environment

from hardener import cli
from hardener.reporting import make_report
from hardener.validation import DATA, ValidationError, load_catalog, target_matches, validate


def profile(os_name):
    return {
        "schema_version": 1,
        "id": "platform-test",
        "revision": 1,
        "target": {"os": os_name, "major_version": 10, "role": "server"},
        "controls": [{"id": "files.passwd-permissions", "enabled": True}],
    }


@pytest.mark.parametrize("os_name", ["rocky", "rhel"])
def test_profile_target_is_bound_to_execution_and_reporting(os_name, tmp_path, monkeypatch):
    p = profile(os_name)
    catalog = load_catalog()
    assert validate(p, catalog) == ["files.passwd-permissions"]
    monkeypatch.setattr(cli, "inventory_target", lambda *a: tmp_path / "inventory")
    captured = {}

    def execute(argv, env):
        captured.update(json.loads(Path(argv[-1][1:]).read_text()))
        return SimpleNamespace(returncode=0, stdout=json.dumps({"preflight_passed": True}))

    monkeypatch.setattr(cli, "run_command", execute)
    args = SimpleNamespace(
        mode="preflight", inventory="unused", target="test", output=tmp_path / "report"
    )
    assert cli.execute(args, p, "a" * 64, catalog) == 0
    assert captured["hardener_expected_os"] == [os_name]
    result = json.loads((args.output / "report.json").read_text())
    assert result["platform"] == os_name + "-10-server"
    assert make_report("audit", "test", p, "a" * 64, catalog, {})["platform"] == "unverified"


def test_single_distribution_catalog_stays_restricted():
    p = profile("rhel")
    catalog = load_catalog()
    catalog["files.passwd-permissions"]["applies_to"]["os"] = "rocky"
    with pytest.raises(ValidationError, match="incompatible target"):
        validate(p, catalog)
    assert target_matches(
        catalog["files.passwd-permissions"]["applies_to"], profile("rocky")["target"]
    )


@pytest.mark.parametrize(
    "distribution,major,kind,role,identity,expected,accepted",
    [
        ("Rocky", "10", "kvm", "guest", "", ["rocky"], True),
        ("RedHat", "10", "kvm", "guest", "", ["rhel"], True),
        ("RedHat", "10", "xen", "guest", "ec2abcdef", ["rhel"], True),
        ("Rocky", "10", "xen", "guest", "EC2ABCDEF", ["rocky"], True),
        ("RedHat", "10", "kvm", "guest", "", ["rocky"], False),
        ("Rocky", "10", "kvm", "guest", "", ["rhel"], False),
        ("Ubuntu", "10", "kvm", "guest", "", ["rhel"], False),
        ("RedHat", "9", "kvm", "guest", "", ["rhel"], False),
        ("RedHat", "10", "kvm", "host", "", ["rhel"], False),
        ("RedHat", "10", "NA", "NA", "", ["rhel"], False),
        ("RedHat", "10", "docker", "guest", "", ["rhel"], False),
        ("RedHat", "10", "xen", "guest", "other-cloud", ["rhel"], False),
        ("RedHat", "10", "xen", "guest", "", ["rhel"], False),
        ("RedHat", "10", "kvm", "guest", "", [], False),
        ("Rocky", "10", "kvm", "guest", "", ["rocky", "rhel"], True),
        ("RedHat", "10", "kvm", "guest", "", ["rocky", "rhel"], True),
    ],
)
def test_preflight_admission_matrix(distribution, major, kind, role, identity, expected, accepted):
    tasks = yaml.safe_load((DATA / "ansible/preflight.yml").read_text())
    task = next(t for t in tasks if t["name"] == "Require matching supported server guest")
    variables = {
        "ansible_facts": {
            "distribution": distribution,
            "distribution_major_version": major,
            "virtualization_type": kind,
            "virtualization_role": role,
        },
        "ec2_xen_identity": {"stdout": identity},
        "hardener_expected_os": expected,
    }
    env = Environment()
    conditions = task["ansible.builtin.assert"]["that"]
    assert all(env.compile_expression(c)(**variables) for c in conditions) is accepted
