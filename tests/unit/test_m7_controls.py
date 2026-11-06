import configparser
import importlib.util
import json
import sys
from types import SimpleNamespace

import pytest
import yaml

from hardener import cli
from hardener.validation import DATA, ValidationError, load_catalog, validate

spec = importlib.util.spec_from_file_location(
    "m7_checks", DATA / "ansible/filter_plugins/hardener_checks.py"
)
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)


def profile(cid, parameters):
    return {
        "schema_version": 1,
        "id": "m7-unit",
        "revision": 1,
        "target": {"os": "rocky", "major_version": 10, "role": "server"},
        "controls": [{"id": cid, "enabled": True, "parameters": parameters}],
    }


def test_repository_edit_preserves_unselected_sections_and_options():
    text = "# retained\n[first] # comment\nname=First\ngpgcheck=0\n[second]\ngpgcheck=0\n"
    rows = [{"id": "first", "path": "/etc/yum.repos.d/test.repo"}]
    result = checks.repository_edit(text, rows, rows[0]["path"], "gpgcheck")
    assert result == text.replace("gpgcheck=0", "gpgcheck=True", 1)
    assert checks.repository_edit(result, rows, rows[0]["path"], "gpgcheck") == result


@pytest.mark.parametrize(
    "text", ["[first]\ngpgcheck=0\ngpgcheck=1\n", "[DEFAULT]\ngpgcheck=0\n[first]\n", "[second]\n"]
)
def test_repository_edit_refuses_ambiguous_layout(text):
    with pytest.raises((ValueError, configparser.Error)):
        checks.repository_edit(text, [{"id": "first", "path": "p"}], "p", "gpgcheck")


def test_chrony_preserves_unrelated_configuration_and_is_idempotent():
    text = "# keep\npool old.example iburst\nsourcedir /run/chrony-dhcp\ndriftfile /var/lib/chrony/drift\n"
    policy = {"sources": ["time.example"], "source_type": "server"}
    result = checks.chrony_edit(text, policy)
    assert result == "# keep\ndriftfile /var/lib/chrony/drift\nserver time.example iburst\n"
    assert checks.chrony_edit(result, policy) == result
    with pytest.raises(ValueError):
        checks.chrony_edit("include /etc/other.conf\n", policy)


@pytest.mark.parametrize(
    "path",
    [
        "/var/log/../etc/shadow",
        "/var/log/a/../../etc/shadow",
        "/var/log/./x",
        "/var/log/a/..",
        "/etc/shadow",
        "/var/log/a b",
        "/var/log/*",
        "/var/log/x\npostrotate",
    ],
)
def test_log_paths_cannot_escape_or_inject(path):
    with pytest.raises(ValidationError):
        validate(
            profile("logging.logfile-permissions", {"paths": [path], "mode": "0640"}),
            load_catalog(),
        )


def test_optional_values_are_required_and_exclusions_need_no_values():
    document = profile("logging.journal-retention", {})
    with pytest.raises(ValidationError):
        validate(document, load_catalog())
    document["controls"][0]["enabled"] = False
    assert validate(document, load_catalog()) == []


def test_assessment_apply_refused_before_inventory_or_target_contact(tmp_path, monkeypatch):
    document = profile("packages.security-update-status", {"repositories": ["example"]})
    validate(document, load_catalog(), mode="audit")
    validate(document, load_catalog(), mode="verify")
    with pytest.raises(ValidationError, match="assessment-only"):
        validate(document, load_catalog(), mode="apply")
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(document))
    monkeypatch.setattr(cli, "inventory_target", lambda *a: pytest.fail("inventory contact"))
    assert (
        cli.main(
            [
                "apply",
                "--profile",
                str(path),
                "--inventory",
                "missing",
                "--target",
                "vm",
                "--output",
                str(tmp_path / "out"),
            ]
        )
        == 2
    )


def test_rotation_has_fixed_action_and_bounded_policy():
    policy = {
        "paths": ["/var/log/example.log"],
        "mode": "0640",
        "frequency": "daily",
        "retain": 7,
        "reopen": "none",
    }
    validate(profile("logging.rotation-policy", policy), load_catalog())
    text = checks.rotation_policy(policy)
    assert "postrotate" not in text and "rotate 7" in text and "create 0640" in text
    for key, value in [
        ("retain", 0),
        ("frequency", "hourly"),
        ("reopen", "exec evil"),
        ("paths", ["/var/log/a", "/var/log/a"]),
    ]:
        with pytest.raises(ValidationError):
            validate(profile("logging.rotation-policy", {**policy, key: value}), load_catalog())


def test_embedded_python_inspections_are_valid_python():
    for path in (DATA / "ansible/tasks").glob("*.yml"):
        for task in yaml.safe_load(path.read_text()):
            argv = task.get("ansible.builtin.command", {}).get("argv", [])
            if len(argv) > 2 and argv[:2] == ["/usr/bin/python3", "-c"]:
                if argv[2].startswith("{{ lookup("):
                    assert "/helpers/" in argv[2]
                else:
                    compile(argv[2], str(path), "exec")
    for path in (DATA / "ansible/helpers").glob("*.py"):
        compile(path.read_text(), str(path), "exec")


def test_advisory_inspection_loads_site_variables_before_repositories(monkeypatch, capsys):
    ready = []

    class Query:
        def upgrades(self):
            return self

        def filter(self, **kwargs):
            assert kwargs == {"advisory_type": "security"}
            return self

        def latest(self):
            return []

    class Base:
        def __init__(self):
            self.conf = SimpleNamespace(
                read=lambda: None,
                installroot="/",
                varsdir=["/etc/dnf/vars"],
                substitutions=SimpleNamespace(
                    update_from_etc=lambda root, varsdir: ready.append((root, varsdir))
                ),
            )
            self.repos = {
                "test": SimpleNamespace(
                    id="test",
                    enabled=True,
                    add_metadata_type_to_download=lambda kind: None,
                    get_metadata_path=lambda kind: "/temporary/updateinfo",
                )
            }
            self.sack = SimpleNamespace(query=Query)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read_all_repos(self):
            assert ready == [("/", ["/etc/dnf/vars"])]

        def fill_sack(self, **kwargs):
            assert kwargs == {"load_system_repo": True}

    monkeypatch.setitem(sys.modules, "dnf", SimpleNamespace(Base=Base))
    monkeypatch.setattr(sys, "argv", ["probe", '["test"]'])
    task = yaml.safe_load(
        (DATA / "ansible/tasks/packages.security-update-status.audit.yml").read_text()
    )[0]
    # Exercise the shipped trusted inspection against a fake DNF API.
    exec(task["ansible.builtin.command"]["argv"][2], {})  # noqa: S102
    assert json.loads(capsys.readouterr().out) == {"pending": 0, "packages": [], "repositories": 1}
