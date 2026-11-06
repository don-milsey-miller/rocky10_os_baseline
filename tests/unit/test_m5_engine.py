"""Engine contracts needed by parameterized and dependent controls."""

import copy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from hardener import cli
from hardener.validation import (
    ValidationError,
    check_schema,
    dependency_order,
    effective_parameters,
    load_catalog,
    read_schema,
)


def control():
    return {
        "id": "test.parameters",
        "parameters": {
            "type": "object",
            "additionalProperties": False,
            "required": ["count", "enabled"],
            "properties": {
                "count": {"type": "integer", "minimum": 0, "maximum": 9, "default": 7},
                "enabled": {"type": "boolean", "default": True},
                "nested": {
                    "type": "object",
                    "default": {},
                    "properties": {
                        "values": {"type": "array", "default": [1]},
                    },
                },
            },
        },
    }


def test_defaults_overrides_and_no_mutation():
    c = control()
    original = copy.deepcopy(c)
    supplied = {"count": 0, "enabled": False}
    result = effective_parameters(c, supplied)
    assert result == {"count": 0, "enabled": False, "nested": {"values": [1]}}
    result["nested"]["values"].append(2)
    assert c == original and supplied == {"count": 0, "enabled": False}
    assert effective_parameters(c, {})["nested"]["values"] == [1]


@pytest.mark.parametrize("value", [-1, 10, True, "1"])
def test_invalid_parameter_values(value):
    with pytest.raises(ValidationError):
        effective_parameters(control(), {"count": value})


def test_required_without_default_and_invalid_default():
    c = control()
    del c["parameters"]["properties"]["count"]["default"]
    with pytest.raises(ValidationError):
        effective_parameters(c, {})
    c["parameters"]["properties"]["count"]["default"] = -1
    with pytest.raises(ValidationError):
        effective_parameters(c, {})


def test_topological_order_and_cycle():
    catalog = {
        "a.child": {"requires": ["z.parent"]},
        "z.parent": {"requires": []},
        "b.grandchild": {"requires": ["a.child"]},
        "m.independent": {"requires": []},
    }
    assert dependency_order(catalog, catalog) == [
        "m.independent",
        "z.parent",
        "a.child",
        "b.grandchild",
    ]
    catalog["z.parent"]["requires"] = ["b.grandchild"]
    with pytest.raises(ValidationError, match="cycle"):
        dependency_order(catalog, catalog)


def test_parameters_reach_ansible(tmp_path, monkeypatch):
    catalog = load_catalog()
    cid = "files.passwd-permissions"
    catalog[cid]["parameters"] = control()["parameters"]
    original = copy.deepcopy(catalog)
    profile = {
        "schema_version": 1,
        "id": "m5",
        "revision": 1,
        "target": {"os": "rocky", "major_version": 10, "role": "server"},
        "controls": [{"id": cid, "enabled": True, "parameters": {"count": 0, "enabled": False}}],
    }
    captured = {}
    monkeypatch.setattr(cli, "inventory_target", lambda *a: tmp_path / "inventory")

    def execute(argv, env):
        captured.update(json.loads(Path(argv[-1][1:]).read_text()))
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps(
                {
                    "preflight_passed": True,
                    "records": {
                        cid: {
                            "id": cid,
                            "status": "pass",
                            "observed": "ok",
                            "expected": "ok",
                            "changed": False,
                            "reason": None,
                            "reboot_required": False,
                        }
                    },
                }
            ),
        )

    monkeypatch.setattr(cli, "run_command", execute)
    args = SimpleNamespace(
        inventory="inventory", target="test-vm", mode="verify", output=tmp_path / "report"
    )
    assert cli.execute(args, profile, "digest", catalog) == 0
    item = captured["hardener_controls"][0]
    assert item["effective_parameters"]["count"] == 0
    assert item["effective_parameters"]["enabled"] is False
    assert item["parameters"] == catalog[cid]["parameters"]
    assert catalog == original


@pytest.mark.parametrize("count,valid", [(128, True), (129, False)])
def test_profile_selection_boundary(count, valid):
    profile = {
        "schema_version": 1,
        "id": "m5",
        "revision": 1,
        "target": {"os": "rocky", "major_version": 10, "role": "server"},
        "controls": [{"id": f"fixture.item-{i}", "enabled": False} for i in range(count)],
    }
    if valid:
        check_schema(profile, read_schema("profile.schema.json"), "profile")
    else:
        with pytest.raises(ValidationError):
            check_schema(profile, read_schema("profile.schema.json"), "profile")


def test_skipped_and_unsupported_are_not_success():
    from hardener.reporting import exit_code

    evidence = {"preflight_passed": True}
    for status in ["skipped", "unsupported"]:
        report = {
            "mode": "apply",
            "summary": {"error": 0, "fail": 0, "skipped": 0, "unsupported": 0},
        }
        report["summary"][status] = 1
        assert exit_code(evidence, report, 0) == 5
    report["mode"] = "preflight"
    report["summary"] = {"error": 0, "fail": 0, "unsupported": 0, "skipped": 1}
    assert exit_code(evidence, report, 0) == 0


def test_excluded_control_does_not_require_site_policy():
    from hardener.validation import validate

    catalog = load_catalog()
    cid = "files.passwd-permissions"
    catalog[cid]["parameters"] = {
        "type": "object",
        "additionalProperties": False,
        "required": ["policy"],
        "properties": {"policy": {"type": "string"}},
    }
    profile = {
        "schema_version": 1,
        "id": "excluded",
        "revision": 1,
        "target": {"os": "rocky", "major_version": 10, "role": "server"},
        "controls": [{"id": cid, "enabled": False}],
    }
    assert validate(profile, catalog) == []
    profile["controls"][0]["enabled"] = True
    with pytest.raises(ValidationError):
        validate(profile, catalog)
