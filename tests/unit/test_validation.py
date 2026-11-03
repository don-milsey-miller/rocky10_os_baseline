import copy
from pathlib import Path

import pytest

from hardener import cli
from hardener.validation import DATA, ValidationError, load_catalog, parse_yaml, validate

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def catalog():
    return load_catalog()


@pytest.fixture
def profile():
    return parse_yaml((ROOT / "profiles/examples/server-minimal.yaml").read_bytes())


def test_valid_profile(profile, catalog):
    assert validate(profile, catalog) == ["files.passwd-permissions"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", 2),
        ("schema_version", True),
        ("revision", 0),
        ("revision", True),
        ("id", "../escape"),
        ("unknown", "ignored?"),
    ],
)
def test_bad_profile_fields(profile, catalog, field, value):
    profile[field] = value
    with pytest.raises(ValidationError):
        validate(profile, catalog)


@pytest.mark.parametrize(
    "field,value", [("os", "other"), ("major_version", 9), ("role", "desktop")]
)
def test_unsupported_target(profile, catalog, field, value):
    profile["target"][field] = value
    with pytest.raises(ValidationError):
        validate(profile, catalog)


def test_duplicate_and_unknown_controls(profile, catalog):
    profile["controls"].append(copy.deepcopy(profile["controls"][0]))
    with pytest.raises(ValidationError, match="Duplicate"):
        validate(profile, catalog)
    profile["controls"][-1]["id"] = "unknown.control"
    with pytest.raises(ValidationError, match="Unknown"):
        validate(profile, catalog)


@pytest.mark.parametrize(
    "raw",
    [
        b"x: [",
        b"x: 1\nx: 2",
        b"x: &x [*x]",
        b"!!python/object/apply:os.system ['false']",
        b"1: value",
        b"x: " + b"a" * 65537,
    ],
)
def test_unsafe_yaml(raw):
    with pytest.raises(ValidationError):
        parse_yaml(raw)


def test_explicit_boolean_required(profile, catalog):
    profile["controls"][0]["enabled"] = "true"
    with pytest.raises(ValidationError):
        validate(profile, catalog)


def test_no_arbitrary_commands(profile, catalog):
    profile["controls"][0]["command"] = "touch /tmp/forbidden"
    with pytest.raises(ValidationError):
        validate(profile, catalog)


def test_parameters_are_strict(profile, catalog):
    item = profile["controls"][0]
    item["parameters"] = {"mode": "0666"}
    with pytest.raises(ValidationError):
        validate(profile, catalog)
    catalog[item["id"]]["parameters"]["properties"] = {"count": {"type": "integer"}}
    item["parameters"] = {"count": "1"}
    with pytest.raises(ValidationError):
        validate(profile, catalog)
    item["parameters"] = {"count": 1}
    validate(profile, catalog)


def test_unimplemented_not_selectable(profile, catalog):
    profile["controls"][1]["enabled"] = True
    with pytest.raises(ValidationError, match="unavailable"):
        validate(profile, catalog)


def test_dependencies_and_conflicts(profile, catalog):
    first, second = profile["controls"][:2]
    catalog[first["id"]]["requires"] = [second["id"]]
    with pytest.raises(ValidationError, match="dependency"):
        validate(profile, catalog)
    catalog[second["id"]]["implemented"] = True
    second["enabled"] = True
    validate(profile, catalog)
    catalog[second["id"]]["conflicts_with"] = [first["id"]]
    with pytest.raises(ValidationError, match="conflicting"):
        validate(profile, catalog)


def test_no_implicit_enablement(profile, catalog):
    profile["controls"] = []
    assert validate(profile, catalog) == []


def test_catalog_paths_exist(catalog):
    for control in catalog.values():
        if control["implemented"]:
            assert set(control["implementation"]) == {"audit", "apply", "verify"}
            for relative in control["implementation"].values():
                assert (DATA / relative).is_file()


def test_invalid_profile_never_contacts_target(tmp_path, monkeypatch):
    path = tmp_path / "bad.yaml"
    path.write_text("unexpected: true")
    monkeypatch.setattr(cli, "run_command", lambda *a: pytest.fail("target contact"))
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


def test_validate_is_offline(profile, tmp_path, monkeypatch):
    path = tmp_path / "profile.yaml"
    import json

    path.write_text(json.dumps(profile))
    monkeypatch.setattr(cli, "run_command", lambda *a: pytest.fail("target contact"))
    assert cli.main(["validate", "--profile", str(path)]) == 0


@pytest.mark.parametrize("target", ["all", "*", "vm:other", "vm,other", "!host", "group&other"])
def test_target_patterns_refused(target):
    with pytest.raises(ValidationError):
        cli.inventory_target("missing", target, {})
