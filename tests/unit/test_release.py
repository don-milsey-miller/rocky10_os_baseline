import json
import tomllib
from pathlib import Path

from packaging.version import Version

from hardener import __version__
from hardener.validation import load_catalog, load_profile

ROOT = Path(__file__).resolve().parents[2]


def test_release_versions_agree():
    python = tomllib.loads((ROOT / "pyproject.toml").read_text())
    web = json.loads((ROOT / "web/package.json").read_text())
    lock = json.loads((ROOT / "web/package-lock.json").read_text())
    assert python["project"]["version"] == __version__
    assert Version(web["version"]) == Version(__version__)
    assert lock["version"] == lock["packages"][""]["version"] == web["version"]


def test_examples_are_valid_and_reference_only_supported_controls():
    catalog = load_catalog()
    examples = list((ROOT / "profiles/examples").glob("*.yaml"))
    assert examples
    for path in examples:
        load_profile(path, catalog)


def test_packaging_includes_runtime_data():
    from hardener.validation import DATA

    assert (DATA / "ansible.cfg").is_file()
    assert (DATA / "ansible/callback_plugins/hardener_json.py").is_file()
    assert (DATA / "ansible/run.yml").is_file()


def test_release_checks_reject_private_assets_and_credential_patterns():
    import importlib.util

    import pytest

    spec = importlib.util.spec_from_file_location(
        "release_checks", ROOT / "tests/release_checks.py"
    )
    checks = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checks)
    for name in ["inventory.local.ini", "reports/report.json", "private.key", "image.qcow2"]:
        with pytest.raises(ValueError):
            checks.check_name(name)
    checks.check_name("profiles/examples/server-minimal.yaml")
    checks.check_bytes("normal.py", b"original source")
    with pytest.raises(ValueError):
        checks.check_bytes("private", b"-----BEGIN " + b"PRIVATE KEY-----")
    with pytest.raises(ValueError):
        checks.check_bytes("token", b"ghp_" + b"x" * 36)
