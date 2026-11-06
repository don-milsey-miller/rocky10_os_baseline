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


def test_bundled_license_check_rejects_missing_text_and_stale_inventory(tmp_path):
    import html
    import importlib.util

    import pytest

    spec = importlib.util.spec_from_file_location(
        "release_checks", ROOT / "tests/release_checks.py"
    )
    checks = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checks)
    (tmp_path / "docs").mkdir()
    dist = tmp_path / "web/dist"
    dist.mkdir(parents=True)
    inventory = []
    texts = []
    for name, license_name in [("ajv", "MIT"), ("yaml", "ISC")]:
        package = tmp_path / "web/node_modules" / name
        package.mkdir(parents=True)
        metadata = {"name": name, "version": "1.0", "license": license_name}
        (package / "package.json").write_text(json.dumps(metadata))
        text = license_name + " complete notice <copyright & permission>"
        (package / "LICENSE").write_text(text)
        inventory.append({**metadata, "bundled": True})
        texts.append(name + " 1.0\n" + text)
    inventory_file = tmp_path / "docs/web-dependency-licenses.json"
    inventory_file.write_text(json.dumps(inventory))
    full = "\n".join(texts)
    (dist / "THIRD-PARTY-NOTICES.txt").write_text(full)
    (dist / "index.html").write_text(html.escape(full))
    checks.check_bundled_notices(tmp_path, ["ajv", "yaml"])
    (dist / "index.html").write_text(html.escape(texts[0]))
    with pytest.raises(AssertionError):
        checks.check_bundled_notices(tmp_path, ["ajv", "yaml"])
    (dist / "index.html").write_text(html.escape(full))
    (dist / "THIRD-PARTY-NOTICES.txt").write_text(texts[0])
    with pytest.raises(AssertionError):
        checks.check_bundled_notices(tmp_path, ["ajv", "yaml"])
    (dist / "THIRD-PARTY-NOTICES.txt").write_text(full)
    inventory[1]["license"] = "incorrect"
    inventory_file.write_text(json.dumps(inventory))
    with pytest.raises(AssertionError):
        checks.check_bundled_notices(tmp_path, ["ajv", "yaml"])
