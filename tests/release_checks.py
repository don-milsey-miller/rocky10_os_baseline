"""Check tracked files and built artifacts before tagging a candidate."""

import html
import json
import re
import subprocess
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SECRET_PATTERNS = [
    rb"-----BEGIN (?:OPENSSH |RSA |EC |DSA )?PRIVATE KEY-----",
    rb"gh[pousr]_[A-Za-z0-9]{30,}",
    rb"github_pat_[A-Za-z0-9_]{40,}",
]
FORBIDDEN_SUFFIXES = {".pdf", ".pem", ".key", ".qcow2", ".iso", ".rpm"}
FORBIDDEN_PARTS = {".venv", "node_modules", "reports", "__pycache__", ".generated"}


def check_name(name):
    path = Path(name)
    if path.suffix in FORBIDDEN_SUFFIXES or set(path.parts) & FORBIDDEN_PARTS:
        raise ValueError("Unexpected release file: " + name)
    if path.name.startswith("inventory.local"):
        raise ValueError("Private inventory in release: " + name)


def check_bytes(name, data):
    if any(re.search(pattern, data) for pattern in SECRET_PATTERNS):
        raise ValueError("Credential pattern found in " + name)


def check_bundled_notices(root, dependencies):
    """Check complete bundled notices against installed packages and the inventory."""
    assert dependencies == ["ajv", "yaml"]
    inventory = {
        row["name"]: row
        for row in json.loads((root / "docs/web-dependency-licenses.json").read_text())
        if row["bundled"]
    }
    assert set(inventory) == set(dependencies)
    notices = (root / "web/dist/THIRD-PARTY-NOTICES.txt").read_text()
    editor = html.unescape((root / "web/dist/index.html").read_text())
    for name in dependencies:
        package = root / "web/node_modules" / name
        metadata = json.loads((package / "package.json").read_text())
        assert metadata["version"] == inventory[name]["version"]
        assert metadata["license"] == inventory[name]["license"]
        license_text = (package / "LICENSE").read_text().strip()
        assert license_text and license_text in notices and license_text in editor
        assert name + " " + metadata["version"] in notices


def main():
    tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).decode().split("\0")
    for name in filter(None, tracked):
        check_name(name)
        check_bytes(name, (ROOT / name).read_bytes())
    wheels = list((ROOT / "dist").glob("*.whl"))
    archives = list((ROOT / "dist").glob("*.tar.gz"))
    if len(wheels) != 1 or len(archives) != 1:
        raise ValueError("Expected exactly one wheel and one source distribution")
    with zipfile.ZipFile(wheels[0]) as archive:
        for name in archive.namelist():
            check_name(name)
            check_bytes(name, archive.read(name))
        if any(
            name.startswith(("ansible/", "yaml/", "jsonschema/")) for name in archive.namelist()
        ):
            raise ValueError("Python dependencies must remain separately installed")
    with tarfile.open(archives[0]) as archive:
        for item in archive.getmembers():
            check_name(item.name)
            if item.isfile():
                check_bytes(item.name, archive.extractfile(item).read())
    manifest = json.loads((ROOT / "web/dist/build-manifest.json").read_text())
    check_bundled_notices(ROOT, manifest["dependencies"])
    print("Tracked source, wheel, source distribution and bundled notices passed release checks.")


if __name__ == "__main__":
    main()
