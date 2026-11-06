"""Build-independent check of a wheel in an isolated, non-editable environment."""

import json
import os
import subprocess
import tempfile
import venv
from pathlib import Path

from hardener import __version__
from hardener.reporting import source_digest
from hardener.validation import load_catalog

ROOT = Path(__file__).resolve().parents[2]


def run(argv, **kwargs):
    return subprocess.run(argv, check=True, capture_output=True, text=True, **kwargs).stdout


def main():
    wheels = sorted((ROOT / "dist").glob("*.whl"))
    if len(wheels) != 1:
        raise SystemExit("Build into an empty dist directory before package smoke testing")
    with tempfile.TemporaryDirectory(prefix="hardener-wheel-") as tmp:
        directory = Path(tmp)
        venv.create(directory / "env", with_pip=True)
        python = directory / "env/bin/python"
        run([str(python), "-m", "pip", "install", "-r", str(ROOT / "requirements-tested.txt")])
        run([str(python), "-m", "pip", "install", "--no-deps", str(wheels[0])])
        env = os.environ.copy()
        env.pop("PYTHONPATH", None)
        env["PATH"] = str(python.parent) + os.pathsep + env["PATH"]
        probe = run(
            [
                str(python),
                "-c",
                """
import json
from pathlib import Path
import hardener
from hardener.reporting import source_digest
from hardener.validation import DATA, load_catalog
catalog = load_catalog()
assert catalog
assert (DATA / 'ansible.cfg').is_file()
assert (DATA / 'ansible/callback_plugins/hardener_json.py').is_file()
print(json.dumps({'version':hardener.__version__,'path':hardener.__file__,
                  'engine_sha256':source_digest(),'controls':sorted(catalog)}))
""",
            ],
            cwd=directory,
            env=env,
        )
        result = json.loads(probe)
        assert result["controls"] == sorted(load_catalog())
        assert result["version"] == __version__
        assert result["engine_sha256"] == source_digest()
        assert Path(result["path"]).is_relative_to(directory)
        for profile in (ROOT / "profiles/examples").glob("*.yaml"):
            run(["hardener", "validate", "--profile", str(profile)], cwd=directory, env=env)
        package = Path(result["path"]).parent
        run(
            [
                "ansible-playbook",
                "-i",
                str(ROOT / "inventory.example.ini"),
                str(package / "data/ansible/run.yml"),
                "--syntax-check",
                "-e",
                "hardener_target=test-vm",
            ],
            cwd=directory,
            env=env,
        )
        print(json.dumps({**result, "wheel": wheels[0].name, "package_smoke": "pass"}, indent=2))


if __name__ == "__main__":
    main()
