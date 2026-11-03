"""Read the engine's authoritative catalog and schemas for a static editor build."""

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from hardener import __version__
from hardener.validation import load_catalog, read_schema


def main():
    controls = list(load_catalog().values())
    schema = read_schema("profile.schema.json")
    payload = {"engineVersion": __version__, "controls": controls, "profileSchema": schema}
    payload["catalogDigest"] = hashlib.sha256(
        json.dumps(controls, sort_keys=True).encode()
    ).hexdigest()
    target = ROOT / "web/.generated"
    target.mkdir(exist_ok=True)
    (target / "catalog.json").write_text(json.dumps(payload, indent=2) + "\n")


if __name__ == "__main__":
    main()
