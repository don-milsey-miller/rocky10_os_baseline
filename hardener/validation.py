"""Strict offline profile and catalog validation."""

import hashlib
import json
from pathlib import Path

import yaml
from jsonschema import Draft202012Validator
from yaml.tokens import AliasToken

DATA = Path(__file__).parent / "data"


class ValidationError(ValueError):
    """Invalid input, safe to display without including input values."""


class StrictLoader(yaml.SafeLoader):
    pass


def mapping(loader, node):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node)
        if not isinstance(key, str) or key in result:
            raise ValidationError("YAML keys must be unique strings")
        result[key] = loader.construct_object(value_node)
    return result


StrictLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, mapping)


def parse_yaml(raw):
    if len(raw) > 65536:
        raise ValidationError("YAML input exceeds 64 KiB")
    try:
        if any(isinstance(token, AliasToken) for token in yaml.scan(raw)):
            raise ValidationError("YAML aliases are not supported")
        return yaml.load(raw, Loader=StrictLoader)
    except (yaml.YAMLError, UnicodeError, RecursionError) as exc:
        raise ValidationError("Invalid or unsafe YAML") from exc


def check_schema(value, schema, label):
    validator = Draft202012Validator(schema)
    error = next(validator.iter_errors(value), None)
    if error:
        path = ".".join(str(part) for part in error.absolute_path) or "root"
        raise ValidationError(f"{label}: invalid {path} ({error.validator})")


def read_schema(name):
    return json.loads((DATA / "schemas" / name).read_text())


def load_catalog(root=DATA):
    result = {}
    for path in sorted((root / "catalog").glob("*.yaml")):
        control = parse_yaml(path.read_bytes())
        check_schema(control, read_schema("control.schema.json"), "catalog")
        cid = control["id"]
        if cid in result:
            raise ValidationError("Duplicate catalog ID")
        try:
            Draft202012Validator.check_schema(control["parameters"])
        except Exception as exc:
            raise ValidationError(f"{cid}: invalid parameter schema") from exc
        params = control["parameters"]
        if params.get("type") != "object" or params.get("additionalProperties") is not False:
            raise ValidationError(f"{cid}: parameters must be a closed object schema")
        for relative in control["implementation"].values():
            candidate = (root / relative).resolve()
            if not candidate.is_relative_to((root / "ansible" / "tasks").resolve()):
                raise ValidationError(f"{cid}: implementation path escapes task directory")
            if not candidate.is_file():
                raise ValidationError(f"{cid}: missing implementation")
        result[cid] = control
    if not result:
        raise ValidationError("Catalog is empty")
    for control in result.values():
        for ref in control["requires"] + control["conflicts_with"]:
            if ref not in result or ref == control["id"]:
                raise ValidationError("Invalid catalog dependency or conflict")
    return result


def validate(profile, catalog):
    check_schema(profile, read_schema("profile.schema.json"), "profile")
    selected = set()
    seen = set()
    for item in profile["controls"]:
        cid = item["id"]
        if cid in seen:
            raise ValidationError(f"Duplicate control: {cid}")
        seen.add(cid)
        if cid not in catalog:
            raise ValidationError(f"Unknown control: {cid}")
        control = catalog[cid]
        check_schema(item.get("parameters", {}), control["parameters"], cid)
        if item["enabled"]:
            if not control["implemented"]:
                raise ValidationError(f"{cid}: implementation unavailable")
            if control["applies_to"] != profile["target"]:
                raise ValidationError(f"{cid}: incompatible target")
            selected.add(cid)
    for cid in sorted(selected):
        control = catalog[cid]
        if set(control["requires"]) - selected:
            raise ValidationError(f"{cid}: missing enabled dependency")
        if set(control["conflicts_with"]) & selected:
            raise ValidationError(f"{cid}: conflicting selection")
    return sorted(selected)


def load_profile(path, catalog):
    raw = Path(path).read_bytes()
    profile = parse_yaml(raw)
    validate(profile, catalog)
    return profile, hashlib.sha256(raw).hexdigest()
