"""Provisioning assessments never implement migration."""

import importlib.util

import pytest

from hardener.validation import DATA, ValidationError, load_catalog, validate

spec = importlib.util.spec_from_file_location(
    "storage_assessment", DATA / "ansible/helpers/storage_assessment.py"
)
storage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(storage)


@pytest.mark.parametrize(
    "nodes,expected",
    [
        ([{"type": "part", "children": [{"type": "disk"}]}], False),
        ([{"type": "crypt", "children": [{"type": "part", "children": [{"type": "disk"}]}]}], True),
        ([{"type": "lvm", "children": [{"type": "crypt", "children": [{"type": "part"}]}]}], True),
        ([{"type": "lvm", "children": [{"type": "crypt"}, {"type": "part"}]}], False),
        ([{"type": "part", "children": [{"type": "crypt", "children": [{"type": "disk"}]}]}], True),
    ],
)
def test_every_backing_branch_requires_encryption(nodes, expected):
    assert storage.encrypted_ancestry(nodes) == expected


def test_empty_ancestry_is_inspection_failure():
    with pytest.raises(ValueError):
        storage.encrypted_ancestry([])


def test_bios_is_finding_not_success():
    result = storage.secure_boot(False)
    assert not result["matches"] and not result["secure_boot"]
    assert result["firmware"] == "bios"


def test_untested_uefi_is_not_claimed_supported():
    with pytest.raises(ValueError, match="UEFI"):
        storage.secure_boot(True)


@pytest.mark.parametrize(
    "cid,parameters",
    [
        ("storage.partition-layout", {"paths": ["/boot"]}),
        ("storage.disk-encryption", {"paths": ["/"]}),
        ("boot.secure-boot", {}),
    ],
)
def test_no_provisioning_assessment_can_apply(cid, parameters):
    profile = {
        "schema_version": 1,
        "id": "test",
        "revision": 1,
        "target": {"os": "rocky", "major_version": 10, "role": "server"},
        "controls": [{"id": cid, "enabled": True, "parameters": parameters}],
    }
    with pytest.raises(ValidationError, match="assessment-only"):
        validate(profile, load_catalog(), mode="apply")
