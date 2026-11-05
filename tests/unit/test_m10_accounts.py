import importlib.util
import json
from types import SimpleNamespace

import pytest

from hardener.validation import DATA

spec = importlib.util.spec_from_file_location(
    "account_assessment", DATA / "ansible/helpers/account_assessment.py"
)
assessment = importlib.util.module_from_spec(spec)
spec.loader.exec_module(assessment)

PASSWD = "root:x:0:0::/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n"
GROUP = "root:x:0:\nalice:x:1000:\n"
SHADOW = "root:!:20000:0:90:14:30::\nalice:PRIVATE_HASH_SENTINEL:20000:0:90:14:30::\n"


@pytest.mark.parametrize("kind", ["unique-identities", "root-only-uid-zero", "no-empty-passwords"])
def test_healthy_identity_assessments_and_no_secret_evidence(kind):
    result = assessment.assess(kind, PASSWD, GROUP, SHADOW)
    assert result["matches"]
    assert "PRIVATE_HASH_SENTINEL" not in json.dumps(result)


def test_duplicate_names_and_numeric_ids_are_separate_findings():
    result = assessment.assess(
        "unique-identities",
        PASSWD + "alice:x:0:0::/:/bin/bash\n",
        GROUP + "duplicate:x:1000:\n",
        SHADOW,
    )
    assert not result["matches"]
    assert result["duplicate_user_names"] == result["duplicate_uids"] == 1
    assert result["duplicate_gids"] == 1


def test_root_alias_or_missing_root_cannot_pass():
    assert not assessment.assess(
        "root-only-uid-zero", PASSWD + "alias:x:0:0::/:/bin/bash\n", GROUP, SHADOW
    )["matches"]
    assert not assessment.assess(
        "root-only-uid-zero", PASSWD.replace("root:x:0:", "root:x:1:"), GROUP, SHADOW
    )["matches"]


@pytest.mark.parametrize(
    "shadow",
    [
        SHADOW.replace("PRIVATE_HASH_SENTINEL", ""),
        SHADOW.splitlines()[0] + "\n",
        SHADOW + SHADOW.splitlines()[1] + "\n",
    ],
)
def test_empty_missing_and_duplicate_shadow_records_fail(shadow):
    assert not assessment.assess("no-empty-passwords", PASSWD, GROUP, shadow)["matches"]


def test_locked_password_is_not_empty():
    assert assessment.assess(
        "no-empty-passwords", PASSWD, GROUP, SHADOW.replace("PRIVATE_HASH_SENTINEL", "!")
    )["matches"]


def test_malformed_records_are_inspection_errors():
    with pytest.raises(ValueError):
        assessment.assess("unique-identities", "broken", GROUP, SHADOW)


def test_root_path_checks_empty_relative_missing_and_parent_writes(tmp_path):
    good = tmp_path / "bin"
    good.mkdir()

    def safe(path):
        return SimpleNamespace(st_uid=0, st_mode=0o40755)

    assert assessment.path_integrity(str(good), safe)["matches"]
    for path in ("", ".", str(good) + ":", str(tmp_path / "missing")):
        assert not assessment.path_integrity(path, safe)["matches"]

    def unsafe_parent(path):
        return SimpleNamespace(st_uid=0, st_mode=0o40777 if path == tmp_path else 0o40755)

    assert not assessment.path_integrity(str(good), unsafe_parent)["matches"]


def test_root_path_checks_symlink_destination(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target)

    def inspect(path):
        return SimpleNamespace(st_uid=1000 if path == target else 0, st_mode=0o40755)

    assert not assessment.path_integrity(str(link), inspect)["matches"]


local_spec = importlib.util.spec_from_file_location(
    "local_accounts", DATA / "ansible/helpers/local_accounts.py"
)
local = importlib.util.module_from_spec(local_spec)
local_spec.loader.exec_module(local)


@pytest.mark.parametrize(
    "names,active,kind",
    [
        (["root"], "operator", "password-aging"),
        (["alice"], "alice", "password-aging"),
        (["absent"], "operator", "password-aging"),
        (["alice"], "operator", "system-login-disabled"),
    ],
)
def test_account_policy_rejects_unsafe_selections(names, active, kind):
    with pytest.raises(ValueError):
        local.select_accounts(names, PASSWD, active, kind)


def test_account_selection_is_explicit_and_preserves_rows():
    rows = local.select_accounts(["alice"], PASSWD, "operator", "password-aging")
    assert rows == [PASSWD.splitlines()[1].split(":")]


def test_duplicate_ids_block_account_remediation():
    with pytest.raises(ValueError):
        local.select_accounts(
            ["alice"], PASSWD + "other:x:1000:1000::/:/bin/bash\n", "operator", "home-permissions"
        )


def test_human_policy_refuses_service_shell():
    with pytest.raises(ValueError):
        local.select_accounts(
            ["alice"],
            PASSWD.replace("/home/alice:/bin/bash", "/home/alice:/sbin/nologin"),
            "operator",
            "password-aging",
        )
