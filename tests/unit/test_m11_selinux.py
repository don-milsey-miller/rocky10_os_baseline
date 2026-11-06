import importlib.util

import pytest

from hardener.validation import DATA

spec = importlib.util.spec_from_file_location(
    "selinux_policy", DATA / "ansible/helpers/selinux_policy.py"
)
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


def test_config_parser_preserves_comments_and_requires_unique_explicit_values():
    assert policy.config_values("# custom\nSELINUX=permissive\nSELINUXTYPE=targeted\n") == {
        "SELINUX": "permissive",
        "SELINUXTYPE": "targeted",
    }
    for bad in [
        "SELINUX=enforcing",
        "SELINUX=enforcing\nSELINUX=enforcing\nSELINUXTYPE=targeted",
        "SELINUX=enforcing\nSELINUXTYPE=targeted\nOTHER=1",
    ]:
        with pytest.raises(ValueError):
            policy.config_values(bad)


@pytest.mark.parametrize(
    "args,allowed",
    [
        ("console=ttyS0 selinux=0", False),
        ("enforcing=0", False),
        ("selinux=1 enforcing=1", True),
        ("audit=1", True),
    ],
)
def test_boot_bypass_is_not_hidden_by_other_arguments(args, allowed):
    assert policy.boot_permits(args) == allowed


def test_unconfined_assessment_counts_context_types_without_disclosing_commands():
    assert policy.unconfined("system_u:system_r:sshd_t:s0 sshd") == 0
    assert policy.unconfined("system_u:system_r:unconfined_service_t:s0 private-command") == 1
    with pytest.raises(ValueError):
        policy.unconfined("unknown command")


@pytest.mark.parametrize(
    "args",
    [
        "selinux=off",
        "selinux=no",
        "enforcing=garbage",
        'enforcing="0"',
        "enforcing=0x0",
        "enforcing",
    ],
)
def test_alternate_boot_bypasses_are_refused(args):
    assert not policy.boot_permits(args)


def test_policy_digest_compares_native_semantics_without_writing_files(monkeypatch):
    from types import SimpleNamespace

    calls = []

    def native(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(returncode=0, stdout=b"(allow source target (file (read)))")

    monkeypatch.setattr(policy.subprocess, "run", native)
    assert policy.policy_digest("/targeted") == policy.policy_digest("/loaded")
    assert all("-C" in args and "/dev/stdout" in args for args in calls)
    monkeypatch.setattr(
        policy.subprocess, "run", lambda *args, **kwargs: SimpleNamespace(returncode=1, stdout=b"")
    )
    with pytest.raises(ValueError):
        policy.policy_digest("/invalid")
