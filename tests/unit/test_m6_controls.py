import importlib.util

import pytest

from hardener.validation import DATA

spec = importlib.util.spec_from_file_location(
    "m6_checks", DATA / "ansible/filter_plugins/hardener_checks.py"
)
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)


@pytest.mark.parametrize(
    "key,desired",
    [
        ("fs.protected_symlinks", "1"),
        ("kernel.randomize_va_space", "2"),
        ("fs.suid_dumpable", "0"),
        ("kernel.unprivileged_bpf_disabled", "2"),
    ],
)
def test_sysctl_precedence_is_specific_to_selected_key(key, desired):
    text = (
        f"# /usr/lib/sysctl.d/50-default.conf\n{key}=9\n"
        "# /etc/sysctl.d/99-rocky10-hardener.conf\n"
        f"{key}={desired}\nfs.protected_hardlinks=1\n"
        "# /etc/sysctl.d/zz-other.conf\nfs.protected_hardlinks=0\n"
    )
    assert checks.sysctl_state(text, key, desired) == {"persistent": desired, "blockers": []}
    text += f"{key}=9\n"
    assert checks.sysctl_state(text, key, desired)["blockers"] == ["/etc/sysctl.d/zz-other.conf"]


def test_explicit_sysctl_overrides_glob_and_exclusion():
    text = "# /etc/sysctl.d/99-rocky10-hardener.conf\nkernel.*=0\nkernel.kptr_restrict=2\n"
    assert checks.sysctl_state(text, "kernel.kptr_restrict", "2")["persistent"] == "2"
    text = "# /etc/sysctl.d/99-rocky10-hardener.conf\nkernel.*=0\n-kernel.kptr_restrict\n"
    assert checks.sysctl_state(text, "kernel.kptr_restrict", "2")["persistent"] is None


@pytest.mark.parametrize(
    "field,value",
    [
        ("isreg", False),
        ("nlink", 2),
        ("uid", 1),
        ("gid", 1),
        ("mode", "0640"),
    ],
)
def test_backup_metadata_rejects_unsafe_state_and_omits_content(field, value):
    info = {
        "exists": True,
        "isreg": True,
        "nlink": 1,
        "uid": 0,
        "gid": 0,
        "mode": "0000",
        "content": "secret-sentinel",
    }
    item = {"backup": {"path": "/etc/shadow-", "mode": "0000"}, "stat": info}
    assert checks.backup_state([item])[0]["ok"] is True
    info[field] = value
    result = checks.backup_state([item])
    assert result[0]["ok"] is False
    assert "secret-sentinel" not in str(result)


def test_missing_backups_are_not_invented():
    assert checks.backup_state([{"stat": {"exists": False}}]) == []
