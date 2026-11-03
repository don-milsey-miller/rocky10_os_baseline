import importlib.util
from pathlib import Path

import pytest

from hardener.validation import DATA, load_catalog, load_profile

SPEC = importlib.util.spec_from_file_location(
    "checks", DATA / "ansible/filter_plugins/hardener_checks.py"
)
CHECKS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKS)


def test_full_profile_selects_exactly_five_controls():
    path = Path(__file__).resolve().parents[2] / "profiles/examples/server-five-controls.yaml"
    profile, _ = load_profile(path, load_catalog())
    assert len(profile["controls"]) == 5
    assert all(item["enabled"] for item in profile["controls"])


def test_sysctl_last_explicit_assignment_wins():
    state = CHECKS.sysctl_state(
        "# /usr/lib/sysctl.d/50-default.conf\nfs.protected_hardlinks=1\n"
        "# /etc/sysctl.d/60-local.conf\nfs/protected_hardlinks=0\n"
    )
    assert state == {"persistent": "0", "blockers": []}


@pytest.mark.parametrize("value", ["0", "2", "", "1 trailing"])
def test_sysctl_later_conflicts_refuse_changes(value):
    state = CHECKS.sysctl_state(
        f"# /etc/sysctl.d/99-sysctl.conf\n-fs.protected_hardlinks={value}\n"
    )
    assert state["blockers"] == ["/etc/sysctl.d/99-sysctl.conf"]


def test_sysctl_later_compatible_setting_allowed():
    assert CHECKS.sysctl_state("# /etc/sysctl.d/zz-local.conf\nfs.protected_hardlinks=1\n") == {
        "persistent": "1",
        "blockers": [],
    }


def test_sysctl_explicit_assignment_excludes_glob():
    state = CHECKS.sysctl_state(
        "# /usr/lib/sysctl.d/50-default.conf\nfs.protected_hardlinks=1\n"
        "# /etc/sysctl.d/zz-local.conf\nfs.protected_*=0\n"
    )
    assert state == {"persistent": "1", "blockers": []}


def test_sysctl_glob_and_exclusion():
    assert CHECKS.sysctl_state("fs.protected_*=0")["persistent"] == "0"
    assert CHECKS.sysctl_state("fs.protected_*=0\n-fs.protected_hardlinks")["persistent"] is None


def test_sysctl_missing_assignment_is_not_pass():
    assert (
        CHECKS.sysctl_state("# fs.protected_hardlinks=1\nfs.protected_symlinks=1")["persistent"]
        is None
    )


@pytest.mark.parametrize(
    "text",
    [
        "[main]\ngpgcheck=1\n",
        "[main]\nlocalpkg_gpgcheck=False\n[repo]\ngpgcheck=1\n",
        "[main] # comment\nlocalpkg_gpgcheck=False\n",
    ],
)
def test_dnf_editable_configuration(text):
    assert CHECKS.dnf_editable(text)


@pytest.mark.parametrize(
    "text",
    [
        "[repo]\ngpgcheck=1\n",
        "[main]\nlocalpkg_gpgcheck=False\nlocalpkg_gpgcheck=True\n",
        "[main]\n[main]\n",
        "[main]\n[repo]\nlocalpkg_gpgcheck=True\n",
        "[DEFAULT]\nlocalpkg_gpgcheck=False\n[main]\n",
        "not an ini file",
    ],
)
def test_dnf_ambiguous_configuration_refused(text):
    assert not CHECKS.dnf_editable(text)
