"""Safety and semantics of native local PAM and session policy."""

import hashlib
import importlib.util
import subprocess

import pytest

from hardener.validation import DATA, ValidationError, load_catalog, validate


def helper(name):
    spec = importlib.util.spec_from_file_location(name, DATA / f"ansible/helpers/{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pam = helper("local_pam")
sessions = helper("local_sessions")


@pytest.mark.parametrize(
    "text",
    [
        "minlen=14\nminlen=8\n",
        "minlen=14 extra\n",
        "minlen=$(id)\n",
        "minlen=14; echo secret\n",
        "bad key=1\n",
    ],
)
def test_ambiguous_pam_configuration_is_rejected(text):
    with pytest.raises(ValueError):
        pam.settings(text)


def test_pam_edit_retains_comments_and_is_idempotent():
    desired = pam.desired("password-quality", {"minimum_length": 14})
    text = "# local note\nminlen = 8\n"
    edited = pam.edit(text, desired)
    assert edited.startswith("# local note\n")
    assert pam.settings(edited) == desired
    assert pam.edit(edited, desired) == edited
    assert all(desired[k] == "0" for k in ("dcredit", "ucredit", "lcredit", "ocredit"))
    assert desired["enforcing"] == "1"


@pytest.mark.parametrize(
    "text",
    [
        "even_deny_root\n",
        "root_unlock_time=900\n",
        "dir=/tmp/tallies\n",
        "debug\n",
    ],
)
def test_lockout_does_not_silently_replace_unknown_or_root_policy(text):
    desired = pam.desired(
        "failed-login-lockout",
        {
            "attempts": 5,
            "interval_seconds": 900,
            "unlock_seconds": 900,
            "exempt_group": "wheel",
        },
    )
    with pytest.raises(ValueError):
        pam.edit(text, desired)


def test_history_configuration_does_not_enable_debug_or_expose_passwords():
    assert pam.desired("password-history", {"remember": 5}) == {"remember": "5"}
    with pytest.raises(ValueError):
        pam.edit("file=/tmp/history\n", {"remember": "5"})


SU = "#%PAM-1.0\nauth sufficient pam_rootok.so\nauth substack system-auth\n"


def test_su_preserves_root_bypass_and_existing_authentication():
    digest = hashlib.sha256(SU.encode()).hexdigest()
    result = sessions.su_candidate(SU, "wheel", digest)
    rows = result.splitlines()
    assert rows[1] == "auth sufficient pam_rootok.so"
    assert rows[2] == "auth required pam_wheel.so use_uid group=wheel # rocky10-hardener-su"
    assert rows[3] == "auth substack system-auth"
    assert sessions.su_candidate(result, "wheel", digest) == result
    changed = sessions.su_candidate(result, "operators", digest)
    assert "group=operators" in changed and "group=wheel" not in changed


@pytest.mark.parametrize(
    "text",
    [
        SU + "auth sufficient pam_permit.so\n",
        SU.replace("pam_rootok.so", "pam_permit.so"),
        SU + "# rocky10-hardener-su\n",
    ],
)
def test_su_rejects_custom_or_forged_layout(text):
    with pytest.raises(ValueError):
        sessions.su_candidate(text, "wheel", hashlib.sha256(SU.encode()).hexdigest())


@pytest.mark.parametrize(
    "kind,parameters",
    [
        ("default-umask", {"mask": "0027"}),
        ("shell-idle-timeout", {"seconds": 900}),
    ],
)
def test_shell_candidate_is_valid_bash_and_noninteractive_noop(kind, parameters):
    candidate = sessions.shell_candidate(kind, [1002, 1001], parameters)
    assert "1001|1002)" in candidate
    subprocess.run(["bash", "-n"], input=candidate, text=True, check=True)
    result = subprocess.run(
        [
            "bash",
            "--noprofile",
            "--norc",
            "-c",
            "umask 0022; " + candidate + "umask; printf '%s' \"$" + '{TMOUT-unset}"',
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout == "0022\nunset"


@pytest.mark.parametrize(
    "control,parameter,value",
    [
        ("auth.password-quality", "minimum_length", 7),
        ("auth.password-history", "remember", 0),
        ("auth.failed-login-lockout", "unlock_seconds", 0),
        ("auth.su-access-policy", "group", "wheel;id"),
        ("auth.default-umask", "mask", "0000"),
        ("auth.shell-idle-timeout", "seconds", 0),
        ("auth.password-aging", "maximum_days", 0),
        ("auth.inactive-account-lock", "days", -1),
        ("accounts.home-permissions", "mode", "0777"),
    ],
)
def test_unsafe_policy_parameters_fail_offline(control, parameter, value):
    catalog = load_catalog()
    # Test draft parameters independently of the execution gate.
    catalog[control]["implemented"] = True
    props = catalog[control]["parameters"]["properties"]
    valid = {}
    for key, schema in props.items():
        if key == "users":
            valid[key] = ["alice"]
        elif schema["type"] == "integer":
            valid[key] = schema["minimum"]
        elif "enum" in schema:
            valid[key] = schema["enum"][0]
        else:
            valid[key] = "wheel"
    valid[parameter] = value
    profile = {
        "schema_version": 1,
        "id": "m10-invalid",
        "revision": 1,
        "target": {"os": "rocky", "major_version": 10, "role": "server"},
        "controls": [{"id": control, "enabled": True, "parameters": valid}],
    }
    with pytest.raises(ValidationError):
        validate(profile, catalog)


def test_m10_requires_explicit_site_parameters():
    catalog = load_catalog()
    for cid in [
        "accounts.home-permissions",
        "accounts.system-login-disabled",
        "auth.default-umask",
        "auth.failed-login-lockout",
        "auth.inactive-account-lock",
        "auth.password-aging",
        "auth.password-history",
        "auth.password-quality",
        "auth.shell-idle-timeout",
        "auth.su-access-policy",
    ]:
        assert catalog[cid]["parameters"]["required"]
        assert all(
            "default" not in schema for schema in catalog[cid]["parameters"]["properties"].values()
        )


def test_vendor_pam_consumers_allow_only_positioned_managed_su_rule():
    text = SU.splitlines(keepends=True)
    rule = "auth required pam_wheel.so use_uid group=wheel # rocky10-hardener-su\n"
    candidate = "".join(text[:2] + [rule] + text[2:])
    assert pam.consumer_text("su", candidate) == SU
    assert pam.consumer_text("passwd", candidate) == candidate
    for altered in (rule + SU, candidate + rule, candidate.replace("group=wheel", "trust")):
        with pytest.raises(ValueError):
            pam.consumer_text("su", altered)


def test_full_generated_pam_comparison_rejects_extra_rules_and_wrong_flags():
    actual = "# Generated header\npassword requisite pam_example.so\n"
    expected = "File /etc/pam.d/system-auth:\npassword requisite pam_example.so\n"
    assert pam.generated_matches("system-auth", actual, expected)
    assert not pam.generated_matches("password-auth", actual, expected)
    assert not pam.generated_matches(
        "system-auth", actual + "password sufficient pam_permit.so\n", expected
    )
    assert not pam.generated_matches(
        "system-auth", actual.replace("requisite", "optional"), expected
    )
    assert pam.generated_matches("system-auth", actual + "# harmless comment\n", expected)


def test_session_replacement_retains_existing_file_ownership(tmp_path, monkeypatch):
    path = tmp_path / "policy"
    path.write_text("old")
    path.chmod(0o640)
    original = path.stat()
    owners = []
    monkeypatch.setattr(sessions.os, "chown", lambda name, uid, gid: owners.append((uid, gid)))
    monkeypatch.setattr(sessions, "run", lambda args: None)
    sessions.replace(path, "new")
    assert path.read_text() == "new"
    assert path.stat().st_mode & 0o777 == 0o640
    assert owners == [(original.st_uid, original.st_gid)]
