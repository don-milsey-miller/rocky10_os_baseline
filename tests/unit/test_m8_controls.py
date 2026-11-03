import copy
import importlib.util

import pytest

from hardener.validation import DATA, ValidationError, load_catalog, validate


def helper(name):
    spec = importlib.util.spec_from_file_location(name, DATA / f"ansible/helpers/{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ssh = helper("ssh_policy")
sudo = helper("sudo_policy")


def test_ssh_edit_preserves_unselected_policy_and_clears_selected_lists():
    text = "# retained\nPermitRootLogin yes\nMaxAuthTries 3\nAllowGroups wheel\n"
    desired = {"PermitRootLogin": "no", "AllowGroups": []}
    result = ssh.edit(text, desired)
    assert result == "# retained\nPermitRootLogin no\nMaxAuthTries 3\n"
    assert ssh.edit(result, desired) == result


def test_ssh_effective_lists_and_numeric_startup_limits():
    values = ssh.parse_effective("hostkey /etc/ssh/a\nhostkey /etc/ssh/b\nallowusers zero test\n")
    assert values["hostkey"] == ["/etc/ssh/a", "/etc/ssh/b"]
    assert ssh.matches(values, {"AllowUsers": ["test", "zero"], "AllowGroups": []})
    assert ssh.matches({"maxstartups": "10:30:10"}, {"MaxStartups": "10"})
    assert not ssh.matches({"maxstartups": "10:30:100"}, {"MaxStartups": "10"})


@pytest.mark.parametrize("user,address", [("zero,host=other", "127.0.0.1"), ("zero", "bad")])
def test_ssh_connection_context_cannot_inject_native_options(user, address):
    with pytest.raises(ValueError):
        ssh.context_arg({"user": user, "connection": [address, "123", "127.0.0.1", "22"]})


def test_ssh_connection_context_accepts_ipv6():
    result = ssh.context_arg({"user": "zero", "connection": ["::1", "123", "::1", "22"]})
    assert result == "user=zero,host=::1,addr=::1,laddr=::1,lport=22"


def grant(authenticate=False):
    return {
        "User_List": [{"username": "testadmin"}],
        "Host_List": [{"hostname": "ALL"}],
        "Cmnd_Specs": [
            {
                "runasusers": [{"username": "ALL"}],
                "Options": [{"authenticate": authenticate}, {"setenv": True}],
                "Commands": [{"command": "ALL"}],
            }
        ],
    }


def test_authentication_edits_never_create_grants_or_copy_group_privileges():
    main = sudo.MAIN
    text = (
        "# retained\n%wheel ALL=(ALL) NOPASSWD: ALL\n"
        "testadmin ALL=(ALL) NOPASSWD: ALL # selected\n"
        "other ALL=(ALL) NOPASSWD: ALL\n"
    )
    result = sudo.authentication_edits({main: text}, ["testadmin"])
    assert result[main] == text.replace(
        "testadmin ALL=(ALL) NOPASSWD: ALL", "testadmin ALL=(ALL) PASSWD: ALL"
    )
    assert sudo.authentication_edits(result, ["testadmin"]) == result
    assert sudo.authentication_edits({main: text}, ["groupmember"])[main] == text
    assert "groupmember" not in result[main]


def test_sudo_user_evaluation_preserves_last_matching_authentication_tag():
    document = {"User_Specs": [grant(False), grant(True)]}
    assert sudo.user_state(document) == {"supported": True, "authenticated": True, "timeout": None}
    document["User_Specs"].reverse()
    assert sudo.user_state(document)["authenticated"] is False


@pytest.mark.parametrize(
    "mutation",
    [
        lambda r: r["Cmnd_Specs"][0]["Commands"].append(
            {"command": "/usr/bin/id", "negated": True}
        ),
        lambda r: r["Cmnd_Specs"][0]["Options"].append({"noexec": True}),
        lambda r: r["Cmnd_Specs"][0].update(runasgroups=[{"usergroup": "ALL"}]),
        lambda r: r.update(Host_List=[{"hostname": "other"}]),
        lambda r: r["Cmnd_Specs"][0]["Options"].append({"setenv": False}),
    ],
)
def test_unmodeled_grants_are_refused_instead_of_rewritten(mutation):
    rule = grant()
    mutation(rule)
    assert sudo.user_state({"User_Specs": [rule]})["supported"] is False


@pytest.mark.parametrize(
    "option",
    [
        {"rootpw": True},
        {"targetpw": True},
        {"runaspw": True},
        {"exempt_group": "special"},
        {"group_plugin": "custom"},
    ],
)
def test_nonstandard_authentication_defaults_require_review(option):
    document = {"User_Specs": [grant()], "Defaults": [{"Options": [option]}]}
    assert sudo.user_state(document)["supported"] is False


def test_scoped_command_timeout_is_not_mistaken_for_user_policy():
    document = {
        "User_Specs": [grant(True)],
        "Defaults": [
            {"Binding": [{"command": "/usr/bin/id"}], "Options": [{"timestamp_timeout": "0"}]}
        ],
    }
    assert sudo.user_state(document)["supported"] is False


def test_scoped_pty_exception_cannot_be_hidden_by_later_global_policy():
    document = {
        "Defaults": [
            {"Binding": [{"username": "other"}], "Options": [{"use_pty": False}]},
            {"Options": [{"use_pty": True}]},
        ]
    }
    assert sudo.pty_state(document) == {"matches": False, "scoped_conflict": True}


def test_timeout_edit_preserves_unselected_subjects():
    text = (
        "# retained\nDefaults:other timestamp_timeout=10\nDefaults:testadmin timestamp_timeout=-1\n"
    )
    desired = {"users": ["testadmin"], "minutes": 0}
    result = sudo.edit(text, "timeout", desired)
    assert result == text.replace("timestamp_timeout=-1", "timestamp_timeout=0")
    assert sudo.edit(result, "timeout", desired) == result
    with pytest.raises(ValueError):
        sudo.edit("Defaults !authenticate\n", "timeout", desired)


def access_profile(parameters):
    return {
        "schema_version": 1,
        "id": "m8-unit",
        "revision": 1,
        "target": {"os": "rocky", "major_version": 10, "role": "server"},
        "controls": [
            {"id": "auth.ssh-config-permissions", "enabled": True},
            {"id": "auth.ssh-hostkey-permissions", "enabled": True},
            {"id": "auth.ssh-access-policy", "enabled": True, "parameters": parameters},
        ],
    }


def test_access_policies_require_explicit_bounded_names():
    base = {"users": ["zero"], "groups": []}
    validate(access_profile(base), load_catalog())
    for bad in [
        {"users": [], "groups": []},
        {"users": ["zero", "zero"], "groups": []},
        {"users": ["zero ALL=(ALL)"], "groups": []},
        {"users": ["zero"]},
    ]:
        with pytest.raises(ValidationError):
            validate(access_profile(bad), load_catalog())
    document = access_profile(copy.deepcopy(base))
    document["controls"][-1]["parameters"]["groups"] = ["*"]
    with pytest.raises(ValidationError):
        validate(document, load_catalog())


def test_independent_ssh_controls_do_not_reorder_each_other():
    policies = [
        {"PermitRootLogin": "no"},
        {"PasswordAuthentication": "no"},
        {"AllowUsers": ["zero"]},
    ]
    first = ""
    for policy in policies:
        first = ssh.edit(first, policy)
    second = first
    for policy in policies:
        second = ssh.edit(second, policy)
    assert second == first


@pytest.mark.parametrize(
    "cid,parameter,value",
    [
        ("auth.ssh-session-limits", "max_auth_tries", 0),
        ("auth.ssh-session-limits", "max_auth_tries", 7),
        ("auth.ssh-session-limits", "max_sessions", 33),
        ("auth.ssh-session-limits", "max_startups", 0),
        ("auth.ssh-session-limits", "login_grace_seconds", 0),
        ("auth.ssh-session-limits", "idle_session_seconds", 29),
        ("auth.ssh-forwarding-policy", "tcp", "unexpected"),
        ("auth.ssh-forwarding-policy", "agent", "false"),
        ("auth.sudo-timeout", "minutes", -1),
        ("auth.sudo-timeout", "minutes", 61),
        ("auth.sudo-authentication", "users", ["zero", "zero"]),
    ],
)
def test_access_parameter_boundaries(cid, parameter, value):
    from pathlib import Path

    import yaml

    source = Path(__file__).resolve().parents[2] / "profiles/examples/server-access-lab.yaml"
    profile = yaml.safe_load(source.read_text())
    validate(profile, load_catalog())
    selected = next(row for row in profile["controls"] if row["id"] == cid)
    selected["parameters"][parameter] = value
    with pytest.raises(ValidationError):
        validate(profile, load_catalog())


def test_session_timeout_covers_native_extended_channel_types():
    import fnmatch

    import yaml

    for operation in ["audit", "apply", "verify", "preflight"]:
        path = DATA / f"ansible/tasks/auth.ssh-session-limits.{operation}.yml"
        value = yaml.safe_load(path.read_text())[0]["vars"]["ssh_values"]["ChannelTimeout"]
        pattern = value.split("=", 1)[0]
        for channel in ["session", "session:shell", "session:command", "session:subsystem:sftp"]:
            assert fnmatch.fnmatchcase(channel, pattern)
        assert not fnmatch.fnmatchcase("direct-tcpip", pattern)


def test_removed_ssh_dropin_still_invalidates_load_evidence(tmp_path, monkeypatch):
    import os
    import time

    drop = tmp_path / "sshd_config.d"
    drop.mkdir()
    main = tmp_path / "sshd_config"
    main.write_text("# fixture")
    removed = drop / "removed.conf"
    removed.write_text("PermitEmptyPasswords yes")
    removed.unlink()
    changed = time.time() + 10
    os.utime(drop, (changed, changed))
    monkeypatch.setattr(ssh, "DROP", drop)
    monkeypatch.setattr(ssh, "CRYPTO", str(tmp_path / "absent-crypto"))
    assert ssh.configuration_changed_at([main]) >= changed


@pytest.mark.parametrize(
    "text",
    [
        "Path plugin_dir /tmp/custom",
        "Plugin sudoers_policy custom.so",
        "Set group_source dynamic",
    ],
)
def test_custom_sudo_plugin_configuration_is_not_treated_as_local_default(text):
    assert not sudo.plugin_configuration_supported(text)


def test_standard_sudo_plugin_configuration_and_source_whitespace():
    assert sudo.plugin_configuration_supported("# defaults only")
    assert sudo.plugin_configuration_supported("Set disable_coredump false")
    assert sudo.plugin_configuration_supported("Set disable_coredump true")
    assert sudo.plugin_configuration_supported("Plugin sudoers_policy sudoers.so")
    assert sudo.sources_supported("sudoers : files # local")
    assert not sudo.sources_supported("sudoers : files sss")
    assert not sudo.sources_supported("sudoers:\tldap")
