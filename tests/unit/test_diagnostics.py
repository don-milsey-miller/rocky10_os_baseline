"""Refusal reports retain approved reasons without forwarding raw module data."""

import importlib.util
from types import SimpleNamespace

from hardener.diagnostics import assertion_reason, network_diagnostic, recovery_observation
from hardener.validation import DATA


def callback():
    spec = importlib.util.spec_from_file_location(
        "diagnostic_callback", DATA / "ansible/callback_plugins/hardener_json.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.CallbackModule()


def test_only_static_assertion_messages_are_reported():
    task = SimpleNamespace(
        action="ansible.builtin.assert",
        args={"fail_msg": "Configure working Ansible privilege escalation."},
    )
    assert assertion_reason(task) == "Configure working Ansible privilege escalation."
    task.args["fail_msg"] = "private-rendered-secret"
    assert assertion_reason(task) is None
    task.args["fail_msg"] = "{{ secret }}"
    assert assertion_reason(task) is None
    task.args["fail_msg"] = "x" * 513
    assert assertion_reason(task) is None
    task.action = "ansible.builtin.command"
    task.args["fail_msg"] = "raw secret"
    assert assertion_reason(task) is None


def test_network_conflicts_are_bounded_and_redacted():
    value = {
        "code": "network-policy-conflict",
        "control_id": "network.reverse-path-filter",
        "unsafe_file": True,
        "blockers": [
            "/etc/sysctl.d/zz-conflict.conf",
            "unsupported network interface: veth0",
            "NetworkManager forwarding default: connection.private-sentinel",
            "private-sentinel\n",
        ]
        * 20,
    }
    result = network_diagnostic(value)
    assert len(result["details"]) == 17
    assert "/etc/sysctl.d/zz-conflict.conf" in str(result)
    assert "veth0" in str(result)
    assert "private-sentinel" not in str(result)
    assert "99-rocky10-network-reverse-path-filter.conf" in str(result)
    assert network_diagnostic({**value, "control_id": "{{ private-sentinel }}"}) is None


def test_callback_attaches_diagnostic_only_to_next_failure():
    cb = callback()
    value = {
        "code": "network-policy-conflict",
        "control_id": "network.reverse-path-filter",
        "blockers": ["/etc/sysctl.d/zz-conflict.conf"],
    }
    cb.v2_runner_on_ok(
        SimpleNamespace(
            _result={"ansible_facts": {"hardener_diagnostic": value}, "stdout": "private-sentinel"}
        )
    )
    task = SimpleNamespace(
        get_name=lambda: "Require network policy",
        action="ansible.builtin.assert",
        args={"fail_msg": "Configure working Ansible privilege escalation."},
    )
    failed = SimpleNamespace(
        _task=task, _result={"msg": "private-sentinel", "stderr": "private-sentinel"}
    )
    cb.v2_runner_on_failed(failed)
    cb.v2_runner_on_failed(failed)
    assert cb.errors[0]["code"] == "network-policy-conflict"
    assert "details" not in cb.errors[1]
    assert cb.errors[1]["reason"] == "Configure working Ansible privilege escalation."
    assert "private-sentinel" not in str(cb.errors)


def test_recovery_observations_are_allowlisted():
    value = {
        "machine_id": "a" * 32,
        "boot_id": "11111111-1111-1111-1111-111111111111",
        "marker_present": False,
        "secret": "private-sentinel",
    }
    assert "secret" not in recovery_observation(value)
    assert recovery_observation({**value, "machine_id": "private-sentinel"}) is None
    assert recovery_observation({**value, "marker_present": "false"}) is None
