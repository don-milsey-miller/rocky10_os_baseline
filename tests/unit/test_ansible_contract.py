import importlib.util
from types import SimpleNamespace

import yaml

from hardener.validation import DATA


def test_read_operations_have_no_remediation():
    files = list((DATA / "ansible/tasks").glob("*.audit.yml"))
    files += list((DATA / "ansible/tasks").glob("*.verify.yml"))
    files += [DATA / "ansible/preflight.yml"]
    allowed = {
        "ansible.builtin.stat",
        "ansible.builtin.command",
        "ansible.builtin.assert",
        "ansible.builtin.setup",
        "ansible.builtin.set_fact",
    }
    for path in files:
        for task in yaml.safe_load(path.read_text()):
            modules = {k for k in task if k.startswith("ansible.builtin.")}
            assert modules <= allowed
            if "ansible.builtin.command" in task:
                assert task["changed_when"] is False
            assert "notify" not in task


def test_callback_does_not_expose_module_secrets():
    path = DATA / "ansible/callback_plugins/hardener_json.py"
    spec = importlib.util.spec_from_file_location("callback", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    callback = module.CallbackModule()
    task = SimpleNamespace(get_name=lambda: "Inspect selected control")
    callback.v2_runner_on_failed(SimpleNamespace(_task=task, _result={"msg": "secret-password"}))
    assert "secret-password" not in str(callback.errors)
    callback.v2_runner_on_ok(SimpleNamespace(_result={"stdout": "secret-key", "changed": False}))
    assert callback.records == {}
    assert callback.changed == 0


def test_every_ansible_file_parses():
    for path in (DATA / "ansible").rglob("*.yml"):
        assert isinstance(yaml.safe_load(path.read_text()), list)
