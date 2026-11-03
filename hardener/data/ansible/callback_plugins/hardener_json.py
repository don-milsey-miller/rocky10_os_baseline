"""Emit only allowlisted evidence, never raw module output or inventory."""

import json

from ansible.plugins.callback import CallbackBase


class CallbackModule(CallbackBase):
    CALLBACK_VERSION = 2.0
    CALLBACK_TYPE = "stdout"
    CALLBACK_NAME = "hardener_json"

    def __init__(self):
        super().__init__()
        self.records = {}
        self.errors = []
        self.preflight = False
        self.changed = 0

    def v2_runner_on_ok(self, result):
        data = result._result
        self.changed += int(bool(data.get("changed", False)))
        facts = data.get("ansible_facts", {})
        if facts.get("hardener_preflight_passed") is True:
            self.preflight = True
        record = facts.get("hardener_record")
        if record:
            self.records[record["id"]] = record

    def v2_runner_on_failed(self, result, ignore_errors=False):
        self.changed += int(bool(result._result.get("changed", False)))
        self.errors.append({"task": result._task.get_name(), "kind": "failed"})

    def v2_runner_on_unreachable(self, result):
        self.errors.append({"task": "SSH reachability", "kind": "unreachable"})

    def v2_playbook_on_stats(self, stats):
        self._display.display(
            json.dumps(
                {
                    "records": self.records,
                    "errors": self.errors,
                    "preflight_passed": self.preflight,
                    "changed_tasks": self.changed,
                }
            )
        )
