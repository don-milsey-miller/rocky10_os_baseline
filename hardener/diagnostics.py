"""Only bounded diagnostic fields intentionally approved for public reports."""

import re
from functools import lru_cache

import yaml

from hardener.validation import DATA


def network_diagnostic(value):
    if not isinstance(value, dict) or value.get("code") != "network-policy-conflict":
        return None
    cid = value.get("control_id", "")
    if not re.fullmatch(r"network\.[a-z0-9-]{1,64}", cid):
        return None
    details = []
    for item in value.get("blockers", [])[:16]:
        if not isinstance(item, str):
            continue
        if re.fullmatch(
            r"/(?:etc|run|usr/lib|usr/local/lib)/sysctl(?:\.conf|\.d/[A-Za-z0-9_.-]{1,128}\.conf)",
            item,
        ):
            details.append("Conflicting configuration: " + item)
        elif (
            re.fullmatch(r"unsupported network interface: [A-Za-z0-9_.:-]{1,15}", item)
            or re.fullmatch(r"forwarding-capable NetworkManager profile: [a-fA-F0-9-]{36}", item)
            or re.fullmatch(
                r"active routing/container/network service: [A-Za-z0-9_.@-]{1,100}", item
            )
        ):
            details.append(item)
        elif item.startswith("NetworkManager forwarding default:"):
            details.append(
                "NetworkManager has a forwarding-enabled connection default. Inspect its effective configuration."
            )
        else:
            details.append(
                "Additional policy conflict. Run audit and inspect effective sysctl and NetworkManager configuration."
            )
    if value.get("unsafe_file") is True:
        details.append(
            "Inspect ownership, links, permissions, ACLs and unrelated assignments in /etc/sysctl.d/99-rocky10-"
            + cid.replace(".", "-")
            + ".conf and its parent."
        )
    return {
        "code": "network-policy-conflict",
        "control_id": cid,
        "reason": "Reconcile the listed configuration or workload conflicts before applying this control.",
        "details": details,
    }


@lru_cache(maxsize=1)
def approved_assertions():
    reasons = set()

    def visit(value):
        if isinstance(value, dict):
            assertion = value.get("ansible.builtin.assert", {})
            reason = assertion.get("fail_msg") if isinstance(assertion, dict) else None
            if (
                isinstance(reason, str)
                and len(reason) <= 512
                and "{{" not in reason
                and "{%" not in reason
            ):
                reasons.add(reason)
            for item in value.values():
                visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    for path in (DATA / "ansible").rglob("*.yml"):
        visit(yaml.safe_load(path.read_text()))
    return reasons


def assertion_reason(task):
    if getattr(task, "action", None) not in {"assert", "ansible.builtin.assert"}:
        return None
    reason = getattr(task, "args", {}).get("fail_msg")
    if isinstance(reason, str) and reason in approved_assertions():
        return " ".join(reason.split())
    return None


def recovery_observation(value):
    if not isinstance(value, dict):
        return None
    machine = value.get("machine_id")
    boot = value.get("boot_id")
    marker = value.get("marker_present")
    if not isinstance(machine, str) or not re.fullmatch(r"[a-f0-9]{32}", machine):
        return None
    if not isinstance(boot, str) or not re.fullmatch(
        r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", boot
    ):
        return None
    if type(marker) is not bool:
        return None
    return {"machine_id": machine, "boot_id": boot, "marker_present": marker}
