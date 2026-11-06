"""Prove SELinux assessment and persistent-policy repair over a retained guest session."""

import json
import shlex

from m11 import SecurityLab, load_profile

from hardener.recovery import read_receipt
from hardener.validation import DATA


def main():
    lab = SecurityLab(__doc__)
    read_receipt(lab.args.recovery_evidence, lab.inventory, lab.args.target)
    base = load_profile()
    profile = {**base, "controls": [{"id": "selinux.no-unconfined-services", "enabled": True}]}
    before = lab.execute("audit", "unconfined-before", profile, 5)
    count = before["controls"][0]["observed"]["unconfined_processes"]
    assert count >= 1 and before["changed_tasks"] == 0
    try:
        lab.remote(
            "sudo systemd-run --unit=m11-unconfined --property=SELinuxContext=system_u:system_r:unconfined_service_t:s0 /usr/bin/sleep 120"
        )
        during = lab.execute("verify", "unconfined-fixture", profile, 5)
        assert during["controls"][0]["observed"]["unconfined_processes"] >= count + 1
        assert during["changed_tasks"] == 0
    finally:
        lab.remote("sudo systemctl stop m11-unconfined")
    after = lab.execute("audit", "unconfined-restored", profile, 5)
    assert after["controls"][0]["observed"]["unconfined_processes"] == count
    helper = (
        (DATA / "ansible/helpers/selinux_policy.py")
        .read_text()
        .split('if __name__ == "__main__":')[0]
    )
    code = """from pathlib import Path
import contextlib,io,json,sys
namespace={}
exec(SOURCE,namespace)
p=Path('/etc/selinux/config')
original=p.read_text()
try:
    p.write_text(original.replace('SELINUXTYPE=targeted','SELINUXTYPE=minimum'))
    assert not namespace['inspect']('targeted-policy')[0]['matches']
    sys.argv=['helper','targeted-policy','apply']
    output=io.StringIO()
    with contextlib.redirect_stdout(output): namespace['main']()
    state=json.loads(output.getvalue())
    assert state['supported'] and state['matches'] and state['changed']
    assert namespace['inspect']('targeted-policy')[0]['matches']
finally:
    p.write_text(original)
print(json.dumps({'persistent_type_repaired':True}))
""".replace("SOURCE", repr(helper))
    repair = json.loads(lab.remote("sudo python3 -c " + shlex.quote(code)))
    assert repair["persistent_type_repaired"]
    assert lab.remote("sudo -n id -u").strip() == "0"
    lab.finish(
        {
            "unconfined_assessment_finding": count,
            "isolated_service_detected": True,
            "assessment_zero_changes": True,
            "persistent_type_repaired": True,
            "fresh_admin_preserved": True,
        }
    )


if __name__ == "__main__":
    main()
