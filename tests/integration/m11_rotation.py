"""Exercise native audit rotation and retention without filling a filesystem."""

import json
import time
import uuid

from m11 import SecurityLab, load_profile


def main():
    lab = SecurityLab(__doc__)
    profile = load_profile()
    profile["controls"] = [
        c
        for c in profile["controls"]
        if c["id"] in ("audit.service-enabled", "audit.storage-policy")
    ]
    lab.execute("verify", "before", profile)
    for index in range(6):
        before = lab.remote("sudo stat -c %i /var/log/audit/audit.log").strip()
        lab.remote("sudo auditctl --signal rotate")
        for _ in range(20):
            after = lab.remote("sudo stat -c %i /var/log/audit/audit.log").strip()
            if after != before:
                break
            time.sleep(0.1)
        else:
            raise AssertionError("Native audit rotation did not replace the active file")
        marker = "m11-rotation-" + str(index) + "-" + uuid.uuid4().hex
        lab.remote("sudo auditctl -m " + marker)
        time.sleep(0.2)
        assert (
            lab.python(
                "from pathlib import Path; print("
                + repr(marker)
                + " in Path('/var/log/audit/audit.log').read_text())"
            ).strip()
            == "True"
        )
    state = json.loads(
        lab.python("""import json,re,stat
from pathlib import Path
files=[p for p in Path('/var/log/audit').glob('audit.log*') if re.fullmatch(r'audit[.]log(?:[.][0-9]+)?',p.name)]
print(json.dumps({'files':len(files),'bounded_sizes':all(p.stat().st_size<=21*1024*1024 for p in files),'root_owned_private':all(p.stat().st_uid==0 and stat.S_IMODE(p.stat().st_mode)&0o077==0 for p in files)}))
""")
    )
    assert state["files"] == 5 and state["bounded_sizes"] and state["root_owned_private"], state
    assert "lost 0" in lab.remote("sudo auditctl -s")
    lab.execute("verify", "after", profile)
    lab.finish(
        {
            "native_rotations": 6,
            "retained_files": 5,
            "continued_recording": True,
            "private_log_permissions": True,
            "lost_audit_events": 0,
        }
    )


if __name__ == "__main__":
    main()
