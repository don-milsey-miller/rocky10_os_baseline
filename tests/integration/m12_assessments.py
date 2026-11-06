"""Disposable isolated metadata faults. Never changes existing application files."""

import sys

from lab import GuestLab

lab = GuestLab("M12 read-only filesystem assessments")
scope = "/srv/hardener-m12-review"
kinds = ["world-writable-review", "unowned-files-review", "privileged-files-review"]
ids = ["filesystem." + k for k in kinds]
parameters = {cid: {"paths": [scope], "max_entries": 100} for cid in ids}
profile = lab.profile(ids, parameters)


def fingerprint():
    return lab.python(
        "import json,os; from pathlib import Path; "
        "p=Path(" + repr(scope) + "); "
        "print(json.dumps([(str(x),x.lstat().st_mode,x.lstat().st_uid,x.lstat().st_gid,"
        "x.read_bytes().hex() if x.is_file() and not x.is_symlink() else None,"
        "{k:os.getxattr(x,k,follow_symlinks=False).hex() for k in os.listxattr(x,follow_symlinks=False)})"
        " for x in sorted(p.rglob('*'))]))"
    )


lab.python(
    "from pathlib import Path; import os; "
    "p=Path(" + repr(scope) + "); p.mkdir(mode=0o755); "
    "(p/'writable').write_text('fixture'); (p/'writable').chmod(0o666); "
    "(p/'unowned').write_text('fixture'); os.chown(p/'unowned',60001,60001); "
    "(p/'privileged').write_text('fixture'); (p/'privileged').chmod(0o4755); "
    "(p/'capability').write_text('fixture'); "
    "(p/'shared').mkdir(mode=0o755); (p/'shared').chmod(0o777); "
    "(p/'link').symlink_to('/etc/passwd')"
)
lab.remote("sudo setcap cap_chown=ep " + scope + "/capability")
before = fingerprint()
for mode in ["audit", "verify"]:
    result = lab.execute(mode, mode + "-faults", profile, expected=5)
    assert result["summary"]["fail"] == 3 and result["changed_tasks"] == 0
    counts = {c["id"]: c["observed"]["finding_count"] for c in result["controls"]}
    assert counts == dict(zip(ids, [2, 1, 2]))
    assert fingerprint() == before
# The CLI must reject applying assessment-only selections without target writes.
source = lab.output / "apply-refused.yaml"
source.write_text(__import__("json").dumps(profile))
argv = [
    sys.executable,
    "-m",
    "hardener.cli",
    "apply",
    "--profile",
    str(source),
    "--inventory",
    str(lab.inventory),
    "--target",
    lab.args.target,
    "--output",
    str(lab.output / "apply-refused"),
]
lab.run(argv, expected=2)
lab.commands.append({"argv": argv, "expected_exit": 2})
assert fingerprint() == before
limited = lab.profile([ids[0]], {ids[0]: {"paths": [scope], "max_entries": 1}})
result = lab.execute("audit", "bounded-failure", limited, expected=4)
assert result["summary"]["error"] == 1 and result["changed_tasks"] == 0
assert fingerprint() == before
lab.python(
    "from pathlib import Path; import os; p=Path(" + repr(scope) + "); "
    "(p/'writable').chmod(0o644); os.chown(p/'unowned',0,0); "
    "(p/'shared').chmod(0o1777)"
)
parameters[ids[2]]["approved_paths"] = [scope + "/privileged", scope + "/capability"]
clean = lab.profile(ids, parameters)
before = fingerprint()
for mode in ["audit", "verify"]:
    result = lab.execute(mode, mode + "-reviewed", clean)
    assert result["summary"]["pass"] == 3 and result["changed_tasks"] == 0
    assert fingerprint() == before
lab.python(
    "from pathlib import Path; p=Path(" + repr(scope) + "); "
    "[(p/x).unlink() for x in ['writable','unowned','privileged','capability','link']]; "
    "(p/'shared').rmdir(); p.rmdir()"
)
lab.finish(
    {
        "read_only": True,
        "fault_counts": [2, 1, 2],
        "approved_privileged_exception": True,
        "incomplete_scan_errors": True,
        "apply_refused": True,
    }
)
