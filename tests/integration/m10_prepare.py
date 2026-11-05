"""Provision only named disposable M10 fixtures before saving the baseline snapshot."""

import json
import os
import secrets
import stat

from m10_identity import PRIVATE, IdentityLab


def main():
    lab = IdentityLab(__doc__)
    lab.execute("preflight", "platform-guard", lab.profile(["files.passwd-permissions"]))
    lab.python(
        "from pathlib import Path;"
        "names={r.split(':',1)[0] for r in Path('/etc/passwd').read_text().splitlines()};"
        "assert not names.intersection({'m10human','m10allow','m10deny','m10outside','m10service'});"
        "assert not Path('/etc/systemd/system/hardener-m10-service.service').exists()"
    )
    assert lab.remote("sudo authselect current --raw").strip() == "local"
    passwords = {
        name: secrets.token_urlsafe(24)
        for name in ["m10human", "m10allow", "m10deny", "m10outside"]
    }
    PRIVATE.parent.mkdir(mode=0o700, exist_ok=True)
    if PRIVATE.exists() or PRIVATE.is_symlink():
        info = PRIVATE.lstat()
        assert stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_nlink == 1
    descriptor = os.open(PRIVATE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        os.fchmod(stream.fileno(), 0o600)
        json.dump(passwords, stream)
    lab.python(
        "import subprocess,os;"
        "[subprocess.run(['useradd','-m','-s','/bin/bash',name],check=True) "
        "for name in ['m10human','m10allow','m10deny','m10outside']];"
        "subprocess.run(['usermod','-a','-G','wheel','m10allow'],check=True);"
        "subprocess.run(['useradd','-r','-M','-s','/bin/bash','m10service'],check=True);"
        "os.chmod('/home/m10human',0o755)"
    )
    lab.run(
        lab.ssh + ["sudo chpasswd"],
        input="".join(name + ":" + password + "\n" for name, password in passwords.items()),
    )
    lab.write(
        "/etc/systemd/system/hardener-m10-service.service",
        "[Unit]\nDescription=Disposable identity service fixture\n[Service]\n"
        "User=m10service\nExecStart=/usr/bin/sleep infinity\n[Install]\nWantedBy=multi-user.target\n",
    )
    lab.remote("sudo systemctl daemon-reload; sudo systemctl enable --now hardener-m10-service")
    uid = int(lab.remote("id -u m10service").strip())
    assert 0 < uid < 1000
    lab.finish(
        {
            "human_fixtures": 4,
            "service_fixtures": 1,
            "service_uid_below_1000": True,
            "passwords_stored_outside_reports": True,
            "baseline_snapshot_required_next": True,
        }
    )


if __name__ == "__main__":
    main()
