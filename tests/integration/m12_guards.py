"""Reject unsafe M12 targets before any selected write."""

import copy
from pathlib import Path

import yaml
from m11 import SecurityLab

lab = SecurityLab(__doc__)
source = yaml.safe_load(Path("profiles/examples/server-storage-boot-lab.yaml").read_text())
controls = {c["id"]: c for c in source["controls"]}
results = []


def fingerprint():
    return lab.python("""import hashlib,json,os
from pathlib import Path
paths=[Path('/etc/fstab'),Path('/etc/issue'),Path('/etc/shadow'),Path('/etc/cron.allow'),Path('/etc/at.allow')]
for directory,pattern in [('/boot/grub2','*'),('/boot/loader/entries','*.conf'),('/etc/modprobe.d','*.conf'),('/etc/dracut.conf.d','*.conf'),('/etc/systemd/system','*.service.d/*.conf')]:
 paths.extend(Path(directory).glob(pattern))
data={}
for p in paths:
 if p.is_file() and not p.is_symlink():
  s=p.stat();data[str(p)]=[hashlib.sha256(p.read_bytes()).hexdigest(),s.st_mode,s.st_uid,s.st_gid]
data['canary']=Path('/srv/hardener-m12-shared').stat().st_mode
print(hashlib.sha256(json.dumps(data,sort_keys=True).encode()).hexdigest())
""").strip()


def case(name, cid, setup, cleanup, parameters=None):
    compile(setup, name + "-setup", "exec")
    compile(cleanup, name + "-cleanup", "exec")
    profile = copy.deepcopy(source)
    profile["controls"] = [
        copy.deepcopy(controls[cid]),
        copy.deepcopy(controls["filesystem.shared-directory-sticky"]),
    ]
    if parameters is not None:
        profile["controls"][0]["parameters"] = parameters
    lab.python("from pathlib import Path;Path('/srv/hardener-m12-shared').chmod(0o777)")
    try:
        lab.python(setup)
        before = fingerprint()
        report = lab.execute("apply", name, profile, expected=3)
        assert report["changed_tasks"] == 0 and not report["preflight_passed"]
        assert fingerprint() == before
        results.append(name)
        print(name + " refused without changes", flush=True)
    finally:
        lab.python(cleanup)
        if name == "loaded-module":
            lab.reboot()
        lab.python("from pathlib import Path;Path('/srv/hardener-m12-shared').chmod(0o1777)")


case(
    "critical-service",
    "services.legacy-listeners-disabled",
    "pass",
    "pass",
    {"units": ["sshd.service"]},
)
case(
    "duplicate-fstab",
    "filesystem.tmp-restrictions",
    """from pathlib import Path
p=Path('/etc/fstab');b=Path('/root/.hardener-m12/fstab-guard');b.write_bytes(p.read_bytes())
line=next(x for x in p.read_text().splitlines() if len(x.split())>1 and x.split()[1]=='/tmp')
with p.open('a') as f:f.write(line+'\\n')
""",
    """from pathlib import Path
p=Path('/root/.hardener-m12/fstab-guard');Path('/etc/fstab').write_bytes(p.read_bytes());p.unlink()
""",
)
case(
    "mount-override",
    "filesystem.tmp-restrictions",
    """from pathlib import Path
import subprocess
p=Path('/etc/systemd/system/tmp.mount.d');p.mkdir()
(p/'90-m12-guard.conf').write_text('[Unit]\\nDescription=custom mount\\n')
subprocess.run(['systemctl','daemon-reload'],check=True)
""",
    """from pathlib import Path
import subprocess
p=Path('/etc/systemd/system/tmp.mount.d');(p/'90-m12-guard.conf').unlink();p.rmdir()
subprocess.run(['systemctl','daemon-reload'],check=True)
""",
)
case(
    "loaded-module",
    "kernel.unused-network-protocols",
    "import subprocess;subprocess.run(['modprobe','--ignore-install','sctp'],check=True)",
    "pass",
)
case(
    "competing-module-policy",
    "kernel.unused-network-protocols",
    "from pathlib import Path;Path('/etc/modprobe.d/01-m12-guard.conf').write_text('install sctp /bin/true\\n')",
    "from pathlib import Path;Path('/etc/modprobe.d/01-m12-guard.conf').unlink()",
)
case(
    "public-credential",
    "boot.loader-authentication",
    "from pathlib import Path;Path('/root/.hardener-m12/grub.hash').chmod(0o644)",
    "from pathlib import Path;Path('/root/.hardener-m12/grub.hash').chmod(0o600)",
)
case(
    "symlink-credential",
    "boot.loader-authentication",
    "from pathlib import Path;Path('/root/.hardener-m12/link.hash').symlink_to('/root/.hardener-m12/grub.hash')",
    "from pathlib import Path;Path('/root/.hardener-m12/link.hash').unlink()",
    {"hash_file": "/root/.hardener-m12/link.hash"},
)
case(
    "grub-auth-override",
    "boot.loader-authentication",
    """from pathlib import Path
p=Path('/boot/grub2/grub.cfg');b=Path('/root/.hardener-m12/grub-guard');b.write_bytes(p.read_bytes())
with p.open('a') as f:f.write('\\nset superusers=""\\n')
""",
    """from pathlib import Path
p=Path('/root/.hardener-m12/grub-guard');Path('/boot/grub2/grub.cfg').write_bytes(p.read_bytes());p.unlink()
""",
)
case(
    "supplemental-grub",
    "boot.loader-authentication",
    "from pathlib import Path;Path('/boot/grub2/custom.cfg').write_text('set superusers=\"\"')",
    "from pathlib import Path;Path('/boot/grub2/custom.cfg').unlink()",
)
case(
    "rescue-bypass-override",
    "boot.rescue-authentication",
    """from pathlib import Path
import subprocess
Path('/etc/systemd/system/rescue.service.d/99-m12-guard.conf').write_text('[Service]\\nEnvironment=SYSTEMD_SULOGIN_FORCE=1\\n')
subprocess.run(['systemctl','daemon-reload'],check=True)
""",
    """from pathlib import Path
import subprocess
Path('/etc/systemd/system/rescue.service.d/99-m12-guard.conf').unlink()
subprocess.run(['systemctl','daemon-reload'],check=True)
""",
)
case(
    "crypto-custom-policy",
    "crypto.system-policy",
    "from pathlib import Path;Path('/etc/crypto-policies/policies/modules/M12GUARD.pmod').write_text('min_rsa_size = 1024\\n')",
    "from pathlib import Path;Path('/etc/crypto-policies/policies/modules/M12GUARD.pmod').unlink()",
)
case(
    "preserve-cron-owner",
    "services.cron-access",
    "import subprocess;subprocess.run(['crontab','-u','m12denied','-'],input='0 0 1 1 * /bin/true\\n',text=True,check=True)",
    "import subprocess;subprocess.run(['crontab','-u','m12denied','-r'],check=True)",
)
case(
    "supplemental-notice",
    "login.authorized-use-banner",
    "from pathlib import Path;Path('/etc/issue.d/m12-guard.issue').write_text('M12-private-sentinel\\n')",
    "from pathlib import Path;Path('/etc/issue.d/m12-guard.issue').unlink()",
)
case(
    "preserve-at-owner",
    "services.at-access",
    """from pathlib import Path
import subprocess
p=Path('/etc/at.allow');p.write_text(p.read_text()+'m12denied\\n')
try:
 subprocess.run(['runuser','-u','m12denied','--','at','now','+','1','day'],input='/bin/true\\n',text=True,check=True,capture_output=True)
finally:p.write_text('m12allowed\\nroot\\n')
""",
    """import subprocess
for row in subprocess.check_output(['atq'],text=True).splitlines():
 if row.split()[-1]=='m12denied':subprocess.run(['atrm',row.split()[0]],check=True)
""",
)
case(
    "required-listener",
    "services.legacy-listeners-disabled",
    """from pathlib import Path
import subprocess
subprocess.run(['systemctl','unmask','m12-obsolete.socket','m12-obsolete.service'],check=True,capture_output=True)
Path('/etc/systemd/system/m12-required.service').write_text('[Unit]\\nRequires=m12-obsolete.socket\\nAfter=m12-obsolete.socket\\n[Service]\\nExecStart=/usr/bin/sleep infinity\\n')
subprocess.run(['systemctl','daemon-reload'],check=True)
subprocess.run(['systemctl','start','m12-required.service'],check=True)
""",
    """from pathlib import Path
import subprocess
subprocess.run(['systemctl','stop','m12-required.service','m12-obsolete.socket','m12-obsolete.service'],check=True)
Path('/etc/systemd/system/m12-required.service').unlink()
subprocess.run(['systemctl','mask','m12-obsolete.socket','m12-obsolete.service'],check=True,capture_output=True)
subprocess.run(['systemctl','daemon-reload'],check=True)
""",
)
assert "M12-private-sentinel" not in "\n".join(p.read_text() for p in lab.output.rglob("*.json"))
# Matching notice text must not allow a native supplemental machine URL to survive.
banner = copy.deepcopy(source)
banner["controls"] = [copy.deepcopy(controls["login.authorized-use-banner"])]
lab.python(
    "from pathlib import Path;Path('/etc/issue.d/cockpit.issue').symlink_to('../../run/cockpit/issue')"
)
result = lab.execute("audit", "supplement-with-matching-banner", banner, expected=5)
assert result["summary"]["fail"] == 1 and result["changed_tasks"] == 0
result = lab.execute("apply", "remove-native-supplement", banner)
assert result["changed_tasks"] > 0 and result["summary"]["pass"] == 1
assert lab.execute("apply", "repeat-native-supplement", banner)["changed_tasks"] == 0

# A native remount rejection after the fstab write must retain partial-change evidence.
mount = copy.deepcopy(source)
mount["controls"] = [copy.deepcopy(controls["filesystem.tmp-restrictions"])]
lab.python("""from pathlib import Path
p=Path('/etc/fstab');b=Path('/root/.hardener-m12/partial-fstab');b.write_bytes(p.read_bytes())
rows=p.read_text().splitlines(keepends=True)
for i,row in enumerate(rows):
 if len(row.split())>1 and row.split()[1]=='/tmp':
  fields=row.split();old=fields[3];new=','.join(v for v in old.split(',') if v!='nosuid')+',m12_unsupported_option'
  rows[i]=row.replace(old,new,1)
p.write_text(''.join(rows))
""")
try:
    result = lab.execute("apply", "native-partial-remount-failure", mount, expected=4)
    assert result["preflight_passed"] and result["changed_tasks"] > 0
    assert result["controls"][0]["changed"] is True
    assert result["controls"][0]["status"] == "error"
finally:
    lab.python("""from pathlib import Path
import subprocess
p=Path('/root/.hardener-m12/partial-fstab');Path('/etc/fstab').write_bytes(p.read_bytes());p.unlink()
subprocess.run(['systemctl','daemon-reload'],check=True)
""")
assert lab.execute("verify", "mount-recovered", mount)["summary"]["pass"] == 1
lab.finish(
    {
        "unsafe_preflight_cases": results,
        "all_selected_writes_blocked": True,
        "secret_content_withheld": True,
        "matching_notice_supplement_removed": True,
        "partial_failure_retains_changes": True,
    }
)
