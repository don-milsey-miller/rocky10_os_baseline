"""M12 lifecycle against the approved, snapshotted disposable guest."""

import copy
import json
import subprocess
from pathlib import Path

import yaml
from m11 import SecurityLab

lab = SecurityLab(__doc__)
profile = yaml.safe_load(Path("profiles/examples/server-storage-boot-lab.yaml").read_text())


def state():
    return lab.python("""import hashlib,json,stat,os
from pathlib import Path
paths=[Path('/etc/fstab'),Path('/etc/issue'),Path('/etc/shadow')]
for folder,pattern in [('/etc/modprobe.d','*rocky10*.conf'),('/etc/dracut.conf.d','*rocky10*.conf'),('/boot/grub2','*'),('/boot/loader/entries','*.conf'),('/etc/systemd/system','*.service.d/*rocky10*.conf')]:
 paths.extend(Path(folder).glob(pattern))
paths += [Path('/etc/cron.allow'),Path('/etc/at.allow')]
rows={}
for p in paths:
 if p.is_file() and not p.is_symlink():
  s=p.stat();rows[str(p)]=[hashlib.sha256(p.read_bytes()).hexdigest(),s.st_mode,s.st_uid,s.st_gid,sorted(os.listxattr(p))]
print(hashlib.sha256(json.dumps(rows,sort_keys=True).encode()).hexdigest())
""").strip()


before = state()
report = lab.execute("audit", "audit-before", profile, expected=5)
assert report["summary"]["fail"] == 15, report["summary"]
assert report["changed_tasks"] == 0 and state() == before
print("initial audit passed", flush=True)
# An excluded or omitted independent directory control cannot change its metadata.
partial = copy.deepcopy(profile)
for item in partial["controls"]:
    if item["id"] == "filesystem.shared-directory-sticky":
        item["enabled"] = False
        item["reason"] = "Selection boundary fixture"
    if item["id"] == "crypto.system-policy":
        item["enabled"] = False
        item["reason"] = "Reboot policy tested separately"
report = lab.execute("apply", "selected-exclusion", partial)
assert report["summary"]["pass"] == 13
assert (
    lab.python("import os;print(oct(os.stat('/srv/hardener-m12-shared').st_mode & 0o7777))").strip()
    == "0o777"
)
partial["controls"] = [
    c for c in partial["controls"] if c["id"] != "filesystem.shared-directory-sticky"
]
report = lab.execute("apply", "selected-omission", partial)
assert report["changed_tasks"] == 0
assert (
    lab.python("import os;print(oct(os.stat('/srv/hardener-m12-shared').st_mode & 0o7777))").strip()
    == "0o777"
)
print("exclusion and omission passed", flush=True)
report = lab.execute("apply", "full-apply-pending", profile, expected=5)
failed = [c for c in report["controls"] if c["status"] != "pass"]
assert len(failed) == 1 and failed[0]["id"] == "crypto.system-policy"
assert failed[0]["reboot_required"] is True
report = lab.execute("apply", "repeat-pending", profile, expected=5)
assert report["changed_tasks"] == 0
lab.reboot()
# kdump can regenerate a boot image during startup. Inspect only after provisioning settles.
lab.python("""import subprocess,time
for _ in range(90):
 result=subprocess.run(['systemctl','show','kdump.service','-p','ActiveState','--value'],capture_output=True,text=True,check=True)
 if result.stdout.strip() != 'activating': break
 time.sleep(1)
else: raise AssertionError('kdump provisioning did not settle')
""")
report = lab.execute("verify", "verify-reboot", profile)
assert report["summary"]["pass"] == 15 and report["changed_tasks"] == 0
before = state()
report = lab.execute("apply", "repeat-accepted", profile)
assert report["summary"]["pass"] == 15 and report["changed_tasks"] == 0 and state() == before
print("reboot and repeat passed", flush=True)
native = lab.python("""import subprocess,os,socket,stat,json,time
from pathlib import Path
def run(args):return subprocess.run(args,capture_output=True,text=True,check=False,timeout=30)
for directory in ['/tmp','/var/tmp','/dev/shm']:
 p=Path(directory)/'hardener-m12-exec'
 subprocess.run(['cp','/usr/bin/true',str(p)],check=True);p.chmod(0o755)
 try:
  try:subprocess.run([str(p)],check=False);raise AssertionError('Execution was permitted')
  except PermissionError:pass
 finally:p.unlink()
p=Path('/home/hardener-m12-id')
subprocess.run(['cp','/usr/bin/id',str(p)],check=True);p.chmod(0o4755)
try:
 expected=run(['id','-u','m12allowed']).stdout.strip()
 actual=run(['runuser','-u','m12allowed','--',str(p),'-u'])
 assert actual.returncode==0 and actual.stdout.strip()==expected
finally:p.unlink()
p=Path('/home/hardener-m12-null')
os.mknod(p,stat.S_IFCHR|0o666,os.makedev(1,3))
try:
 try:
  with p.open('wb') as f:f.write(b'x')
  raise AssertionError('Device access was permitted')
 except PermissionError:pass
finally:p.unlink()
p=Path('/srv/hardener-m12-shared/owned')
p.write_text('preserve');uid=int(run(['id','-u','m12allowed']).stdout);os.chown(p,uid,uid);p.chmod(0o666)
assert run(['runuser','-u','m12denied','--','rm',str(p)]).returncode!=0 and p.exists()
assert run(['runuser','-u','m12allowed','--','rm',str(p)]).returncode==0
for module in ['udf','sctp']:
 assert run(['modprobe',module]).returncode!=0 and not Path('/sys/module',module).exists()
sock=socket.socket();sock.settimeout(2)
assert sock.connect_ex(('127.0.0.1',18412))!=0
sock.close()
assert run(['systemctl','start','m12-obsolete.socket']).returncode!=0
assert run(['runuser','-u','m12allowed','--','crontab','-l']).returncode==0
assert run(['runuser','-u','m12denied','--','crontab','-l']).returncode!=0
assert run(['runuser','-u','m12allowed','--','atq']).returncode==0
assert run(['runuser','-u','m12denied','--','atq']).returncode!=0
queued=subprocess.run(['runuser','-u','m12allowed','--','at','now'],input='/usr/bin/touch /home/m12allowed/at-proof\\n',text=True,capture_output=True,cwd='/home/m12allowed')
assert queued.returncode==0
prior=Path('/home/m12allowed/cron-proof').stat().st_mtime
for _ in range(90):
 if Path('/home/m12allowed/at-proof').exists() and Path('/home/m12allowed/cron-proof').stat().st_mtime>prior:break
 time.sleep(1)
else:raise AssertionError('Required scheduler workload did not execute')
assert run(['systemctl','is-active','hardener-m10-service']).stdout.strip()=='active'
print(json.dumps({'noexec':True,'nosuid':True,'nodev':True,'sticky':True,'module_denial':True,'listener_denial':True,'scheduler_admission':True,'cron_and_at_jobs_executed':True,'service_continuity':True}))
""")
assert all(json.loads(native).values())
lab.marker_receipt("m12-crypto")
tls = lab.remote(
    "sudo openssl s_client -brief -connect 192.0.2.30:6514 -tls1_2 -CAfile /etc/pki/rsyslog/lab-ca.pem -verify_hostname logs.lab.test </dev/null 2>&1"
)
assert "TLSv1.2" in tls and "Verification: OK" in tls
command = lab.ssh + [
    "sudo openssl s_client -brief -connect 192.0.2.30:6514 -tls1_1 -CAfile /etc/pki/rsyslog/lab-ca.pem </dev/null"
]
result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=15)
assert result.returncode != 0
before = state()
report = lab.execute("verify", "verify-native", profile)
assert report["summary"]["pass"] == 15 and report["changed_tasks"] == 0 and state() == before
lab.finish(
    {
        "selected": 15,
        "initial_failures": 15,
        "zero_change_repeat": True,
        "reboot_verified": True,
        "crypto_pending_before_reboot": True,
        "exclusion_and_omission": True,
        "native_behavior": json.loads(native),
        "tls12_and_collector_receipt": True,
        "tls11_denied": True,
        "readonly_preserved": True,
    }
)
