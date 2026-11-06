"""Provision disposable M12 fixtures. This is outside the hardening engine."""

import json
import os
import secrets
import shlex
import subprocess
import time
from pathlib import Path

from lab import GuestLab

lab = GuestLab(__doc__)
for attempt in range(60):
    ready = subprocess.run(lab.ssh + ["sudo -n id -u"], capture_output=True, text=True, check=False)
    if ready.returncode == 0 and ready.stdout.strip() == "0":
        break
    time.sleep(2)
else:
    raise RuntimeError("Target did not become ready")
credentials = Path.home() / ".local/state/rocky10-hardener/m12-credentials.json"
credentials.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
if not credentials.exists():
    fd = os.open(credentials, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump({"grub": secrets.token_hex(16), "root": secrets.token_hex(16)}, handle)
passwords = json.loads(credentials.read_text())
grub = subprocess.run(
    lab.ssh + ["sudo grub2-mkpasswd-pbkdf2"],
    input=passwords["grub"] + "\n" + passwords["grub"] + "\n",
    capture_output=True,
    text=True,
    check=True,
    timeout=60,
)
grub_hash = next(word for word in grub.stdout.split() if word.startswith("grub.pbkdf2.sha512."))
root_hash = subprocess.run(
    ["openssl", "passwd", "-6", "-stdin"],
    input=passwords["root"] + "\n",
    capture_output=True,
    text=True,
    check=True,
    timeout=30,
).stdout.strip()
payload = json.dumps({"grub": grub_hash, "root": root_hash})
secret_writer = """import sys,json,os
from pathlib import Path
values=json.load(sys.stdin)
base=Path('/root/.hardener-m12')
base.mkdir(mode=0o700,exist_ok=True)
for key,value in values.items():
 p=base/(key+'.hash')
 fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
 with os.fdopen(fd,'w') as f:f.write(value+'\\n')
"""
subprocess.run(
    lab.ssh + ["sudo python3 -c " + shlex.quote(secret_writer)],
    input=payload,
    text=True,
    capture_output=True,
    check=True,
    timeout=30,
)
lab.remote("sudo dnf -y install at e2fsprogs > /var/tmp/hardener-m12-packages.log 2>&1")
lab.python("""from pathlib import Path
import subprocess,os
def run(args): subprocess.run(args,check=True,capture_output=True)
base=Path('/var/lib/hardener-m12')
base.mkdir(mode=0o700)
for target in ['/tmp','/var/tmp','/home']:
 image=base/(target.strip('/').replace('/','-')+'.img')
 with image.open('xb') as f:f.truncate(256*1024*1024)
 image.chmod(0o600)
 run(['mkfs.ext4','-F',str(image)])
 staging=base/'staging'
 staging.mkdir()
 run(['mount','-o','loop',str(image),str(staging)])
 run(['cp','-a',target+'/.',str(staging)])
 run(['umount',str(staging)])
 staging.rmdir()
 with Path('/etc/fstab').open('a') as f:
  f.write(str(image)+' '+target+' ext4 defaults,loop 0 0 # m12 fixture\\n')
 run(['mount',target])
 run(['restorecon','-RF',target])
with Path('/etc/fstab').open('a') as f:f.write('tmpfs /dev/shm tmpfs defaults 0 0 # m12 fixture\\n')
run(['systemctl','daemon-reload'])
Path('/srv/hardener-m12-shared').mkdir(mode=0o755)
Path('/srv/hardener-m12-shared').chmod(0o777)
for user in ['m12allowed','m12denied']:
 run(['useradd','-m','-s','/bin/bash',user])
# Prepare the supported unused-module scope outside the runtime engine.
for image in Path('/boot').glob('initramfs-*.img'):
 listing=subprocess.check_output(['lsinitrd',str(image)],text=True)
 if 'rescue' in image.name or '/udf.ko' not in listing:
  continue
 version=image.name[len('initramfs-'):-len('.img')].removesuffix('kdump')
 run(['dracut','--force','--omit-drivers','udf',str(image),version])
# Rescue initramfs may share an older kernel. Remove udf through the same native rebuild.
kernel=subprocess.check_output(['uname','-r'],text=True).strip()
for image in Path('/boot').glob('initramfs-*rescue*.img'):
 run(['dracut','--force','--omit-drivers','udf',str(image),kernel])
Path('/usr/local/lib/systemd/system').mkdir(parents=True,exist_ok=True)
Path('/usr/local/lib/systemd/system/m12-obsolete.socket').write_text('[Unit]\\nDescription=Disposable obsolete listener\\n[Socket]\\nListenStream=127.0.0.1:18412\\n[Install]\\nWantedBy=sockets.target\\n')
Path('/usr/local/lib/systemd/system/m12-obsolete.service').write_text('[Unit]\\nDescription=Disposable obsolete listener consumer\\nRequires=m12-obsolete.socket\\n[Service]\\nExecStart=/usr/bin/sleep infinity\\n')
run(['systemctl','daemon-reload'])
run(['systemctl','enable','--now','m12-obsolete.socket','atd'])
# Preserve a scheduler workload for the allowed account.
run(['su','-s','/bin/sh','m12allowed','-c',"printf '* * * * * /usr/bin/touch /home/m12allowed/cron-proof\\n' | crontab -"])
# Serial GRUB is test infrastructure, not a framework policy change.
p=Path('/etc/default/grub')
text=p.read_text()
for key in ['GRUB_TERMINAL_INPUT','GRUB_TERMINAL_OUTPUT','GRUB_TIMEOUT']:
 text='\\n'.join(row for row in text.split('\\n') if not row.startswith(key+'='))
text+='GRUB_TERMINAL_INPUT="serial console"\\nGRUB_TERMINAL_OUTPUT="serial console"\\nGRUB_SERIAL_COMMAND="serial --speed=115200 --unit=0 --word=8 --parity=no --stop=1"\\nGRUB_TIMEOUT=5\\n'
p.write_text(text)
run(['grub2-mkconfig','-o','/boot/grub2/grub.cfg'])
run(['chmod','0644','/boot/grub2/grub.cfg'])
run(['update-crypto-policies','--set','LEGACY'])
""")
lab.reboot()
lab.finish(
    {
        "dedicated_existing_mounts": True,
        "bios_serial_console_prepared": True,
        "credentials_external": True,
        "unused_module": "udf",
        "unused_protocol": "sctp",
        "allowed_scheduler_user": "m12allowed",
        "denied_scheduler_user": "m12denied",
    }
)
