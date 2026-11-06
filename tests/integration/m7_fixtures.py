"""Build disposable M7 packages, metadata, and TLS keys inside the development guest.

Output contains private disposable keys. Keep it outside Git and evidence archives.
"""

import argparse
import os
import shutil
import subprocess
from pathlib import Path


def run(argv, **kwargs):
    return subprocess.run(argv, check=True, capture_output=True, text=True, **kwargs).stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--disposable", action="store_true", required=True)
    root = Path(parser.parse_args().output).resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    build = root / "build"
    repo = root / "repo"
    repo.mkdir()
    for name in ("BUILD", "RPMS", "SOURCES", "SPECS", "SRPMS", "BUILDROOT"):
        (build / name).mkdir(parents=True)
    for version in ("1", "2"):
        spec = build / "SPECS/probe.spec"
        spec.write_text(f"""Name: hardener-m7-probe
Version: {version}
Release: 1
Summary: Disposable advisory fixture
License: MIT
BuildArch: noarch
%description
Disposable empty package for integration testing.
%files
""")
        run(["rpmbuild", "--define", "_topdir " + str(build), "-bb", str(spec)])
    shutil.copy2(build / "RPMS/noarch/hardener-m7-probe-2-1.noarch.rpm", repo)
    shutil.copy2(build / "RPMS/noarch/hardener-m7-probe-1-1.noarch.rpm", root)
    run(["createrepo_c", str(repo)])
    update = root / "updateinfo.xml"
    update.write_text("""<?xml version="1.0" encoding="UTF-8"?>
<updates><update from="disposable-lab" status="stable" type="security" version="1">
<id>LAB-M7-1</id><title>Disposable advisory fixture</title>
<issued date="2026-01-01 00:00:00"/><updated date="2026-01-01 00:00:00"/>
<severity>Low</severity><description>Disposable test package upgrade.</description>
<pkglist><collection short="lab"><name>Lab</name>
<package name="hardener-m7-probe" epoch="0" version="2" release="1" arch="noarch">
<filename>hardener-m7-probe-2-1.noarch.rpm</filename></package>
</collection></pkglist></update></updates>
""")
    run(["modifyrepo_c", str(update), str(repo / "repodata")])
    gpg = root / "gnupg"
    gpg.mkdir(mode=0o700)
    env = {**os.environ, "GNUPGHOME": str(gpg)}
    run(
        [
            "gpg",
            "--batch",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
            "--quick-generate-key",
            "Disposable M7 metadata",
            "rsa2048",
            "sign",
            "0",
        ],
        env=env,
    )
    (root / "repo-key.asc").write_text(run(["gpg", "--armor", "--export"], env=env))
    run(
        ["gpg", "--batch", "--yes", "--armor", "--detach-sign", str(repo / "repodata/repomd.xml")],
        env=env,
    )
    run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(root / "tls.key"),
            "-out",
            str(root / "tls.crt"),
            "-days",
            "30",
            "-subj",
            "/CN=Disposable M7",
            "-addext",
            "subjectAltName=IP:127.0.0.1",
            "-addext",
            "extendedKeyUsage=serverAuth",
        ]
    )
    empty = root / "no-advisory"
    empty.mkdir()
    run(["createrepo_c", str(empty)])
    run(
        ["gpg", "--batch", "--yes", "--armor", "--detach-sign", str(empty / "repodata/repomd.xml")],
        env=env,
    )
    (root / "tls.key").chmod(0o600)
    (root / "server.py").write_text("""import http.server,ssl
from pathlib import Path
import os
root=Path(__file__).resolve().parent
os.chdir(root)
server=http.server.ThreadingHTTPServer(('127.0.0.1',8443),http.server.SimpleHTTPRequestHandler)
context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(str(root/'tls.crt'),str(root/'tls.key'))
server.socket=context.wrap_socket(server.socket,server_side=True)
server.serve_forever()
""")
    print("Disposable fixtures built. Private keys must remain outside publication.")


if __name__ == "__main__":
    main()
