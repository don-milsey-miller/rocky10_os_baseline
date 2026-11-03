"""Native OpenSSH probes for the disposable M8 fixture. No passwords enter argv."""

import os
import selectors
import socket
import ssl
import subprocess
import tempfile
import time
from pathlib import Path

from lab import GuestLab


class AccessLab(GuestLab):
    def __init__(self, description):
        super().__init__(description)
        self.private = tempfile.TemporaryDirectory(prefix="hardener-m8-")
        self.private_path = Path(self.private.name)
        self.host = self.ssh[-1].split("@", 1)[1]
        self.port = self.ssh[-2]
        self.key = Path.home() / ".ssh/id_ed25519"
        self.public_key = self.key.with_suffix(".pub").read_text().strip()
        self.askpass = self.private_path / "askpass"
        self.askpass.write_text('#!/bin/sh\nprintf "%s\\n" "$HARDENER_TEST_PASSWORD"\n')
        self.askpass.chmod(0o700)
        self.bad_keys = []
        for number in range(2):
            path = self.private_path / f"bad-{number}"
            self.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(path)])
            self.bad_keys.append(path)

    def argv(self, user="zero", command=None, extra=(), password=False, keys=None, multiplex=False):
        args = [
            "ssh",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "ConnectTimeout=5",
            "-o",
            "IdentitiesOnly=yes",
            "-p",
            self.port,
        ]
        if not multiplex:
            args += ["-o", "ControlMaster=no", "-o", "ControlPath=none"]
        args += ["-o", "BatchMode=no" if password else "BatchMode=yes"]
        if password:
            args += [
                "-o",
                "PreferredAuthentications=password",
                "-o",
                "PubkeyAuthentication=no",
                "-o",
                "KbdInteractiveAuthentication=no",
                "-o",
                "NumberOfPasswordPrompts=1",
            ]
        for key in keys if keys is not None else [self.key]:
            args += ["-i", str(key)]
        args += list(extra) + [user + "@" + self.host]
        if command is not None:
            args.append(command)
        return args

    def connection(self, user="zero", command="/usr/bin/true", secret=None, input=None, **kwargs):
        env = {**os.environ, "LC_ALL": "C"}
        if secret is not None:
            env.update(
                DISPLAY=":0",
                SSH_ASKPASS=str(self.askpass),
                SSH_ASKPASS_REQUIRE="force",
                HARDENER_TEST_PASSWORD=secret,
            )
        return subprocess.run(
            self.argv(user, command, password=secret is not None, **kwargs),
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
            input=input,
            env=env,
            start_new_session=secret is not None,
        )

    def reload_ssh(self):
        self.remote("sudo sshd -t && sudo systemctl reload sshd")
        # SIGHUP returns before the listener necessarily reopens.
        for _ in range(30):
            result = self.connection(command="sudo -n id -u")
            if result.returncode == 0 and result.stdout.strip() == "0":
                return
            time.sleep(1)
        raise AssertionError("Fresh SSH/sudo did not recover after fixture reload")

    def forwarding(self, expected):
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        process = subprocess.Popen(
            self.argv(
                extra=[
                    "-N",
                    "-o",
                    "ExitOnForwardFailure=yes",
                    "-L",
                    f"127.0.0.1:{port}:127.0.0.1:8443",
                ]
            ),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, "LC_ALL": "C"},
        )
        successful = False
        try:
            for _ in range(50):
                assert process.poll() is None, "Forwarding SSH connection failed"
                try:
                    connection = socket.create_connection(("127.0.0.1", port), timeout=1)
                    connection.close()
                    break
                except OSError:
                    time.sleep(0.1)
            else:
                raise AssertionError("Forwarding listener did not start")
            context = ssl.create_default_context(cafile=str(Path.home() / "m7-fixtures/tls.crt"))
            try:
                with (
                    socket.create_connection(("127.0.0.1", port), timeout=3) as connection,
                    context.wrap_socket(connection, server_hostname="127.0.0.1") as secure,
                ):
                    secure.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                    successful = b"200" in secure.recv(512).splitlines()[0]
            except (OSError, IndexError):
                successful = False
        finally:
            process.terminate()
            _, error = process.communicate(timeout=5)
        assert successful is expected
        if not expected:
            assert "administratively prohibited" in error

    def startup_limit(self, count):
        held = []
        try:
            for _ in range(count):
                connection = socket.create_connection((self.host, int(self.port)), timeout=5)
                held.append(connection)
                assert connection.recv(128).startswith(b"SSH-")
            with socket.create_connection((self.host, int(self.port)), timeout=5) as extra:
                assert not extra.recv(128).startswith(b"SSH-")
        finally:
            for connection in held:
                connection.close()

    def session_limit(self, count):
        control = self.private_path / "multiplex"
        master = subprocess.Popen(
            self.argv(
                extra=[
                    "-M",
                    "-N",
                    "-S",
                    str(control),
                    "-o",
                    "ControlMaster=yes",
                    "-o",
                    "ControlPersist=no",
                ],
                multiplex=True,
            ),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        sessions = []
        try:
            for _ in range(50):
                assert master.poll() is None
                if control.exists():
                    break
                time.sleep(0.1)
            assert control.exists()
            for _ in range(count):
                session = subprocess.Popen(
                    self.argv(
                        command="printf 'ready\\n'; sleep 60",
                        extra=["-S", str(control), "-o", "ProxyCommand=false"],
                        multiplex=True,
                    ),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                sessions.append(session)
                with selectors.DefaultSelector() as selector:
                    selector.register(session.stdout, selectors.EVENT_READ)
                    assert selector.select(10), "Session did not start"
                    assert session.stdout.readline().strip() == "ready"
            refused = subprocess.run(
                self.argv(
                    command="true",
                    extra=["-S", str(control), "-o", "ProxyCommand=false"],
                    multiplex=True,
                ),
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            assert refused.returncode != 0
            assert "Session open refused" in refused.stderr
        finally:
            # The master owns the remote channel descriptors. Close it first.
            master.terminate()
            try:
                master.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                master.kill()
                master.communicate(timeout=5)
            for session in sessions:
                if session.poll() is None:
                    session.kill()
                session.communicate(timeout=5)

    def idle_limit(self, seconds):
        started = time.monotonic()
        result = subprocess.run(
            self.argv(command="sleep 90"),
            check=False,
            capture_output=True,
            text=True,
            timeout=seconds + 20,
        )
        elapsed = time.monotonic() - started
        assert result.returncode != 0 and seconds - 5 <= elapsed <= seconds + 15
        return round(elapsed, 1)

    def close(self):
        self.private.cleanup()
