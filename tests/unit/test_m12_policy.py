"""M12 policy refusal, parameter and secret-handling contracts."""

import importlib.util
from pathlib import Path

import pytest

from hardener.validation import DATA, ValidationError, load_catalog, validate


def helper(name):
    spec = importlib.util.spec_from_file_location(name, DATA / ("ansible/helpers/" + name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


optional = helper("optional_policy")
boot = helper("boot_policy")


@pytest.mark.parametrize(
    "modules", [[], ["udf", "udf"], ["../udf"], ["udf;id"], ["SCTP"], ["sctp-mod"], [""]]
)
def test_module_names_cannot_escape_configuration(modules):
    with pytest.raises(ValueError):
        optional.module_text(modules)


def test_module_denial_has_canonical_order_and_no_unload():
    assert (
        optional.module_text(["udf", "sctp"])
        == "install sctp /bin/false\nblacklist sctp\ninstall udf /bin/false\nblacklist udf\n"
    )


@pytest.mark.parametrize(
    "users", [[], ["test"], ["root", "root"], ["root", "bad user"], ["root", "-option"]]
)
def test_scheduler_requires_explicit_root_and_valid_local_names(users):
    with pytest.raises(ValueError):
        optional.scheduler_text(users)


def test_scheduler_list_is_deterministic():
    assert optional.scheduler_text(["root", "test"]) == "root\ntest\n"


@pytest.mark.parametrize("text", ["", " ", "hello\x1b[2J", r"Release \r", "x" * 2049, "Unicode é"])
def test_banner_refuses_terminal_and_information_escapes(text):
    with pytest.raises(ValueError):
        optional.banner_text(text)


def test_banner_preserves_operator_content():
    assert (
        optional.banner_text("Authorized laboratory access only.\n")
        == "Authorized laboratory access only.\n"
    )


@pytest.mark.parametrize(
    "pattern,value",
    [
        (r"grub\.pbkdf2\.sha512\.[0-9]+\.[A-Fa-f0-9]+\.[A-Fa-f0-9]+", "not-a-hash"),
        (r"\$6\$[A-Za-z]+\$[A-Za-z]+", "root:password"),
    ],
)
def test_external_secret_format_rejected_without_echo(tmp_path, monkeypatch, pattern, value):
    path = tmp_path / "credential"
    path.write_text(value)
    monkeypatch.setattr(boot, "safe", lambda *a, **k: None)
    with pytest.raises(ValueError) as exc:
        boot.private_value(str(path), pattern)
    assert value not in str(exc.value)


def test_grub_requires_exact_single_vendor_hook(monkeypatch):
    hook = 'if [ -f \u0024{prefix}/user.cfg ]; then\nset superusers="root"\npassword_pbkdf2 root HASH\nfi'
    monkeypatch.setattr(boot, "run", lambda *a, **k: hook)
    text = "### BEGIN /etc/grub.d/01_users ###\n" + hook + "\n### END /etc/grub.d/01_users ###"
    assert boot.grub_block(text)
    for bad in [
        text + text,
        text + '\nset superusers=""',
        text.replace("password_pbkdf2", "password"),
    ]:
        with pytest.raises(ValueError):
            boot.grub_block(bad)


def test_uefi_boot_mutation_is_refused(monkeypatch):
    original = Path.exists
    monkeypatch.setattr(
        Path, "exists", lambda p: True if str(p) == "/sys/firmware/efi" else original(p)
    )
    with pytest.raises(ValueError, match="BIOS"):
        boot.bios()


@pytest.mark.parametrize(
    "cid,params",
    [
        ("crypto.system-policy", {"policy": "FIPS"}),
        ("crypto.system-policy", {"policy": "LEGACY"}),
        ("boot.loader-authentication", {"password": "unsafe"}),
        ("boot.rescue-authentication", {"hash": "unsafe"}),
        ("kernel.unused-network-protocols", {"modules": ["-x"]}),
        ("services.legacy-listeners-disabled", {"units": ["sshd@*.service"]}),
    ],
)
def test_unsupported_or_inline_secret_parameters_fail_offline(cid, params):
    profile = {
        "schema_version": 1,
        "id": "test",
        "revision": 1,
        "target": {"os": "rocky", "major_version": 10, "role": "server"},
        "controls": [{"id": cid, "enabled": True, "parameters": params}],
    }
    with pytest.raises(ValidationError):
        validate(profile, load_catalog())


@pytest.mark.parametrize(
    "output,expected",
    [
        ("install /bin/false \n", True),
        ("insmod /lib/modules/kernel/lib/crc.ko.xz \ninstall /bin/false \n", True),
        ("install /bin/true\n", False),
        ("insmod /lib/modules/kernel/fs/udf.ko.xz\ninstall /bin/false\n", False),
        ("install /bin/false\ninsmod /lib/modules/kernel/fs/udf.ko.xz\n", False),
        ("install /bin/false; /bin/true\n", False),
        ("", False),
    ],
)
def test_module_effective_denial_handles_native_dependency_output(output, expected):
    assert optional.loading_denied(output, "udf") == expected


def test_initramfs_inspection_reused_only_with_identical_complete_bytes(tmp_path, monkeypatch):
    image = tmp_path / "initramfs.img"
    image.write_bytes(b"image-one")
    calls = []
    monkeypatch.setattr(optional, "run", lambda argv: calls.append(argv) or "safe module list")
    proof = optional.initramfs_proof(["udf", "sctp"], {}, [image])
    assert len(calls) == 1
    assert optional.initramfs_proof(["sctp", "udf"], proof, [image]) == proof
    assert len(calls) == 1
    image.write_bytes(b"image-two")
    new = optional.initramfs_proof(["udf", "sctp"], proof, [image])
    assert len(calls) == 2 and new != proof
    optional.initramfs_proof(["udf"], new, [image])
    assert len(calls) == 3


def test_initramfs_presence_is_never_cached_as_absence(tmp_path, monkeypatch):
    image = tmp_path / "initramfs.img"
    image.write_bytes(b"image")
    monkeypatch.setattr(optional, "run", lambda argv: "usr/lib/modules/kernel/fs/udf/udf.ko.xz")
    with pytest.raises(ValueError, match="initramfs"):
        optional.initramfs_proof(["udf"], {}, [image])


def test_initramfs_race_refuses_evidence(tmp_path, monkeypatch):
    image = tmp_path / "initramfs.img"
    image.write_bytes(b"original")

    def listing(argv):
        image.write_bytes(b"replaced")
        return "safe list"

    monkeypatch.setattr(optional, "run", listing)
    with pytest.raises(ValueError, match="changed"):
        optional.initramfs_proof(["udf"], {}, [image])


@pytest.mark.parametrize(
    "unit",
    [
        "sshd.service",
        "NetworkManager.service",
        "firewalld.service",
        "auditd.service",
        "dbus.socket",
        "systemd-journald.service",
        "crond.service",
    ],
)
def test_essential_services_refused_before_native_commands(unit, monkeypatch):
    monkeypatch.setattr(
        optional, "unit_values", lambda unit: pytest.fail("Must refuse before inspection")
    )
    with pytest.raises(ValueError, match="protected"):
        optional.inspect_listeners({"units": [unit]})


@pytest.mark.parametrize("module", [optional, boot])
def test_failed_relabel_reports_partial_file_replacement(module, tmp_path, monkeypatch, capsys):
    path = tmp_path / "owned"
    path.write_text("old")
    monkeypatch.setattr(module, "WRITE_OCCURRED", False)
    monkeypatch.setattr(module, "safe", lambda *args, **kwargs: None)

    def fail(*args, **kwargs):
        raise ValueError("native failure")

    monkeypatch.setattr(module, "run", fail)
    if module is optional:
        kind = "cron-access"
        plan = [(path, "new")]
    else:
        kind = "loader-authentication"
        plan = (path, "new")
    monkeypatch.setattr(module, "inspect", lambda *args: ({"matches": False}, plan))
    monkeypatch.setattr(module.sys, "argv", ["helper", kind, "apply", "{}"])
    module.main()
    import json

    report = json.loads(capsys.readouterr().out)
    assert path.read_text() == "new"
    assert report["supported"] is False and report["changed"] is True


def test_matching_banner_still_requires_native_supplement_removal(tmp_path, monkeypatch):
    from types import SimpleNamespace

    issue = tmp_path / "etc/issue"
    notices = tmp_path / "etc/issue.d"
    notices.mkdir(parents=True)
    issue.write_text("Authorized laboratory access only.\n")
    cockpit = notices / "cockpit.issue"
    cockpit.symlink_to("../../run/cockpit/issue")
    monkeypatch.setattr(optional, "safe", lambda *args, **kwargs: None)
    monkeypatch.setattr(optional, "file_matches", lambda *args, **kwargs: True)
    monkeypatch.setattr(
        optional,
        "Path",
        lambda value: (
            tmp_path / value.lstrip("/") if str(value).startswith("/etc/") else Path(value)
        ),
    )
    original = Path.lstat
    monkeypatch.setattr(
        Path,
        "lstat",
        lambda path: (
            SimpleNamespace(st_uid=0, st_mode=original(path).st_mode)
            if path == cockpit
            else original(path)
        ),
    )
    state, _ = optional.inspect(
        "authorized-use-banner", {"text": "Authorized laboratory access only."}
    )
    assert state["matches"] is False
    cockpit.unlink()
    state, _ = optional.inspect(
        "authorized-use-banner", {"text": "Authorized laboratory access only."}
    )
    assert state["matches"] is True


def test_initramfs_canonical_name_detects_hyphenated_module_filename(tmp_path, monkeypatch):
    image = tmp_path / "initramfs.img"
    image.write_bytes(b"image")
    monkeypatch.setattr(
        optional, "run", lambda argv: "usr/lib/modules/kernel/net/test-module.ko.xz"
    )
    with pytest.raises(ValueError, match="initramfs"):
        optional.initramfs_proof(["test_module"], {}, [image])


def test_supplemental_grub_configuration_refused(monkeypatch):
    monkeypatch.setattr(boot, "bios", lambda: None)
    original = Path.exists
    monkeypatch.setattr(
        Path,
        "exists",
        lambda path: True if str(path) == "/boot/grub2/custom.cfg" else original(path),
    )
    with pytest.raises(ValueError, match="supplemental GRUB"):
        boot.inspect("loader-authentication", {"hash_file": "/external/hash"})
