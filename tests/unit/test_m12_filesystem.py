"""Filesystem review boundaries and findings."""

import importlib.util
import json
import stat
from types import SimpleNamespace

import pytest

from hardener.validation import DATA, load_catalog, validate

spec = importlib.util.spec_from_file_location(
    "filesystem_review", DATA / "ansible/helpers/filesystem_review.py"
)
review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(review)


@pytest.mark.parametrize(
    "mode,expected",
    [
        (stat.S_IFREG | 0o666, True),
        (stat.S_IFLNK | 0o777, False),
        (stat.S_IFREG | 0o644, False),
        (stat.S_IFDIR | 0o777, True),
        (stat.S_IFDIR | 0o1777, False),
        (stat.S_IFDIR | 0o755, False),
    ],
)
def test_shared_write_policy(mode, expected):
    info = SimpleNamespace(st_mode=mode, st_uid=0, st_gid=0)
    assert review.unsafe_metadata("world-writable-review", info, False, {0}, {0}) == expected


@pytest.mark.parametrize("uid,gid,expected", [(0, 0, False), (991, 0, True), (0, 992, True)])
def test_unresolved_ownership(uid, gid, expected):
    info = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=uid, st_gid=gid)
    assert review.unsafe_metadata("unowned-files-review", info, False, {0}, {0}) == expected


@pytest.mark.parametrize(
    "mode,cap,approved,expected",
    [
        (0o4755, False, False, True),
        (0o2755, False, False, True),
        (0o755, True, False, True),
        (0o4755, False, True, False),
        (0o755, False, False, False),
    ],
)
def test_privileged_file_disposition(mode, cap, approved, expected):
    info = SimpleNamespace(st_mode=stat.S_IFREG | mode, st_uid=0, st_gid=0)
    assert (
        review.unsafe_metadata("privileged-files-review", info, cap, {0}, {0}, approved) == expected
    )


def local_scan(monkeypatch):
    monkeypatch.setattr(
        review.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(stdout=json.dumps({"filesystems": [{"fstype": "xfs"}]})),
    )


def test_scan_counts_but_never_follows_symbolic_links(tmp_path, monkeypatch):
    local_scan(monkeypatch)
    inside = tmp_path / "inside"
    outside = tmp_path / "outside"
    inside.mkdir()
    outside.mkdir()
    bad = outside / "private"
    bad.write_text("not read")
    bad.chmod(0o666)
    (inside / "link").symlink_to(outside, target_is_directory=True)
    result = review.assess("privileged-files-review", {"paths": [str(inside)], "max_entries": 10})
    assert result["matches"] and result["entries_checked"] == 2


def test_incomplete_scan_raises_instead_of_passing(tmp_path, monkeypatch):
    local_scan(monkeypatch)
    (tmp_path / "file").touch()
    with pytest.raises(ValueError, match="limit"):
        review.assess("world-writable-review", {"paths": [str(tmp_path)], "max_entries": 1})


def test_overlapping_roots_rejected(tmp_path, monkeypatch):
    local_scan(monkeypatch)
    (tmp_path / "child").mkdir()
    with pytest.raises(ValueError, match="overlap"):
        review.assess(
            "world-writable-review",
            {"paths": [str(tmp_path), str(tmp_path / "child")], "max_entries": 10},
        )


def test_symlink_scope_rejected(tmp_path):
    (tmp_path / "link").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError, match="symbolic"):
        review.canonical_scope(str(tmp_path / "link"))


def test_nonlocal_scope_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(
        review.subprocess,
        "run",
        lambda *a, **k: SimpleNamespace(stdout=json.dumps({"filesystems": [{"fstype": "nfs4"}]})),
    )
    with pytest.raises(ValueError, match="local"):
        review.assess("world-writable-review", {"paths": [str(tmp_path)], "max_entries": 10})


def test_findings_are_bounded(tmp_path, monkeypatch):
    local_scan(monkeypatch)
    for i in range(45):
        p = tmp_path / str(i)
        p.touch()
        p.chmod(0o666)
    result = review.assess("world-writable-review", {"paths": [str(tmp_path)], "max_entries": 100})
    assert result["finding_count"] == 45 and len(result["finding_paths"]) == 40
    assert result["findings_truncated"] and not result["matches"]


def test_assessments_refuse_apply():
    catalog = load_catalog()
    profile = {
        "schema_version": 1,
        "id": "test",
        "revision": 1,
        "target": {"os": "rocky", "major_version": 10, "role": "server"},
        "controls": [
            {
                "id": "filesystem.world-writable-review",
                "enabled": True,
                "parameters": {"paths": ["/srv"]},
            }
        ],
    }
    validate(profile, catalog)
    assert catalog["filesystem.world-writable-review"]["supported_modes"] == ["audit", "verify"]


mount_spec = importlib.util.spec_from_file_location(
    "filesystem_policy", DATA / "ansible/helpers/filesystem_policy.py"
)
mounts = importlib.util.module_from_spec(mount_spec)
mount_spec.loader.exec_module(mounts)


@pytest.mark.parametrize(
    "flags,expected",
    [
        (["nodev"], "defaults,nosuid,noexec,nodev"),
        (["noexec"], "defaults,dev,nosuid,noexec"),
        (["nodev", "nosuid", "noexec"], "defaults,nosuid,noexec,nodev"),
    ],
)
def test_restrictions_preserve_unselected_options(flags, expected):
    assert mounts.restrict_options("defaults,dev,nosuid,noexec", flags) == expected


@pytest.mark.parametrize("flags", [[], ["exec"], ["nodev", "nodev"], ["remount"], ["rw,noexec"]])
def test_restrictions_reject_unknown_and_duplicate_flags(flags):
    with pytest.raises(ValueError):
        mounts.restrict_options("defaults", flags)


def test_fstab_parser_retains_original_location_and_fields():
    value = "# header\nUUID=fixture /tmp xfs defaults,size=256m 0 2 # retained\n"
    index, row = mounts.fstab_entry(value, "/tmp")
    assert index == 1 and row == ["UUID=fixture", "/tmp", "xfs", "defaults,size=256m", "0", "2"]


@pytest.mark.parametrize(
    "value",
    [
        "",
        "tmpfs /tmp tmpfs defaults 0 0\ntmpfs /tmp tmpfs defaults 0 0\n",
        "bad row\n",
        "server:/tmp /tmp nfs defaults 0 0\n",
        "tmpfs /tmp tmpfs bind 0 0\n",
        "tmpfs /tmp tmpfs noauto 0 0\n",
        "tmpfs /tmp tmpfs x-systemd.automount 0 0\n",
        "tmpfs /tmp tmpfs user 0 0\n",
        "tmpfs /tmp tmpfs defaults,defaults 0 0\n",
    ],
)
def test_ambiguous_mount_ownership_refused(value):
    with pytest.raises(ValueError):
        mounts.fstab_entry(value, "/tmp")


def test_mount_controls_require_explicit_operator_parameters():
    catalog = load_catalog()
    for cid in [
        *("filesystem." + name for name in mounts.MOUNTS),
        "filesystem.shared-directory-sticky",
    ]:
        assert catalog[cid]["parameters"]["required"]
