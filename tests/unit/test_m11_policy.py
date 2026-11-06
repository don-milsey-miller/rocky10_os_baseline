"""Audit, integrity and collector policy safety contracts."""

import importlib.util

import pytest

from hardener.validation import DATA, ValidationError, effective_parameters, load_catalog, validate


def helper(name):
    spec = importlib.util.spec_from_file_location(name, DATA / f"ansible/helpers/{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


audit = helper("audit_policy")
integrity = helper("integrity_policy")
logging = helper("remote_logging")

STORAGE = {
    "max_log_file_mib": 20,
    "num_logs": 5,
    "space_left_mib": 75,
    "admin_space_left_mib": 50,
    **{
        k: "syslog"
        for k in (
            "space_left_action",
            "admin_space_left_action",
            "disk_full_action",
            "disk_error_action",
        )
    },
}
TLS = {
    "host": "192.0.2.30",
    "peer_name": "logs.lab.test",
    "port": 6514,
    "ca_file": "/etc/pki/rsyslog/lab-ca.pem",
}


@pytest.mark.parametrize(
    "line",
    [
        "-a never,task",
        "-D",
        "-e 2",
        "-w /etc/passwd -p z -k tag",
        "-w relative -p wa -k tag",
        "-w /etc/passwd -p wa",
    ],
)
def test_unknown_or_suppressing_rules_cannot_be_misread_as_watches(line):
    with pytest.raises(ValueError):
        audit.canonical_rule(line)


def test_watch_normalization_and_original_keys():
    assert audit.canonical_rule("-w /etc/selinux/ -p aw -k r10_config") == (
        "/etc/selinux",
        "aw",
        "r10_config",
    )
    keys = set()
    for kind in audit.GROUPS:
        for rule in audit.desired_rules(kind):
            path, permissions, key = audit.canonical_rule(rule)
            assert path.startswith("/") and permissions
            keys.add(key)
    assert len(keys) == 4


@pytest.mark.parametrize(
    "text,good",
    [
        ("console=ttyS0 audit=1", True),
        ("audit=0 audit=1", False),
        ("audit=1 audit=1", False),
        ("audit=off", False),
        ("", False),
    ],
)
def test_early_boot_requires_one_unambiguous_enable(text, good):
    assert audit.audit_boot_enabled(text) == good


def test_boot_entry_parser_requires_real_entries():
    assert audit.boot_args('index=0\nargs="audit=1"\nindex=1\nargs="audit=0"') == [
        "audit=1",
        "audit=0",
    ]
    with pytest.raises(ValueError):
        audit.boot_args("unparseable")


def test_audit_config_duplicates_and_thresholds_fail_closed():
    with pytest.raises(ValueError):
        audit.settings("num_logs = 5\nnum_logs = 1")
    with pytest.raises(ValueError):
        audit.settings("num_logs = 5 extra")
    desired = audit.storage_values(STORAGE)
    assert desired["max_log_file_action"] == "ROTATE" and desired["disk_full_action"] == "SYSLOG"
    with pytest.raises(ValueError):
        audit.storage_values({**STORAGE, "admin_space_left_mib": 75})


def test_aide_scope_has_path_boundaries_and_fixed_database():
    rendered = integrity.render({"paths": ["/srv/m11-baseline"]})
    assert "/srv/m11" in rendered and "(/|$)" in rendered
    assert "database_in=file:/var/lib/aide/rocky10.db.gz" in rendered
    assert "database_out=file:/var/lib/aide/rocky10.db.new.gz" in rendered
    assert "--update" not in rendered
    assert integrity.render({"paths": ["/etc", "/srv"]}) == integrity.render(
        {"paths": ["/srv", "/etc"]}
    )


@pytest.mark.parametrize(
    "paths", [[], ["/"], ["/proc"], ["/srv/../etc"], ["/srv/a.*"], ["/etc", "/etc"]]
)
def test_aide_rejects_unbounded_or_ambiguous_paths(paths):
    with pytest.raises(ValueError):
        integrity.render({"paths": paths})


def test_timer_runs_check_and_never_refreshes_baseline():
    service, timer = integrity.units("daily")
    assert "--check" in service and "--init" not in service and "--update" not in service
    assert "OnCalendar=daily" in timer and "Persistent=true" in timer
    with pytest.raises(ValueError):
        integrity.units("daily\nExecStart=/bin/sh")


def test_tls_render_authenticates_names_and_has_bounded_queue():
    result = logging.render(TLS)
    assert 'StreamDriverAuthMode="x509/name"' in result and 'StreamDriverMode="1"' in result
    assert 'queue.maxDiskSpace="100m"' in result and "lab-ca.pem" in result
    assert "PRIVATE KEY" not in result and 'AuthMode="anon"' not in result


@pytest.mark.parametrize(
    "change",
    [
        {"host": 'host" stop'},
        {"peer_name": "*"},
        {"port": 0},
        {"ca_file": "/tmp/ca.pem"},
        {"ca_file": "/etc/pki/../ca.pem"},
    ],
)
def test_tls_rejects_config_injection_and_untrusted_paths(change):
    with pytest.raises(ValueError):
        logging.render({**TLS, **change})


def test_storage_and_collector_parameters_require_explicit_owner_values():
    catalog = load_catalog()
    for cid in ("audit.storage-policy", "integrity.aide-scheduled", "logging.remote-tls"):
        with pytest.raises(ValidationError):
            effective_parameters(catalog[cid], {})
    assert effective_parameters(catalog["audit.storage-policy"], STORAGE) == STORAGE
    assert effective_parameters(catalog["logging.remote-tls"], TLS) == TLS


def test_immutable_requires_every_audit_group_and_orders_last():
    catalog = load_catalog()
    ids = [
        "audit.service-enabled",
        "audit.early-boot",
        "audit.storage-policy",
        *["audit." + kind for kind in audit.GROUPS],
        "audit.immutable-rules",
    ]
    for cid in ids:
        catalog[cid]["implemented"] = True
    profile = {
        "schema_version": 1,
        "id": "audit-test",
        "revision": 1,
        "target": {"os": "rocky", "major_version": 10, "role": "server"},
        "controls": [
            {
                "id": cid,
                "enabled": True,
                **(
                    {"parameters": STORAGE}
                    if cid == "audit.storage-policy"
                    else (
                        {"parameters": {"backlog_limit": 8192}} if cid == "audit.early-boot" else {}
                    )
                ),
            }
            for cid in ids
        ],
    }
    assert validate(profile, catalog)[-1] == "audit.immutable-rules"
    profile["controls"] = [c for c in profile["controls"] if c["id"] != "audit.session-events"]
    with pytest.raises(ValidationError):
        validate(profile, catalog)


def test_native_audit_configuration_accepts_digit_in_kerberos_key():
    assert audit.settings("krb5_principal = auditd") == {"krb5_principal": "auditd"}


@pytest.mark.parametrize(
    "args",
    [
        "audit=1",
        "audit=1 audit_backlog_limit=64",
        "audit=1 audit_backlog_limit=8192 audit_backlog_limit=64",
    ],
)
def test_early_boot_cannot_pass_with_absent_or_ambiguous_buffer(args):
    assert not audit.audit_boot_enabled(args, 8192)


def test_early_boot_requires_explicit_sufficient_buffer():
    assert audit.audit_boot_enabled("audit=1 audit_backlog_limit=8192", 8192)


def test_early_boot_apply_sets_both_parameters_and_retains_pending_failure(monkeypatch):
    calls = []
    monkeypatch.setattr(
        audit, "inspect", lambda *args: ({"matches": False, "persistent": False}, None)
    )
    monkeypatch.setattr(audit, "run", lambda argv: calls.append(argv))
    assert audit.apply("early-boot", {"backlog_limit": 8192})
    assert calls[0][-1] == "--args=audit=1 audit_backlog_limit=8192"
    monkeypatch.setattr(
        audit, "inspect", lambda *args: ({"matches": False, "persistent": True}, None)
    )
    assert not audit.apply("early-boot", {"backlog_limit": 8192})
    assert len(calls) == 1


def test_logging_service_override_refused_before_tls_configuration(monkeypatch):
    monkeypatch.setattr(logging, "safe", lambda path: None)
    monkeypatch.setattr(logging.Path, "read_text", lambda path: 'SYSLOGD_OPTIONS=""\n')
    monkeypatch.setattr(
        logging, "run", lambda argv: "/etc/systemd/system/rsyslog.service.d/unsafe.conf"
    )
    with pytest.raises(ValueError, match="customized"):
        logging.service_policy()


def test_replaced_logging_unit_refused(monkeypatch):
    monkeypatch.setattr(logging, "safe", lambda path: None)
    monkeypatch.setattr(logging.Path, "read_text", lambda path: 'SYSLOGD_OPTIONS=""\n')
    monkeypatch.setattr(
        logging,
        "run",
        lambda argv: "" if "DropInPaths" in argv else "/etc/systemd/system/rsyslog.service",
    )
    with pytest.raises(ValueError, match="replaced"):
        logging.service_policy()


def test_deleted_trusted_database_is_never_silently_reinitialized(monkeypatch, tmp_path):
    from types import SimpleNamespace

    for name in ("CONFIG", "DATABASE", "CANDIDATE", "MANIFEST", "SERVICE", "TIMER"):
        monkeypatch.setattr(integrity, name, tmp_path / name)
    integrity.MANIFEST.write_text("prior-approved-baseline")
    monkeypatch.setattr(
        integrity, "run", lambda *args, **kwargs: SimpleNamespace(stdout="", returncode=0)
    )
    monkeypatch.setattr(integrity, "safe", lambda *args, **kwargs: None)
    monkeypatch.setattr(integrity, "render", lambda parameters: "definition")
    with pytest.raises(ValueError, match="Missing trusted baseline"):
        integrity.inspect({"paths": [], "schedule": "daily", "initialize_baseline": True})
    assert not integrity.DATABASE.exists()


@pytest.mark.parametrize(
    "options",
    [
        'SYSLOGD_OPTIONS="-f /tmp/other.conf"',
        'SYSLOGD_OPTIONS=""\nOTHER=1',
        'SYSLOGD_OPTIONS=""\nSYSLOGD_OPTIONS=""',
    ],
)
def test_alternate_logging_startup_cannot_bypass_owned_configuration(options):
    assert not logging.empty_options(options)


def test_empty_native_logging_options_are_supported():
    assert logging.empty_options('# packaged options\nSYSLOGD_OPTIONS=""\n')


def test_unconfined_service_assessment_cannot_be_applied():
    profile = {
        "schema_version": 1,
        "id": "assessment",
        "revision": 1,
        "target": {"os": "rocky", "major_version": 10, "role": "server"},
        "controls": [{"id": "selinux.no-unconfined-services", "enabled": True}],
    }
    with pytest.raises(ValidationError, match="assessment-only"):
        validate(profile, load_catalog(), mode="apply")
