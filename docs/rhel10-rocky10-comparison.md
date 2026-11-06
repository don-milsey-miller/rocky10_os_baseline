# RHEL 10 and Rocky Linux 10 server hardening comparison

Date: 2026-11-06. Scope: the two supplied benchmark editions, operating-system differences relevant to server hardening, and implications for this project.

## Findings

**F1 - The two benchmark editions prescribe effectively the same server hardening baseline.** Both contain the same 328 recommendation IDs and titles, with identical server-level and Automated/Manual assignments. No different intended hardening setting was identified in the compared recommendation fields. This is a document comparison, not proof that both operating systems behave identically.

**F2 - Most detected text differences are presentation issues.** After removing page footers and normalizing whitespace, 320 of 328 recommendations match across the seven core fields defined below. Eight have small audit or remediation text differences. The most meaningful is an incorrect setting name in explanatory audit text. Both documents' actual script checks the same correct setting.

**F3 - Vendor-specific examples need review even where the text matches.** The Rocky guide includes Red Hat signing-key and repository examples. Matching example output does not make those keys or repository IDs appropriate for Rocky.

**F4 - The current framework remains Rocky-only.** The project has 102 independently defined controls and explicitly rejects RHEL targets. The benchmark similarity supports reusing hardening concepts, but it does not establish RHEL support or complete benchmark coverage.

## Source editions and counts

Source codes used below: **S1** is the supplied CIS Red Hat Enterprise Linux 10 Benchmark v1.0.1. **S2** is the supplied CIS Rocky Linux 10 Benchmark v1.0.0. Both cover pages are dated **2025-09-30**. A higher benchmark revision does not establish a later operating-system release or a stronger policy.

| Measure | RHEL document S1 | Rocky document S2 |
| --- | --- | --- |
| PDF pages | 1,146 | 1,077 |
| Server-applicable recommendations | 328 | 328 |
| Recommendations tagged Level 1 Server | 248 | 248 |
| Recommendations tagged Level 2 Server | 80 | 80 |
| Automated assessment labels | 307 | 307 |
| Manual assessment labels | 21 | 21 |
| Recommendation IDs unique to this document | 0 | 0 |

The level counts describe recommendation labels. They do not mean a complete Level 2 assessment consists of only 80 checks. All 328 parsed recommendations have a server applicability label. Applicability still depends on installed components and the server's role. Workstation profile assignments were not compared.

The matching recommendation counts by chapter are: initial setup 79, services 39, network 35, host firewall 7, access and authentication 68, logging and auditing 78, and system maintenance 22. These are benchmark counts, not counts of this project's custom controls.

**Page convention:** all page references below use the number printed in the PDF footer. The PDF viewer's one-based page number is one higher. For example, printed page 442 is viewer page 443.

## Recommendation text differences

The table lists all eight recommendations with differences in the compared core fields. Identifiers here locate the supplied source documents. They do not replace the project's independent control IDs. The page column gives the start of each recommendation, in RHEL / Rocky order.

| Source reference | Start pages S1 / S2 | Difference and significance |
| --- | --- | --- |
| 1.5.10 | 208 / 198 | Core-dump storage audit prose has a bullet/page-flow difference. The intended storage setting is unchanged. |
| 2.1.21 | 327 / 317 | The mail-agent audit's diagnostic string wraps the word `non-loopback` differently. No different listener policy was identified. |
| 3.3.1.8 | 442 / 434 | The audit introduction names `net.ipv4.conf.all.send_redirects` in S1 and `net.ipv4.ip_forward` in S2. Both are wrong for this recommendation. Both scripts correctly inspect `net.ipv4.conf.all.accept_redirects`, with expected value `0`. |
| 5.3.2.4.2 | 702 / 693 | PAM remediation prose differs around `system-auth` and spacing before `/etc/pam.d`. The instruction to remove the `remember` argument from `pam_unix` is unchanged. |
| 6.2.4.1 | 828 / 817 | Logfile audit/remediation code wraps `systemd-journal` and the `find` option `-group` differently. This creates a copy/paste hazard, not a different ownership policy. |
| 6.3.4.3 | 1002 / 979 | Audit-log ownership script formatting splits `stat -Lc` and `find -print0` in the Rocky PDF. The required owner remains root. |
| 6.3.4.4 | 1005 / 981 | Audit-log group script formatting splits `-group` or `-print0` differently. The permitted group policy is unchanged. |
| 7.1.11 | 1041 / 1017 | The world-writable-file audit wraps a `-path` option differently. No different file-permission or sticky-bit requirement was identified. |

For the incorrect network-setting introduction, inspect S1 printed pages 442-443 and S2 printed page 435. The script's parameter assignment, live-state command, and expected value agree. Treat the conflicting prose as a documentation defect, not an instruction to substitute a different sysctl.

PDF layout is not executable source. Joining wrapped command lines incorrectly can turn `-group` into separate tokens or alter quoted strings. The comparison did not execute benchmark scripts or certify them as safe to paste into a shell.

Across all 328 recommendations, the extracted **Description, Rationale, Impact, Default Value, and Additional Information** fields match after whitespace normalization. Audit fields differ in seven recommendations and remediation fields in two, with one recommendation in both groups.

## Additional document differences and shared problems

**F5 - Page count and supporting material differ without adding server recommendations.** S1 has additional mapped and unmapped implementation-group appendices at printed pages 1096-1143. S2 proceeds from its summary table to its change history and has unresolved appendix bookmarks in its table of contents. S1's change history records v1.0.1 updates at printed pages 1144-1145. S2 records its first publication at printed page 1076. These edition histories should not be treated as a direct list of differences between the two operating systems.

One reference-field difference remains after separating recommendation content from following chapter introductions: recommendation 4.1.2 includes an unresolved `GRID #` entry in S2, while S1 omits it. The hardening requirement itself matches. See S1 starting at printed page 546 and S2 at 535.

The guides also share vendor-specific examples that need interpretation:

| Source location | Shared example | Correct interpretation for Rocky |
| --- | --- | --- |
| 1.2.1.1, S1 pp. 125-126 / S2 pp. 118-119 | Example imported keys identify Red Hat. | Validate the actual repository's approved signing keys against Rocky's or the relevant third-party vendor's current published fingerprints. Do not require an example Red Hat key merely because it appears in S2. |
| 1.2.1.4, S1 p. 132 / S2 p. 125 | Example repository output uses RHEL repository IDs and subscription-management text. | Evaluate Rocky repository IDs and approved endpoints. The shared recommendation requires site-approved repositories, not literal reproduction of the sample output. |

## Operating-system differences that matter

These are operational platform differences, separate from the near-matching benchmark text. Official web sources were checked on 2026-11-06. The supplied benchmark editions date from 2025 and cannot establish the current package or cryptographic behavior of every 10.x minor release.

| Area | RHEL 10 | Rocky Linux 10 |
| --- | --- | --- |
| Repository access and management | Red Hat content is managed through its registration/subscription infrastructure and approved delivery routes such as CDN or Satellite. | Rocky uses its own distribution repositories and mirrors. A RHEL subscription check is not a Rocky baseline prerequisite. |
| Repository identifiers | Examples include `rhel-10-for-x86_64-baseos-rpms` and `rhel-10-for-x86_64-appstream-rpms`. | Standard identifiers include `baseos`, `appstream`, and optional `crb`. |
| Package trust | Uses Red Hat product signing keys, including keys supplied through `RPM-GPG-KEY-redhat-release`. | Uses Rocky signing keys supplied by `rocky-gpg-keys`, including `RPM-GPG-KEY-Rocky-10`. Vendor key sets and rotation policies are distinct. |
| Distribution identity | RHEL identification and vendor metadata must be recognized explicitly by an implementation that supports it. | The inspected development guest identifies as `ID=rocky`, version 10.2, with `PLATFORM_ID=platform:el10`. Family compatibility does not change its vendor identity. |
| Published hardware scope | RHEL 10 lists x86-64-v3, ARMv8.0-A, POWER10 or later, and IBM z15. | Rocky's 10.0 release notes list x86-64-v3, ARMv8.0-A, POWER9, IBM z14, and RISC-V. The x86 minimum is shared, while the published non-x86 scope differs. |
| Major-version upgrade path | Red Hat documents supported RHEL 9 to 10 in-place upgrade paths with version and environment restrictions. | Rocky's 10.0 release notes direct 8.x/9.x users to a fresh installation rather than a supported major-version upgrade. |
| Support relationship | Red Hat registration and subscription terms govern access to its support and services. | Rocky is hosted by RESF and is not affiliated with or endorsed by Red Hat. Support arrangements must be evaluated for Rocky separately. |

Repository and subscription sources: [Red Hat registration](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/automatically_installing_rhel/registering-your-rhel-system), [RHEL repository identifiers](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/upgrading_from_rhel_9_to_rhel_10/appendix-rhel-10-repositories), and [Rocky repositories](https://docs.rockylinux.org/teams/rel_eng/repo/).

Trust sources: [Red Hat product signing keys](https://access.redhat.com/security/team/key) and [Rocky GPG key information](https://rockylinux.org/resources/gpg-key-info). Verify current vendor fingerprints rather than hard-coding the benchmark's example key IDs.

Hardware and upgrade sources: [RHEL 10 architectures](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/considerations_in_adopting_rhel_10/architectures), [Rocky 10.0 release notes](https://docs.rockylinux.org/latest/releases/release_notes/10_0/), and [RHEL supported upgrade paths](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html/upgrading_from_rhel_9_to_rhel_10/supported-upgrade-paths). Support identity source: [Rocky project organization](https://rockylinux.org/about).

The common use of DNF/RPM, SELinux, systemd, OpenSSH, PAM/authselect, firewalld/nftables, auditd, and system-wide cryptographic policy explains why many hardening concepts transfer. It does not prove identical packages, defaults, security-update timing, or certification status. Do not carry a vendor certification claim from one distribution to the other based on benchmark similarity.

## Implications for the current project

**F6 - A policy comparison and a coverage assessment answer different questions.** The current catalog has 102 custom controls: 90 remediations and 12 assessments. A custom control can combine requirements, implement only a bounded subset, or cover project-specific concerns. Dividing 102 by 328 would not produce a valid compliance percentage. This report does not establish full coverage of either benchmark.

The engine's [preflight](../hardener/data/ansible/preflight.yml) explicitly requires Rocky major version 10, KVM guest identity, and server role. The [profile schema](../hardener/data/schemas/profile.schema.json) fixes the target OS to `rocky`. RHEL is therefore unsupported by the current product even where an underlying command would work on both systems.

Retain the existing Rocky policy and independent control IDs. Review repository/key assumptions and the documented sysctl inconsistency when interpreting external guidance. The document comparison alone supplies no reason to change the intended hardening values.

If RHEL support becomes a separate approved task, it needs explicit platform/schema changes, vendor-specific repository and trust configuration, and tests on a disposable RHEL 10 guest. Those tests must cover refusal behavior, audit, apply, independent verification, repeatability, reboot persistence, and recovery. Existing Rocky results cannot substitute for RHEL acceptance.

Project scope and accepted evidence: [control coverage](control-coverage.md), [release readiness](m13-release-readiness.md), and [recovery enforcement](recovery-enforcement.md). Runtime source reviewed from the current project lineage, with README integration at commit `1346d50`.

## Method and verification

The comparison extracted both complete PDFs with Poppler `pdftotext -layout`, identified recommendation starts by identifier, assessment label, and Profile Applicability marker, and matched records by source identifier. All 328 applicability markers in each document were accounted for. Duplicate identifiers, missing required fields, differing ID sets, or metadata mismatches cause the comparison to stop.

Core fields were Description, Rationale, Impact, Audit, Remediation, Default Value, and Additional Information. Page footers were removed and whitespace runs collapsed. Numbers, commands, paths, vendor names, and policy values were preserved. References were compared separately. Subsequent chapter introductions were excluded from recommendation fields. Supporting control-framework mapping tables and introductory prose were outside the core-field equality count.

Seven unit checks passed for the comparison parser: value changes remain detectable, layout changes normalize consistently, duplicate IDs fail, unparsed recommendations fail, following sections are excluded, missing controls fail, and changed server levels fail. Rendered source pages were inspected to distinguish wrapping from policy changes. Source PDFs and extraction files remain outside the published framework assets.

This work compared documents and reviewed project code. It did not apply hardening, execute benchmark remediation scripts, or conduct side-by-side RHEL/Rocky runtime tests. No server certification or complete compliance claim follows from the matching counts.

### Source fingerprints

S1 file: `CIS_Red_Hat_Enterprise_Linux_10_Benchmark_v1.0.1.pdf`

SHA-256: `5ac1adfbc26394c82227b334bfb8216d07875458fa75f558833e9af63d9b7a2a`

S2 file: `CIS_Rocky_Linux_10_Benchmark_v1.0.0.pdf`

SHA-256: `1c10115663879b15d0116a49503681a2b0b440e587908e5901f8106773f0ec6e`
