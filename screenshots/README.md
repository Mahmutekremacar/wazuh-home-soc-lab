# Screenshots

Evidence for each lab. Every screenshot pairs the **action** with the **result** in one frame where possible — the command on one side, the resulting Wazuh alert on the other — so that nothing has to be taken on trust.

## Index

### `architecture/`

| File | Shows |
|---|---|
| `agents-enrolled-overview.png` | Both agents enrolled and active, Wazuh 4.14.7 |
| `infra-dashboard-over-tailscale.png` | The dashboard reached over the overlay network from a mobile device |

### `lab-000/` — Telemetry validation

| File | Shows |
|---|---|
| `lab-000-service-creation-rule-61138.png` | `sc.exe create` / `delete` alongside the resulting `61138` alerts |
| `lab-000-rule-61138-event-details.png` | The expanded alert: `eventID 7045`, `serviceName`, level 5, ATT&CK `T1543.003` |
| `lab-000-win10-01-rule-61138.png` | The same test on the second endpoint — not a single-host special case |

### `lab-001/` — PowerShell detection engineering

| File | Shows |
|---|---|
| `lab-001-powershell-severity-progression.png` | All four tests and the resulting `100100` → `100101` → `100102` → `100103` progression, levels 3 → 10 |
| `lab-001-download-execute-rule-100103-expanded.png` | The `100103` alert expanded: full `commandLine`, `parentImage`, process SHA-256, integrity level |

### `lab-002/` — Failed authentication & correlation

| File | Shows |
|---|---|
| `lab-002-multiple-logon-failures-rule-60204.png` | Failed RDP logons, the `60122` stream, and `60204` firing once the threshold was crossed |
| `lab-002-rule-60204-details.png` | `rule.frequency: 8`, level 10, ATT&CK `T1110` and the compliance mappings |
| `lab-002-logon-failure-rule-60122.png` | The loopback `net use` method — single detections, below the correlation threshold |

### `lab-003/` — File integrity monitoring

| File | Shows |
|---|---|
| `lab-003-file-created-rule-554.png` | `554`, `syscheck.event: added`, size 18, full hash set, owner and ACL |
| `lab-003-file-modified-rule-550-details.png` | `550`, `changed_attributes`, before/after hashes, the content diff, ATT&CK `T1565.001` |
| `lab-003-file-deleted-rule-553-details.png` | `553`, `syscheck.event: deleted`, last known hashes, ATT&CK `T1070.004` / `T1485` |

### `lab-004/` — Security configuration assessment

| File | Shows |
|---|---|
| `lab-004-sca-check-26002-failed.png` | Check `26002` **Failed**, the `secedit` command it runs, and the CIS rationale |
| `lab-004-sca-check-26002-passed.png` | The same check after remediation and rescan: **Passed** |
| `lab-004-sca-check-26002-passed-rule-19010.png` | Rule `19010` — `previous_result: failed`, `result: passed`, policy name, scan ID, CIS `1.1.3` |

## Redaction rules

What is removed before a screenshot goes in this repository:

- **Overlay and LAN IP addresses**, on both the agent and the manager side. Not secrets, but unnecessary infrastructure disclosure — and placeholders cost nothing.
- **Real machine names** — the Windows hostname, the SIEM host's machine name, personal device nicknames.
- **Account names** other than the purpose-made lab accounts (`WazuhLabUser`).
- **Anything resembling a credential**, token, agent key or certificate.

What is deliberately *not* removed:

- **Rule IDs, levels, ATT&CK and compliance mappings** — these are the evidence.
- **File hashes from the FIM lab** — they are hashes of a two-line test file created for the lab.
- **The lab agent names** `WIN11-01` and `WIN10-01` — these are Wazuh agent names chosen for the lab, not the machines' real hostnames.
- **Localized (non-English) field values.** Some service-type and audit fields render in the endpoint's own language because it runs a localized Windows install. That is left visible: it is the reason `auditpol` has to be addressed by GUID in LAB-002, and a suspected factor in the Who-data failure in LAB-003.

## A note on what these images prove

Each screenshot shows an alert produced by **authorised testing on the author's own machines**. A detection firing is a true-positive detection of a *behaviour*, not evidence of an attack. Nothing malicious was downloaded, executed or exploited at any point — the PowerShell tests place suspicious-looking strings on the command line and print them back.
