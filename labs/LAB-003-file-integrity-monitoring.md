# LAB-003 — File Integrity Monitoring

**Status:** ✅ Complete

## Objective

Put a directory under real-time File Integrity Monitoring and prove that Wazuh detects and distinguishes all three states of a file's lifecycle — **created**, **modified**, **deleted** — with enough forensic detail to reconstruct what changed without ever touching the endpoint.

The question this lab answers is not *"did something happen?"* but *"what exactly changed, and can I prove it after the fact?"*

## Environment

| Component | Value |
|---|---|
| Endpoint | `WIN11-01` — Windows 11 Pro, physical |
| Telemetry | Wazuh **syscheck** (FIM) module — no Sysmon required |
| Monitored path | `C:\SecurityLab` |
| Mode | `realtime` |
| SIEM | Wazuh 4.14.7 |

Agent-side configuration:

```xml
<syscheck>
  <directories check_all="yes" realtime="yes" report_changes="yes">C:\SecurityLab</directories>
</syscheck>
```

Three attributes carry the lab:

- `realtime="yes"` — changes are reported as they happen rather than on the next scheduled scan.
- `check_all="yes"` — size, permissions, owner, group, MD5, SHA-1 and SHA-256 are all recorded, which is what makes the before/after comparison possible.
- `report_changes="yes"` — Wazuh stores a diff of the content, not just the fact that the hash moved.

`C:\SecurityLab` is a purpose-made test directory. In production the same configuration would be pointed at paths that should not change quietly: `C:\Windows\System32\drivers\etc`, service binary directories, web roots, or scheduled-task definitions.

## Detection concept

FIM is a different detection primitive from the previous labs. LAB-001 matched content inside a single event; LAB-002 correlated many events over time. This one maintains **state** — Wazuh keeps a baseline of every monitored file and alerts on the delta.

```text
File operation on C:\SecurityLab → syscheck baseline comparison → Wazuh alert
                                                                   ├─ 554  created   (level 5)
                                                                   ├─ 550  modified  (level 7)
                                                                   └─ 553  deleted   (level 7)
```

The severity split is deliberate on Wazuh's part. A new file appearing is common and benign most of the time. An existing, already-baselined file changing or disappearing is the more interesting signal — it is how binary replacement, log tampering and ransomware all look from the filesystem's point of view.

## Test procedure

Three commands from an Administrator PowerShell, run against a single file so that the three alerts form one continuous chain of evidence:

```powershell
# 1 — create   → expect rule 554
Set-Content C:\SecurityLab\portfolio-test.txt "ORIGINAL VERSION"

# 2 — modify   → expect rule 550
Add-Content C:\SecurityLab\portfolio-test.txt "MODIFIED VERSION"

# 3 — delete   → expect rule 553
Remove-Item C:\SecurityLab\portfolio-test.txt
```

`Set-Content` then `Add-Content` is chosen over two `Set-Content` calls on purpose: appending changes the file size as well as its hashes, so the `size_before` → `size_after` delta becomes part of the evidence.

Verify in Wazuh → Threat Hunting → `WIN11-01` → Events, searching `rule.id:554 OR rule.id:550 OR rule.id:553`, or filtering on `syscheck.path`.

## Expected vs actual result

| Stage | Action | Expected | Actual |
|---|---|---|---|
| Create | `Set-Content` | Rule `554`, level 5 — *File added to the system* | ✅ |
| Modify | `Add-Content` | Rule `550`, level 7 — *Integrity checksum changed* | ✅ |
| Delete | `Remove-Item` | Rule `553`, level 7 — *File deleted* | ✅ |

All three fired in `realtime` mode (`syscheck.mode: realtime` on every alert), within seconds of the command.

### The forensic chain

The three alerts are not three isolated events. Read in order, they reconstruct the file's entire history — and each one's `before` values match the previous alert's `after` values exactly:

| | 554 — created | 550 — modified | 553 — deleted |
|---|---|---|---|
| `syscheck.event` | `added` | `modified` | `deleted` |
| `syscheck.size` | 18 | 18 → 36 | 36 (last known) |
| `syscheck.md5` | `725266d6…f0defe` | `725266d6…f0defe` → `23cef1dd…bdd7b8` | `23cef1dd…bdd7b8` |
| `syscheck.sha1` | `8284c27d…cd14a1` | `8284c27d…cd14a1` → `9046ded6…9b6dfb` | `9046ded6…9b6dfb` |
| `syscheck.mtime` | 09:40:30 | 09:40:30 → 09:45:19 | 09:45:19 |

That continuity is the actual product of FIM. The deletion alert still carries the hash of what was deleted, which means the file can be identified — against a threat-intel feed, a known-good baseline, or a backup — after it no longer exists on disk.

The `550` alert also lists exactly which attributes moved:

```text
syscheck.changed_attributes: size, mtime, md5, sha1, sha256
syscheck.diff:               --- > MODIFIED VERSION
```

`changed_attributes` is the first field to read during triage. A content change touches hashes and size. A change that lists only `permission` or `uname` is a different story — that is someone altering who can reach the file, not what is in it.

### MITRE ATT&CK, applied by Wazuh's built-in rules

| Rule | Technique | Tactic |
|---|---|---|
| `554` | — (no ATT&CK mapping; file creation alone is not a technique) | — |
| `550` | `T1565.001` — Stored Data Manipulation | Impact |
| `553` | `T1070.004` — Indicator Removal: File Deletion<br>`T1485` — Data Destruction | Defense Evasion, Impact |

`553` carrying two techniques across two tactics is worth noting: the same filesystem event is either an attacker covering their tracks or an attacker destroying data, and the telemetry alone cannot tell you which. Context — *which* file, *whose* account, *what else happened around it* — decides that, not the alert.

### Compliance mappings

Wazuh attaches regulatory references to the FIM rules out of the box — PCI DSS `11.5`, NIST 800-53 `SI.7`, HIPAA `164.312.c.1` / `.c.2`, GDPR `II_5.1.f`, GPG13 `4.11`, and TSC `PI1.4`, `PI1.5`, `CC6.1`, `CC6.8`, `CC7.2`, `CC7.3`. File integrity monitoring is one of the few controls that appears near-verbatim in almost every framework, which is why it is usually among the first things an auditor asks to see.

## Evidence

![File created — rule 554](../screenshots/lab-003/lab-003-file-created-rule-554.png)

*Right: `Set-Content` creates `portfolio-test.txt`. Left: the resulting `554` alert — `syscheck.event: added`, `mode: realtime`, size 18 bytes, full MD5/SHA-1/SHA-256, owner `Administrators` (`S-1-5-32-544`), and the complete Windows ACL in `win_perm_after`.*

![File modified — rule 550](../screenshots/lab-003/lab-003-file-modified-rule-550-details.png)

*`Add-Content` appends a line. The `550` alert (level 7) shows `changed_attributes: size, mtime, md5, sha1, sha256`, both hash sets side by side, the `mtime` moving from 09:40:30 to 09:45:19, the ATT&CK mapping `T1565.001`, and the content diff `> MODIFIED VERSION`.*

![File deleted — rule 553](../screenshots/lab-003/lab-003-file-deleted-rule-553-details.png)

*`Remove-Item` deletes the file. The `553` alert (level 7) records `syscheck.event: deleted` along with the last known state — size 36, the post-modification hashes — and maps to both `T1070.004` and `T1485`.*

## Analysis

FIM completes the coverage the earlier labs started. LAB-001 watches processes, LAB-002 watches authentication; neither would see a file quietly replaced on disk by a process that was itself unremarkable. Syscheck closes that gap, and it does so with no dependency on Sysmon.

The trade-off is scope. A monitored directory produces an alert for every legitimate change in it, so FIM on a busy path — a user profile, a build output directory, a log folder — is a noise generator rather than a detection. The engineering work in a real deployment is not enabling syscheck; it is choosing paths that *should not change*, and excluding the ones that change constantly by design.

Real-time mode also has a cost: it holds a watch on the directory rather than waking on a timer. That is affordable for a handful of sensitive paths and not affordable for an entire volume.

## Lessons learned

- FIM is stateful detection. Unlike a rule that examines one event, syscheck compares against a stored baseline — which is why it can report a *before* value at all.
- The deletion alert retains the deleted file's hashes. Detection survives the evidence being destroyed, which is exactly the case the technique `T1070.004` exists to describe.
- `changed_attributes` is the fastest triage field in a `550` alert: content change, permission change and ownership change are three different investigations.
- Severity follows state, not action. Wazuh rates a modification and a deletion (level 7) above a creation (level 5) because a baselined file changing is a stronger signal than a new file appearing.
- `report_changes="yes"` is what turns "the hash changed" into "here is the line that was added". It stores file content on the manager, so it is enabled for specific sensitive paths — never blanket, and never for paths that could hold secrets.
- Path selection is the whole design decision. FIM's value is inversely proportional to how often the monitored files legitimately change.

## Portfolio takeaway

Stateful, real-time integrity monitoring with a complete forensic chain: three alerts on one file, each one's *before* state matching the previous one's *after*, enough to reconstruct the file's entire lifecycle — including its identity after deletion — purely from SIEM telemetry.

## MITRE ATT&CK

**T1565.001 — Stored Data Manipulation** (Impact) and **T1070.004 — Indicator Removal: File Deletion** / **T1485 — Data Destruction** (Defense Evasion, Impact), both applied by Wazuh's built-in rules. As in the other labs, this demonstrates *visibility* of those techniques, produced by authorised benign testing rather than by an attack.
