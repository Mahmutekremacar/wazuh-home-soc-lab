# Troubleshooting

Every problem hit while building this lab, and what each one cost to find. A lab where nothing broke is a lab where nothing was learned — these sections are the ones worth reading.

Format: **symptom → cause → resolution → lesson.**

---

## 1. Telemetry is not the same thing as an alert

**Symptom.** Sysmon was installed, the Sysmon channel was configured in the agent, and Threat Hunting still looked empty when searching the Sysmon rule-ID range.

**Cause.** Wazuh maps Sysmon Event ID 1 to built-in rule `61603`, which is **level 0** — a classification rule that deliberately produces no visible alert. Level-0 rules categorise events so that other rules can build on them. Wazuh only surfaces an alert when a more specific rule matches.

**Resolution.** Write a rule that matches the telemetry — which became LAB-001.

**Lesson.** *Collected ≠ detected ≠ alerted.* Three distinct states. An empty alert view does not mean an empty pipeline; check the event stream before assuming the agent is broken.

---

## 2. One event produces one alert

**Symptom.** Four graded PowerShell rules (`100100`–`100103`) were written, but a single test command only ever produced `100100`.

**Cause.** Two things at once. Wazuh emits the **most specific matching rule** for an event, not every conceptual stage simultaneously — the original design expected a layered cascade that does not exist. And the test event's `commandLine` field contained only the plain PowerShell path, so there was genuinely nothing for the stronger rules to match.

**Resolution.** Rules rewritten as four independent, self-contained detections ordered by specificity. Test commands rewritten so they actually contain the indicator strings.

**Lesson.** When a rule does not fire, open the **raw event** and compare the real field value against the pattern before touching the regex. Blind regex edits are how you end up with a rule that matches nothing and a false sense that it works.

---

## 3. Check built-in coverage before writing a custom rule

**Symptom.** Custom correlation rule `100200` (5 × `60122` in 120 s, `same_field` on the target username) was structurally correct and never fired.

**Cause.** Generating five genuine `60122` events inside one 120-second window was harder than expected. While chasing that, Wazuh's **built-in rule `60204` — Multiple Windows Logon Failures, level 10, frequency 8** — turned out to already do exactly this job, complete with ATT&CK and compliance mappings.

**Resolution.** `100200` retired, kept commented in `configs/custom-rules.xml` with the reasoning. `60204` used instead.

**Lesson.** Duplicate detections for one behaviour are a false-positive generator, not extra coverage. Writing `100200` was still worth it — it is how the built-in rule got found, and it taught `frequency` / `timeframe` / `if_matched_sid` / `same_field`. Knowing when to delete your own work is a detection-engineering skill.

---

## 4. Localized Windows breaks `auditpol` by name

**Symptom.**

```powershell
auditpol /get /subcategory:"Logon"
# Error 0x00000057 occurred: The parameter is incorrect.
```

**Cause.** The endpoint runs a localized (non-English) Windows install. Audit subcategory **names are translated by the OS**; the English strings simply do not exist on that system.

**Resolution.** Address subcategories by their **locale-independent GUID**:

```powershell
auditpol /get /subcategory:"{0CCE9215-69AE-11D9-BED3-505054503030}"   # Logon
auditpol /get /subcategory:"{0CCE921D-69AE-11D9-BED3-505054503030}"   # File System
auditpol /get /subcategory:"{0CCE9223-69AE-11D9-BED3-505054503030}"   # Handle Manipulation
```

**Lesson.** Any script or runbook that touches Windows auditing should use GUIDs. Names are a localization trap, and one that typically only shows up on someone else's machine.

---

## 5. Who-data: prerequisites valid, vendor engine still failed

**Symptom.** With `whodata="yes"` set on the monitored directory, no user or process attribution ever appeared on FIM events.

**Investigation.** Every Windows prerequisite was verified independently rather than assumed:

| Check | Result |
|---|---|
| File System auditing | `Success` |
| Handle Manipulation auditing | `Success` |
| SACL on the monitored directory | absent at first → created manually → **persisted** across restarts |
| `auditpol /backup` | succeeded, exit code `0` |

**Cause.** The agent failed inside its own audit-policy initialization:

```text
ERROR: (6955): Auditpol command failed, attempt number: 1
ERROR: (6915): Audit policies could not be auto-configured due to the Windows version.
ERROR: (6916): Local audit policies could not be configured.
ERROR: (6710): Failed to start the Whodata engine.
Directories/files will be monitored in Realtime mode
ERROR: (6646): DeleteAce() failed restoring the SACLs. Error '87'
```

**Resolution.** Documented as a limitation. Real-time FIM kept working throughout — the fallback is explicit in that log line, and visible in the alert data as `syscheck.mode: realtime`.

**Lesson.** Isolate by layer, then stop at an honest conclusion. Localization is a **suspected** contributing factor; the endpoint also runs a very recent Windows 11 build, and the available evidence does not separate the two. The controlled experiment — enable Who-data on the second, English endpoint and compare — was not run. Say "suspected", not "caused by". Full write-up in LAB-003.

---

## 6. Endpoint identity and network identity are different things

**Symptom.** The agent for the physical endpoint went `disconnected`, and a new agent named after the machine's Windows hostname appeared as `active` — with the same overlay IP. It looked like the network layer had renamed the machine.

**Cause.** It had not. Changing the manager `<address>` does **not** change an agent's identity; the key and ID stay the same. What actually happened is that the agent **re-enrolled** during the network and restart churn, received a new client key, and — because no explicit `<agent_name>` was configured — Wazuh fell back to the real Windows hostname. Confirmed by reading `client.keys` on the manager.

**Resolution.** Delete the stale registration, then pin the name for all future enrollments:

```xml
<enrollment>
  <enabled>yes</enabled>
  <manager_address><WAZUH_SERVER_IP></manager_address>
  <port>1515</port>
  <agent_name>WIN11-01</agent_name>
</enrollment>
```

Verified by re-enrolling once more and confirming the agent came back under the right name.

**Lesson.** Agent identity comes from **enrollment and the client key**, not from the route to the manager. Set `<agent_name>` explicitly at build time; hostname-derived naming is a time bomb that goes off during an unrelated change. In the architecture this is two endpoints, not three — and an agent list with phantom entries is the first thing a reviewer notices.

---

## 7. The dashboard summary and the event stream can disagree

**Symptom.** After the SCA remediation and an agent restart, the Configuration Assessment page still showed the previous scan timestamp and check `26002` still rendered as `Failed`. It looked like the remediation had not taken effect.

**Cause.** It had. The summary panel had not refreshed. The agent log proved a new scan had started and completed:

```text
sca: INFO: Module started.
sca: INFO: Loaded policy '...\ruleset\sca\cis_win11_enterprise.yml'
sca: INFO: Starting Security Configuration Assessment scan.
```

**Resolution.** Search the alert index directly. The real `19010` event was there, with `previous_result: failed` / `result: passed`, timestamped to match the scan in the agent log exactly.

**Lesson.** When a SIEM's aggregated view contradicts the endpoint's own logs, trust the logs and go to the raw events. Summary panels are a convenience layer, not the source of truth.

---

## 8. A tool failing is not the same as an authentication failing

**Symptom.** Attempts to generate failed logons with `runas` produced no Event 4625 at all.

```powershell
runas /user:.\WazuhLabUser cmd.exe
# RUNAS ERROR: Unable to acquire user password
```

**Cause.** `runas` failed *before* it attempted authentication, so Windows had nothing to log.

**Resolution.** Use `Get-Credential` + `Start-Process -Credential`, or `net use` for a network logon type. The final evidence used repeated failed Remote Desktop logons from the second endpoint — the most realistic method, and the only one that produced enough failures to cross the correlation threshold.

**Lesson.** Verify the raw Windows event before blaming the SIEM. A missing alert has at least four distinct causes — the endpoint did not log it, the agent did not forward it, no rule matched it, or the search is scoped wrongly — and they should be checked in that order.

---

## 9. Small operational gotchas

| Problem | Fix |
|---|---|
| `Restart-Service WazuhSvc` → *"cannot be stopped"* | `net stop wazuh` then `net start wazuh` |
| Dashboard over the overlay → `ERR_EMPTY_RESPONSE` | Browse to **`https://<WAZUH_SERVER_IP>`**, not `<WAZUH_SERVER_IP>:443` — the latter sends plain HTTP to a TLS port |
| Certificate warning on the overlay address | Expected; the certificate was not issued for that IP. Acceptable for a private lab |
| Real-time FIM ignores the monitored directory | The directory must exist **before** the agent restarts |
| Create/modify/delete produced unreadable FIM evidence | Wait 10–20 s between steps so each state is captured separately |
| "No alert" after a test | Widen the time range and check the agent filter before touching any rule |
| Two Linux hosts answering to the same hostname | `hostname` alone does not identify a machine. Check a service that only one of them runs before debugging |

---

Conceptual takeaways drawn from these: [`lessons-learned.md`](lessons-learned.md).
