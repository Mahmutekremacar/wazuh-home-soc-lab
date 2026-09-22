# Lessons Learned

The conceptual takeaways from building this lab, separated from the incidents that produced them. Each one is traceable to something that actually happened — the incidents are in [`troubleshooting.md`](troubleshooting.md).

---

## On telemetry and detection

**1. Collected, detected and alerted are three different states.**
Sysmon Event ID 1 reached the manager correctly the whole time LAB-001 looked broken. Wazuh classified it with a level-0 rule, which raises nothing by design. A silent dashboard is not evidence of a silent pipeline, and the fix for each of the three states is different.

**2. A detection is not proof of malicious activity.**
Rule `100103` firing is a true-positive detection of a *behaviour*, produced by an authorised test on the author's own machine. Both statements are true simultaneously. An analyst who cannot hold both will either dismiss real alerts or escalate their own admin scripts.

**3. Severity should escalate on evidence, not on process name.**
"Alert on every `powershell.exe`" is not a detection, it is a noise generator. The four-tier design exists because the interesting question is never *did PowerShell run* but *what was it told to do* — which is why Sysmon's command line, and not the native Windows process event, is what the rules read.

**4. One event produces one alert.**
Wazuh emits the most specific matching rule, not every conceptual stage at once. Detections have to be designed as independent, self-contained rules ordered by specificity — not as a cascade that "builds up" severity.

**5. Different detection primitives fail in different ways.**
Content matching on one event (LAB-001), temporal correlation across many (LAB-002), stateful baseline comparison (LAB-003) and configuration assessment (LAB-004) are genuinely different capabilities. Building one of each surfaced four different classes of failure — which is the argument for building all four rather than four variants of one.

---

## On engineering judgement

**6. Check built-in coverage before writing anything.**
Rule `100200` worked as designed and was deleted anyway, because Wazuh's `60204` already covered the behaviour with better mappings. Two alerts for one behaviour makes the ruleset worse. The rule was not wasted: writing it is how the built-in one was found.

**7. Knowing when to delete your own work is a skill.**
This is the same lesson as #6 from the other side. The instinct to keep something because it took effort is exactly what produces noisy, unmaintainable rulesets.

**8. Validate the pipeline before building on it.**
LAB-000 exists so that every later failure has one fewer possible cause. An untested pipeline does not produce errors — it produces silence, which is much harder to debug.

**9. Compare the pattern against the real field value, not against what you typed.**
The PowerShell rules were correct while the *test data* was wrong. Editing the regex would have made a working rule broken. Open the raw event first.

**10. Debug by layer, cheapest first.**
Transport → config present → config loaded → agent status → search scope. Each step eliminates a whole class of cause. "Present in the config file" and "loaded into the running agent" are two different claims, and the log line that distinguishes them is the one worth knowing.

---

## On evidence and honesty

**11. Independent validation beats self-reporting.**
"I changed the setting" is a claim. `previous_result: failed → result: passed`, observed by the tool on its own next scan, is evidence. LAB-004 is built entirely around that distinction, and it is the shape of evidence a compliance or vulnerability-management team works with daily.

**12. Verify with the same mechanism the checker uses.**
The SCA remediation was confirmed with `secedit /export` — what the CIS check itself runs — rather than with a friendlier command that reports something adjacent. A check that passes against a different measurement has not been verified.

**13. Trust endpoint logs over dashboard summaries when they disagree.**
Aggregated panels are a convenience layer. The event stream is the source of truth.

**14. A failed feature still produces useful engineering evidence.**
Who-data never worked. Verifying every Windows prerequisite independently, isolating the failure to the vendor's own initialization path, and stopping there is worth more than either hiding the failure or spending three more hours working around it.

**15. Say "suspected" when the evidence supports "suspected".**
Two plausible causes for the Who-data failure were identified — localization and a very recent OS build — and the available evidence separates neither. The controlled experiment that would settle it is named and recorded as not performed. Overclaiming a root cause is the fastest way to lose a technical interview.

**16. Document failures as first-class content.**
The troubleshooting sections are the most convincing part of this project, because they show reasoning under uncertainty rather than a happy path. A write-up with no failures in it invites the question of what was left out.

---

## On operations

**17. Endpoint identity is not network identity.**
Re-enrollment changes an agent's identity; changing the route to the manager does not. Set `<agent_name>` explicitly at build time — hostname-derived naming is a time bomb that detonates during an unrelated change.

**18. Secure remote access does not require public exposure.**
An overlay network gave full dashboard, SSH and agent connectivity with nothing port-forwarded to the internet. Testing it from inside the home LAN proves nothing, though — the overlay routes directly over the LAN when both peers are local, so the verification has to come from off-network.

**19. Use locale-independent identifiers.**
Windows audit subcategory names are translated; their GUIDs are not. Any runbook that touches Windows auditing should use GUIDs, or it works only on the machine it was written on.

**20. Pick a first remediation that is understandable, reversible and low-risk.**
Minimum password age was chosen over anything touching networking, credential providers, BitLocker or remote access — all of which can lock you out of your own lab. Reading the CIS rationale before applying the fix is what separates a security action from a checkbox exercise.

**21. Scope selection is the real work in monitoring.**
Enabling FIM takes one line. Choosing paths that *should not change* — and excluding the ones that change constantly by design — is the engineering. The same is true of detection rules: the value is in what you decide not to alert on.
