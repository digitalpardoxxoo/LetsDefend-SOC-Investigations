# LetsDefend SOC Investigations

A practical SOC Analyst L1 / Incident Responder portfolio documenting security alert investigations performed on LetsDefend.

Each case study documents the investigation process, including:

- Initial alert details and investigation objectives
- Evidence collection and investigation methodology
- Analysis of suspicious activity and endpoint or network artifacts
- Timeline reconstruction and event correlation
- Confirmed findings versus unverified hypotheses
- MITRE ATT&CK technique mapping
- Final alert classification and recommended response

## Repository Structure

```text
LetsDefend-SOC-Investigations/
│
├── README.md
│
├── Methodology/
│   └── Investigation-Methodology.md
│
└── Alerts/
    │
    ├── SOC341-Local-Privilege-Escalation-CVE-2025-32463/
    │   ├── Investigation.md
    │   ├── Timeline.md
    │   └── Evidence/
    │
    ├── SOC342-SharePoint-ToolShell-CVE-2025-53770/
    │   ├── Investigation.md
    │   ├── Timeline.md
    │   └── Evidence/
    │
    └── SOC343-WinRAR-CVE-2025-8088/
        ├── Investigation.md
        ├── Timeline.md
        └── Evidence/
```

## Case Studies

| Alert | Investigation Topic | Classification |
|---|---|---|
| [SOC341](Alerts/SOC341-Local-Privilege-Escalation-CVE-2025-32463/Investigation.md) | Local Privilege Escalation via chroot - CVE-2025-32463 | True Positive |
| [SOC342](https://github.com/digitalpardoxxoo/LetsDefend-SOC-Investigations/blob/main/LetsDefend-SOC-Investigations/Alerts/SOC342%20-%20CVE%E2%80%912025%E2%80%9153770%20SharePoint%20ToolShell%20Auth%20Bypass%20and%20RCE/Investigation.md) | SharePoint ToolShell Authentication Bypass and RCE - CVE-2025-53770 | True Positive |
| [SOC343](https://github.com/digitalpardoxxoo/LetsDefend-SOC-Investigations/blob/main/LetsDefend-SOC-Investigations/Alerts/SOC343-WinRAR-CVE-2025-8088/Investigation.md) | WinRAR Path Traversal Vulnerability - CVE-2025-8088 | True Positive |

## Investigation Methodology

Each investigation follows a structured approach:

1. **Alert Review:** Understand the alert, affected host, source, destination, and detection reason.
2. **Evidence Collection:** Identify relevant logs, process activity, files, commands, and other artifacts.
3. **Investigation:** Correlate evidence and examine suspicious activity.
4. **Timeline Reconstruction:** Arrange observed events chronologically.
5. **MITRE ATT&CK Mapping:** Map techniques supported by the collected evidence.
6. **Classification:** Determine whether the alert is a True Positive or False Positive.
7. **Response Recommendations:** Document containment, remediation, and further investigation steps.

Refer to [Investigation Methodology](Methodology/Investigation-Methodology.md) for the investigation approach.

## Evidence and Privacy

Screenshots and sanitized evidence exports are stored in the respective case's `Evidence/` folder.

Use descriptive filenames and reference evidence directly from the investigation report.

Before publishing, remove:

- Credentials, passwords, and authentication tokens
- Personal information
- Sensitive internal infrastructure details
- Unredacted email addresses
- Data belonging to other users or organizations

## Investigation Standards

- Preserve original timestamps and clearly identify their timezone.
- Distinguish direct observations from interpretations.
- Do not claim successful exploitation, persistence, privilege escalation, or impact without supporting evidence.
- Record investigation limitations and unanswered questions.
- Treat alert-provided MITRE ATT&CK mappings as investigation leads, not automatically confirmed techniques.
- Ensure every conclusion is supported by collected evidence.

---

*This repository is a record of practical SOC investigations, evidence analysis, incident classification, and continuous improvement in security operations.*
