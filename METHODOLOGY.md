# Methodology

This document describes how the intelligence in this repository was collected, validated and turned into detection content. It is meant to let a reader reproduce or audit the work.

---

## 1. Requirements first

The work was driven by three time-bound Priority Intelligence Requirements (PIRs), set before any collection began:

1. Which threat actors have targeted professional services organisations in Qatar or the wider GCC between December 2025 and November 2026?
2. What infrastructure have they used in that window, and is it still active?
3. What malware and tools are they deploying, and which MITRE ATT&CK techniques do they use?

Each PIR is answered explicitly in Section 10 of the [report](REPORT.md).

## 2. Sources and tools

| Purpose | Tools and sources |
|---|---|
| Actor and landscape research | Vendor research (Group-IB, Acronis, Microsoft, Trend Micro, Sophos, Check Point, Symantec, Trellix, Cyble, CYFIRMA, Nopal Cyber, Derp.ca), SOCRadar Ransomware Intelligence |
| Indicator enrichment | VirusTotal (detections, details, relations, behaviour, WHOIS, passive DNS, certificates), AlienVault OTX (pulses, passive DNS, associated URLs), MalwareBazaar (signatures, YARA matches) |
| Driver checks | LOLDrivers |
| Technique mapping | MITRE ATT&CK v19 |
| Detection engineering | Sigma, sigma-cli, pySigma (Kusto backend), YARA, Microsoft Defender XDR Advanced Hunting |
| Packaging | STIX 2.1 (validated with the OASIS `stix2-validator`), ATT&CK Navigator |

Only public, TLP:CLEAR sources were used. No internal telemetry is included.

## 3. Process

1. **Define PIRs** and the environment in scope (Windows endpoints; Microsoft Defender XDR and Sentinel).
2. **Map the threat landscape** and split actors into *confirmed* (observed against the sector in Qatar) and *assessed* (credible regional or sector risk).
3. **Select actors for deep analysis** — two ransomware groups with confirmed Qatari professional services victims and one active state espionage campaign.
4. **Collect indicators from primary sources** — the original vendor reports, not news summaries.
5. **Triage** large indicator sets: fully validate a representative subset, bulk-check the remainder.
6. **Validate** each indicator against the criteria in Section 4.
7. **Pivot** from validated indicators to related infrastructure and files, testing each lead before accepting it.
8. **Map behaviour to ATT&CK v19.**
9. **Engineer detections** in Sigma, convert to KQL, and validate.
10. **Package and hand over** — internal register to the SOC; sanitised versions published here.

## 4. Validation criteria

### 4.1 File hashes

| Check | What counts as a pass |
|---|---|
| Independent sources | Listed by the primary source **and** confirmed by at least one independent source (VirusTotal vendor labels, MalwareBazaar signature) |
| Family labels | Vendors with their **own** engines name the expected family |
| Behaviour | Sandbox behaviour matches the published description, where the sample runs |
| Consistency | Size, MD5/SHA-1/SHA-256 and timestamps agree across platforms |
| Links | The file contacts, or is contacted by, other validated indicators |

### 4.2 Domains and IPs

| Check | What counts as a pass |
|---|---|
| Detections | Flagged by multiple vendors on VirusTotal; present in OTX pulses |
| Registration | Registration date consistent with campaign timing |
| Resolution history | Passive DNS reviewed; shared CDN and parking IPs identified and excluded |
| Malware relations | Malicious files communicate with the domain or IP |
| Current status | Live, suspended (`clientHold`), expired or parked — recorded with a date |

### 4.3 Independence of sources

Sources were counted as independent only when they did not derive from each other:

- Vendors that license another vendor's engine (for example, the BitDefender engine used by ALYac, Arcabit, eScan, GData, Emsisoft and VIPRE) were counted as **one** opinion.
- An advisory and a YARA rule written by the same original researcher were counted as **one** source.
- Automated filenames from bulk feeds that list many unrelated malware families were disregarded.
- AI-generated analysis (VirusTotal *Code insights*) was treated as a lead only and labelled *unverified*.

## 5. Confidence tiers

| Tier | Confidence | Definition |
|---|---|---|
| Validated | High | Two or more independent sources, consistent labels, and supporting behaviour or links |
| Corroborated | Medium-High | Primary source plus VirusTotal presence and at least one supporting vendor label; bulk-checked |
| Single-source | Medium | Confirmed malicious, but attribution rests on one primary source |
| Reported, unverified | Low | One source only and not found in any public repository |

Confidence in *maliciousness* and confidence in *attribution* were assessed separately where they differed — for example, a file confirmed as ransomware by many vendors, but attributed to a specific family by only one researcher.

## 6. Pivoting rules

A pivot was accepted only when the shared attribute is specific to the attacker. The following were **rejected** as pivots:

| Attribute | Why it is not a valid pivot |
|---|---|
| Registrar abuse email (e.g. `abuse@namecheap.com`) | Appears on every domain registered with that registrar |
| WHOIS registrant IDs behind a privacy service | Identify the privacy service, shared by thousands of domains |
| Cloudflare IPs | Shared by millions of legitimate websites |
| Parking IPs and name servers | Belong to parking providers; appear when domains expire |
| Generic Go import hashes (imphash) | Many unrelated Go programs share similar import tables |

Every accepted and rejected pivot is recorded in Section 5.4 of the [report](REPORT.md).

## 7. Detection engineering

1. Write Sigma rules from **validated behaviour**, preferring artefacts that no legitimate software produces (distinctive paths, task and service names).
2. Validate with `sigma check`, including ATT&CK tag validation against v19. All 20 rules pass with 0 errors and 0 issues.
3. Convert to KQL with pySigma (Kusto backend, Microsoft XDR pipeline). Where no automatic mapping exists — driver loads, DNS, proxy URLs, scheduled-task events — queries were written by hand against Defender tables.
4. Run queries in Defender Advanced Hunting to confirm they are valid. Two have been run in a live tenant; the remainder are pending.
5. Test YARA logic on synthetic files and scan benign files for false positives.

No rule has been tested against live malware in a lab. All rules are marked **experimental**.

### ATT&CK v19 notes

- **Defense Evasion was retired** and split into **Stealth** (TA0005) and **Defense Impairment** (TA0112).
- **T1562 Impair Defenses** sub-techniques were consolidated into **T1685 Disable or Modify Tools**. Rules use T1685.
- **T1574.001 is now named *Hijack Execution Flow: DLL***; the former *DLL Side-Loading* (T1574.002) and *DLL Search Order Hijacking* were merged into it. T1574.002 is not used.

## 8. Indicator lifecycle

Every indicator carries an expiry date, after which it should be reviewed rather than left in place indefinitely:

| Indicator type | Review period |
|---|---|
| File hashes and host artefacts | 6 months |
| Active domains and URLs | 3 months, or the domain's own expiry date if sooner |
| Hosting IPs | 60 days |
| Suspended or expired domains (retro-hunting only) | 30 days |

## 9. Publication and sanitisation

- **Defanging.** Domains, URLs and IPs are defanged (`[.]`, `hxxp`) in human-readable files. They are left raw only where machines must read them: the STIX bundle, Sigma rules and KQL queries. Hashes, mutexes, paths and task names are not defanged, as they cannot be clicked or resolved.
- **Victims.** No victim organisation is named. Screenshots containing victim names or personal data were redacted or cropped before publication.
- **Organisation.** The organisation is described only as "a professional services firm in Qatar". Indicator IDs use the public `CTI-` prefix.

## 10. Internal deliverables (not published)

This project also produced a *Threat Intelligence – SOC Handover Report* and an internal version of the Threat Intelligence Register, which were delivered to the organisation's SOC team. They contain internal organisational information and are withheld for confidentiality. All intelligence findings, indicators and detection content in this repository are reproduced from public sources in sanitised form.

## 11. Limitations

See Section 9 of the [report](REPORT.md) for the full list of limitations and intelligence gaps.
