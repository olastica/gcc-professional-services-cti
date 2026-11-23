# GCC Professional Services — Cyber Threat Intelligence

**Threats to professional services firms in Qatar and the GCC, December 2025 to November 2026.**

This is an intelligence-led threat assessment for a professional services firm in Qatar. It covers three actors: **Payload** ransomware, **The Gentlemen** ransomware and **MuddyWater** (Operation Olalampo). Each indicator was validated against independent sources, and the findings were turned into detection content for Microsoft Defender XDR and Microsoft Sentinel.

`TLP:CLEAR` · Public sources only · MITRE ATT&CK v19 · Author: Olasunkanmi Ogidan

📄 **Read the report:** [REPORT.md](REPORT.md) · [PDF](REPORT.pdf)

---

## Key findings

- **Two ransomware groups have hit the sector in Qatar.** In the last 12 months, The Gentlemen claimed a Qatari design consultancy and Payload claimed a Qatari law firm.
- **The Gentlemen disables security tools before encrypting.** Its EDR killer abuses vulnerable signed Safetica and Lenovo drivers. The driver versions are already catalogued in LOLDrivers, but the hashes Acronis reported are new, so hash blocking alone won't stop it and behavioural detection matters most.
- **MuddyWater's Operation Olalampo is active.** The Iranian state actor's campaign uses new malware (CHAR, GhostFetch, HTTP_VIP) and DLL sideloading through a legitimate binary. Two of its C2 domains were still live on 22 November 2026.
- **Detection content is ready.** The repo holds 72 indicators tiered by confidence, 20 Sigma rules with Defender KQL equivalents, a YARA rule and a STIX 2.1 bundle. 25 unique ATT&CK techniques are mapped.

## Intelligence requirements

| PIR | Question |
|---|---|
| 1 | Which threat actors have targeted professional services firms in Qatar or the wider GCC between December 2025 and November 2026? |
| 2 | What infrastructure have those actors used in that window, and is it still active? |
| 3 | What malware and tools are they deploying, and which MITRE ATT&CK techniques do they use? |

Answers are in [Section 10 of the report](REPORT.md#10-answers-to-the-intelligence-requirements).

## Repository structure

```
├── REPORT.md / REPORT.pdf        Full threat assessment
├── METHODOLOGY.md                How intelligence was collected, validated and rated
├── iocs/
│   ├── iocs.csv                  72 indicators (defanged), with confidence and validation notes
│   ├── gcc_professional_services_cti.stix2.json   STIX 2.1 bundle (actors, malware, indicators, techniques)
│   └── Threat_Intelligence_Register.xlsx           Register with dashboard (public version)
├── detections/
│   ├── sigma/                    20 Sigma rules (payload/, gentlemen/, muddywater/)
│   ├── kql/                      Microsoft Defender XDR advanced hunting queries
│   └── yara/                     YARA rule for the Payload Windows encryptor
├── attack/
│   ├── navigator_layer.json      ATT&CK Navigator layer (v19)
│   └── muddywater_attack_chain.md  MuddyWater infrastructure chain with evidence
└── validation/
    ├── VALIDATION_MATRIX.md      Evidence for every indicator
    └── screenshots/              Validation screenshots (VirusTotal, AlienVault OTX, SOCRadar)
```

## Using the content

| Content | How to use it |
|---|---|
| **Sigma rules** | Validate with `sigma check detections/sigma/`. Convert for your SIEM with sigma-cli, e.g. `sigma convert -t kusto -p microsoft_xdr detections/sigma/`. Replace allowlist placeholders such as `<APPROVED_IT_ACCOUNT>` before deploying. |
| **KQL** | Paste into Microsoft Defender XDR → Hunting → Advanced hunting. Each query is labelled (e.g. `[MW-1]`) and maps back to a Sigma rule ID. Run them as hunts first, then promote to custom detection rules. |
| **YARA** | `yara -r detections/yara/payload_ransomware_windows.yar <path>`. Tested on synthetic data only. |
| **IOC CSV** | Indicators are defanged (`[.]`, `hxxp`). Refang before importing into Defender (Settings → Endpoints → Indicators) or a TIP. Respect the expiry dates in the register. |
| **STIX 2.1** | Import into OpenCTI, MISP or another TIP. Values inside the bundle are **not** defanged, because STIX patterns must be machine-readable. |
| **Navigator layer** | Open [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) → Open Existing Layer → Upload from local. Score = number of actors using the technique. |

## Confidence tiers

| Tier | Meaning |
|---|---|
| **Validated (High)** | Confirmed by two or more independent sources, plus sandbox behaviour or infrastructure linkage |
| **Corroborated (Medium-High)** | Primary source plus at least one independent vendor detection |
| **Single-source (Medium)** | Credible but confirmed by one source only |
| **Reported (Low)** | Listed by one source and not independently verified |

See [METHODOLOGY.md](METHODOLOGY.md) for the full criteria, including how source independence was judged.

## A note on ATT&CK v19

This project uses **ATT&CK v19** (April 2026). In v19, *Defense Evasion* was split into **Stealth (TA0005)** and **Defense Impairment (TA0112)**. T1562 and its sub-techniques became **T1685 Disable or Modify Tools**, and T1574.002 was merged into **T1574.001 Hijack Execution Flow: DLL**. Older tooling that only knows v18 or earlier may flag these tags as unknown.

## Internal deliverables (not published)

This project also produced a *Threat Intelligence – SOC Handover Report* and an internal version of the Threat Intelligence Register, which were delivered to the organisation's SOC team. They contain internal organisational information and are withheld for confidentiality. All intelligence findings, indicators and detection content in this repository are reproduced from public sources in sanitised form.

## Community contributions

While validating The Gentlemen's vulnerable drivers, I found that both driver versions reported by Acronis TRU (Lenovo BootRepair.sys 2.5.30.11281 and Safetica STProcessMonitor 11.26.18) are already catalogued in [LOLDrivers](https://www.loldrivers.io/), but the two driver hashes Acronis published are not. As far as I could find, Acronis is also the first public source linking BootRepair.sys to The Gentlemen. I reported this to the LOLDrivers project:

- Issue [#504](https://github.com/magicsword-io/LOLDrivers/issues/504): the two new hashes, proposed as context only (no samples are public) — *Status: open*
- Pull request [#505](https://github.com/magicsword-io/LOLDrivers/pull/505): adds the Acronis report as a reference to both driver entries — *Status: open, awaiting review*

## Disclaimer

The indicators and rules are provided as-is for defensive use. Infrastructure changes quickly, so check each indicator's status and expiry before blocking it. Test rules in your own environment before you deploy them. Victim names that appear in public leak-site data have been redacted.

## Licence

- **Detection rules and code** (`detections/`, `attack/navigator_layer.json`): [MIT](LICENSE)
- **Report, methodology, indicators and STIX bundle**: [CC BY 4.0](LICENSE-CC-BY-4.0.md)

Third-party reports cited in the report remain the property of their authors.
