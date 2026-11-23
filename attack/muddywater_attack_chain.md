# MuddyWater – Operation Olalampo: FMAPP sideloading chain

Built from independently validated IOCs (IDs refer to the register and validation matrix). All indicators defanged.

```mermaid
flowchart TD
    A["Phishing Office document<br/>Macro runs on open"] --> B["codefusiontech[.]org<br/>Serves /FMAPP.dll<br/>CTI-0027, CTI-0032"]
    B --> C["FMAPP.exe loads FMAPP.dll<br/>Legit EXE, malicious DLL<br/>CTI-0040"]
    C --> D["162.0.230[.]185<br/>C2 server, Namecheap<br/>CTI-0031"]
    E["jerusalemsolutions[.]com<br/>Origin server = this IP<br/>CTI-0030"] -. "hidden behind Cloudflare" .-> D

    classDef infra fill:#FAECE7,stroke:#993C1D,color:#712B13
    classDef file fill:#EEEDFE,stroke:#534AB7,color:#3C3489
    class B,D,E infra
    class C file
```

## Evidence for each link

| Link | Evidence | Source |
|---|---|---|
| Document → codefusiontech[.]org | Office droppers listed as communicating files of the domain | VirusTotal (Relations) |
| codefusiontech[.]org → FMAPP.dll | URL `hxxp://codefusiontech[.]org/FMAPP.dll` observed 17 May 2026 | AlienVault OTX (Associated URLs) |
| FMAPP.exe → FMAPP.dll | Legitimate Fortemedia binary sideloads malicious DLL | Group-IB Operation Olalampo |
| FMAPP.dll → 162.0.230[.]185 | DLL contacts the IP (SHA-256 3fa148e2…68af) | VirusTotal (Relations) |
| jerusalemsolutions[.]com ↔ 162.0.230[.]185 | TLS certificates for the domain seen on the IP (Dec 2025 – Feb 2026); domain fronted by Cloudflare | VirusTotal (Historical SSL certificates) |

## Notes

- The document → FMAPP step reflects the campaign as described by Group-IB; Group-IB also logged operators launching FMAPP.exe via PowerShell commands sent over Telegram.
- Do not block FMAPP.exe by hash – it is a legitimate signed binary. Detect FMAPP.exe loading FMAPP.dll from a non-standard path.
