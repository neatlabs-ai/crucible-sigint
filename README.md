# CRUCIBLE SIGINT

**Passive OSINT Infrastructure Fingerprinting Engine**

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111%2B-green)
![License](https://img.shields.io/badge/License-MIT-yellow)
![OSINT](https://img.shields.io/badge/Type-Passive%20OSINT-cyan)

> *"One confirmed-bad domain → full infrastructure cluster in under 90 seconds."*

---

## Methodology Credit

**The foundational analytical approach in CRUCIBLE is directly inspired by the work of Ryan McDonald** (Principal Security Engineer | USMC 0341).

Ryan published ["Fingerprinting Malicious Infrastructure Using Free Resources"](https://www.linkedin.com/in/ryan-mcdonald/) (LinkedIn, May 2026), documenting his passive pivot of the **DSJ Exchange / BG Wealth Sharing LTD** pig-butchering operation — a $150M cryptocurrency fraud that victimized thousands of people, ultimately traced by FBI Operation Level Up with $41M in stolen funds frozen.

Ryan demonstrated — using only free passive sources (crt.sh, urlscan.io, DNS, WHOIS, manual JS inspection) — how a single confirmed-bad domain maps an entire 47-domain criminal infrastructure cluster, identifies on-chain wallet drain mechanisms, and reveals the two-layer brand structure of a large-scale scam operation.

**CRUCIBLE automates that methodology.** The investigative framework is Ryan's work. This tool is the automation layer built on top of it.

---

## What It Does

CRUCIBLE takes a single seed domain and runs a 7-stage passive pipeline:

| Stage | Source | What It Finds |
|-------|--------|---------------|
| **01 Cert Transparency** | crt.sh + certspotter | Sister domains, NEIBU admin portals, cert timeline |
| **02 DNS Resolution** | dns.google (DoH) | A/AAAA/MX/NS/TXT/SOA records, parking indicators |
| **03 IP Intelligence** | freeipapi.com + ip-api | ASN, ISP, hosting type, proxy/CDN detection |
| **04 RDAP Registration** | rdap.org | Registrar, creation date, status flags |
| **05 urlscan.io** | urlscan.io | Historical scan count, additional IPs, ASNs |
| **06 JS Bundle Scan** | Live domain fetch | MAX_UINT wallet drain, ERC-20/TRC-20, mobileconfig |
| **07 Threat Score** | All signals | 12-signal weighted composite with confidence rating |

### 12-Signal Threat Scoring Model

Signals are weighted by investigative value. The highest-weight signals (3.0×) represent direct evidence, not inference:

| Signal | Weight | What It Detects |
|--------|--------|-----------------|
| JS Wallet Drain | 3.0 | MAX_UINT `approve(0xffff...ffff)` in deposit flow |
| NEIBU Admin Portal | 3.0 | 内部 (internal) subdomains — Chinese-dev admin panel |
| Known Operation Match | 3.0 | Direct DSJ/BG Wealth infrastructure fingerprint |
| Scam Naming Pattern | 2.5 | dsj*, ffs*, ge7*, neibu*, suspicious TLDs |
| Domain Cluster Volume | 2.0 | 10+ domains from CT = scam-kit-as-a-service |
| Chinese Cloud Infra | 2.0 | Alibaba Cloud SG, Tencent EdgeOne |
| CDN Origin Masking | 1.5 | Cloudflare, AWS Global Accelerator |
| Registrar Risk | 1.5 | gname.com, nicenic (primary scam-kit registrars) |
| Domain Freshness | 1.5 | Age-based risk (< 30 days = critical) |
| API Failover Triplet | 1.5 | api.ddjea, api.ddjeb, api.dsjhout patterns |
| Suspicious Infra | 1.5 | DNS parking, scam hosting ASNs, internal subdomains |
| urlscan Presence | 1.0 | Historical scan count corroboration |

---

## Installation

**Requirements:** Python 3.10+, 3 packages, no API keys, no accounts.

```bash
# 1. Clone
git clone https://github.com/neatlabs-ai/crucible-sigint.git
cd crucible-sigint

# 2. Install dependencies
pip install fastapi uvicorn httpx

# 3. Run
python crucible_app.py

# 4. Open
# http://localhost:8000
```

The server auto-selects a free port (8000 → 8080 → 8888 → 9000) if your preferred port is in use.

---

## Five Modes

| Mode | Use Case |
|------|----------|
| **Standard** | Full 7-stage pipeline for any suspected domain |
| **Investigator** | Verbose mode, raw API responses in JSON export for LEA referrals |
| **Phishing / Brand Abuse** | Point at your brand domain, find every lookalike in cert transparency |
| **Cert Intelligence** | Direct wildcard CT queries with CA distribution and issuance timeline |
| **Bulk IOC** | Enrich up to 50 domains/IPs at once, export SIEM-ready CSV |

---

## Demo Seeds

These are confirmed domains from documented criminal operations. Run them in Standard mode to see the full pipeline with real data.

| Domain | Operation | What to Expect |
|--------|-----------|----------------|
| `exofdsj09.net` | DSJ Exchange / BG Wealth Sharing | 40+ domains, NEIBU portals, gname registrar, Alibaba Cloud |
| `dsjexchange.com` | DSJ Exchange — trading platform | AWS Global Accelerator masking, fresh domain, known-op match |
| `bggracefulwealth.com` | BG Wealth Sharing — recruitment layer | Hostinger, DNS parking, two-layer brand structure |
| `bgwealthalert.com` | BG Wealth Sharing — alert funnel | Recruitment funnel, scam naming pattern |
| `copypasteandconfirm.com` | DSJ — recruiter instruction domain | Social engineering infrastructure |
| `wxpass.net` | DSJ — sinkholed domain | Demonstrates post-takedown state |

---

## APIs Used

All free. No authentication required. No data leaves your machine.

| API | Purpose | Limit |
|-----|---------|-------|
| [crt.sh](https://crt.sh) | Certificate transparency logs | Generous, may be flaky |
| [certspotter.com](https://sslmate.com/certspotter/api/) | CT fallback | 100 req/hour unauthenticated |
| [freeipapi.com](https://freeipapi.com) | IP enrichment, ASN, hosting | Generous free tier |
| [dns.google](https://developers.google.com/speed/public-dns/docs/doh) | DNS-over-HTTPS | Unlimited |
| [rdap.org](https://rdap.org) | Domain registration (WHOIS replacement) | Generous |
| [urlscan.io](https://urlscan.io/docs/api/) | Historical domain scans | ~1000/day unauthenticated |

---

## Exports

Every mode exports:
- **JSON** — full structured report with all signals and raw data
- **IOC CSV** — domain/IP list, SIEM-ready with source and flag columns
- **HTML Report** — standalone dark-theme report, no external dependencies
- **Copy Findings** — plain text for Slack, email, or ticketing systems

All exports support **defang toggle** — IOCs neutralized with `[.]` and `[://]` per TLP conventions before sharing.

---

## Themes

Toggle between **dark terminal** (default) and **paper/light** mode using the ☀ button in the top right. Theme preference is saved in localStorage.

---

## Security Design

- **No active probing** — no exploit payloads, no port scans, no authenticated requests
- **All IOC data rendered as inert text** — `textContent` throughout, no `innerHTML` with external data
- **Input validation** — strict domain/IP regex before any data reaches the pipeline
- **Server-side APIs** — no CORS restrictions, no browser sandbox fighting you
- **Localhost only** — binds to `127.0.0.1`, never exposed to your network

---

## Project Structure

```
crucible-sigint/
├── crucible_app.py        # FastAPI backend — all API calls, scoring, SSE pipeline
├── templates/
│   └── index.html         # Full frontend — 5 modes, 2 themes, all exports
├── requirements.txt       # fastapi, uvicorn, httpx
├── LICENSE                # MIT
└── README.md
```

---

## Contributing

PRs welcome. The most valuable additions would be:

- **Shodan free-tier integration** — open port detection and historical IPs
- **STIX 2.1 export** — for LEA and ISAC sharing
- **Re-validation diff engine** — compare two runs, flag what changed (NXDOMAIN, clientHold, new domains)
- **Additional scam-kit signatures** — extend the known-operation fingerprint database
- **VirusTotal passive DNS** — surface pre-CDN IPs for Cloudflare-masked domains

---

## Acknowledgements

**Ryan McDonald** — for publishing his methodology openly. The investigative approach that became CRUCIBLE's foundation was entirely his work, freely shared with the security community.

**NEATLABS™** — built as part of the NEATLABS open intelligence tooling initiative. CRUCIBLE joins a portfolio of free practitioner-grade tools at [neatlabs.ai](https://neatlabs.ai).

---

## Author

**Randy Bator** | Security 360, LLC DBA NEATLABS™  
28+ years cybersecurity · USAF Veteran · IRS/DoD practitioner  
[rbator@neatlabs.ai](mailto:rbator@neatlabs.ai) · [neatlabs.ai](https://neatlabs.ai)  
[LinkedIn](https://linkedin.com/in/randy-b-84aa6731)

---

*CRUCIBLE SIGINT is for authorized security research, threat intelligence, fraud investigation, and brand protection. Use responsibly.*
