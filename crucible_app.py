"""
CRUCIBLE SIGINT v5.0
====================
Passive OSINT infrastructure fingerprinting engine.

METHODOLOGY CREDIT
------------------
The foundational analytical approach in CRUCIBLE is directly inspired by the
investigation published by Ryan McDonald (Principal Security Engineer, USMC 0341)
documenting his passive pivot of the DSJ Exchange / BG Wealth Sharing pig-butchering
operation — a $150M cryptocurrency fraud ultimately traced by FBI Operation Level Up.

Ryan's article: "Fingerprinting Malicious Infrastructure Using Free Resources"
Published: LinkedIn, May 2026

Ryan demonstrated — using only free passive sources (crt.sh, urlscan.io, DNS, WHOIS,
manual JS inspection) — how a single confirmed-bad domain can be used to map an entire
criminal infrastructure cluster. CRUCIBLE automates that methodology into a repeatable,
7-stage pipeline with weighted threat scoring.

All credit for the investigative framework belongs to Ryan McDonald.
CRUCIBLE is the automation layer built on top of his published work.

AUTHOR
------
Randy Bator | Security 360, LLC DBA NEATLABS™
rbator@neatlabs.ai | https://neatlabs.ai
LinkedIn: linkedin.com/in/randy-b-84aa6731

LICENSE
-------
MIT License — see LICENSE file

USAGE
-----
pip install fastapi uvicorn httpx
python crucible_app.py
Open: http://localhost:8000
"""

import asyncio
import json
import os
import re
import ipaddress
import pathlib
from datetime import datetime, timezone
from typing import Optional
from contextlib import asynccontextmanager
from collections import Counter

import httpx
from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse
import uvicorn

BASE_DIR = pathlib.Path(__file__).parent.resolve()
TEMPLATE = BASE_DIR / "templates" / "index.html"

# Module-level constant — ASN numbers known to belong to datacenter/hosting providers.
# Rebuilt here once rather than inside the hot path of fetch_ipinfo().
DATACENTER_ASNS: frozenset[int] = frozenset({
    # Major cloud / CDN
    15169, 16509, 14618, 13335, 8075, 20940, 16591, 54113,
    396982, 19527, 36459, 32934, 63949, 14061, 22822,
    # Chinese cloud providers
    4134, 4837, 9808, 4538,
    # VPS / shared hosting frequently used in scam ops
    47583,  # Hostinger
    24940,  # Hetzner
    16276,  # OVH
    51167,  # Contabo
    9009,   # M247
    20473,  # Vultr
})

client: Optional[httpx.AsyncClient] = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global client
    client = httpx.AsyncClient(
        timeout=httpx.Timeout(30.0, connect=10.0),
        follow_redirects=True,
        headers={"User-Agent": "CRUCIBLE-SIGINT/5.0 (OSINT Research Tool)"},
        limits=httpx.Limits(max_connections=30, max_keepalive_connections=15),
    )
    yield
    await client.aclose()

app = FastAPI(title="CRUCIBLE SIGINT", version="5.0", lifespan=lifespan)

# ════════════════════════════════════════════════════════════
# VALIDATION
# ════════════════════════════════════════════════════════════

DOMAIN_RE = re.compile(r'^([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$')

def validate_domain(raw: str) -> Optional[str]:
    s = re.sub(r'^https?://', '', raw.strip().lower())
    s = re.sub(r'/.*$', '', s)
    s = re.sub(r':\d+$', '', s)
    clean = s.lstrip('%.')
    if not clean or len(clean) > 253: return None
    return s if DOMAIN_RE.match(clean) else None

def validate_ip(raw: str) -> Optional[str]:
    try:
        ip = ipaddress.ip_address(raw.strip())
        if ip.is_private or ip.is_loopback or ip.is_reserved: return None
        return str(ip)
    except ValueError:
        return None

def validate_seed(raw: str):
    d = validate_domain(raw)
    if d: return d, 'domain'
    ip = validate_ip(raw)
    if ip: return ip, 'ip'
    return None, 'invalid'

# ════════════════════════════════════════════════════════════
# API FETCHERS
# ════════════════════════════════════════════════════════════

async def fetch_crtsh(domain: str) -> list[dict]:
    base = domain.lstrip('%.').lstrip('*.')
    for attempt in range(3):
        try:
            if attempt: await asyncio.sleep(attempt * 2)
            r = await client.get(f"https://crt.sh/?q=%.{base}&output=json", timeout=25.0)
            if r.status_code == 200:
                data = r.json()
                if data: return data
        except Exception:
            pass
    # certspotter fallback
    try:
        r = await client.get(
            f"https://api.certspotter.com/v1/issuances?domain={base}"
            f"&include_subdomains=true&expand=dns_names&limit=1000", timeout=20.0)
        if r.status_code == 200:
            data = r.json()
            if data:
                return [{"name_value": "\n".join(i.get("dns_names",[])),
                         "issuer_name": i.get("cert",{}).get("issuer","?"),
                         "not_before": i.get("not_before",""),
                         "_source": "certspotter"} for i in data]
    except Exception:
        pass
    raise RuntimeError("crt.sh and certspotter both unavailable")

async def fetch_dns(name: str, rtype: str = "A") -> dict:
    r = await client.get(f"https://dns.google/resolve?name={name}&type={rtype}",
                         headers={"Accept":"application/dns-json"}, timeout=8.0)
    r.raise_for_status()
    return r.json()

async def fetch_ipinfo(ip: str) -> dict:
    # freeipapi — no auth, no CORS issues server-side
    try:
        r = await client.get(f"https://freeipapi.com/api/json/{ip}", timeout=8.0)
        if r.status_code == 200:
            d = r.json()
            asn_num = d.get("asn")
            is_hosting = (
                d.get("ipType") in ("datacenter", "business", "education", "government")
                or (asn_num and int(asn_num) in DATACENTER_ASNS)
            )
            return {
                "query": ip, "country": d.get("countryName", "?"),
                "countryCode": d.get("countryCode", "?"),
                "regionName": d.get("regionName", "?"), "city": d.get("cityName", "?"),
                "isp": d.get("asnOrganization", "?"), "org": d.get("asnOrganization", "?"),
                "as": f"AS{asn_num}" if asn_num else "?",
                "asname": d.get("asnOrganization", "?"),
                "hosting": is_hosting, "proxy": d.get("isProxy", False),
                "mobile": d.get("ipType") == "mobile", "_source": "freeipapi",
            }
    except Exception:
        pass
    # ip-api.com fallback — HTTP is fine server-side, no CORS restriction
    try:
        r = await client.get(
            f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,"
            f"regionName,city,isp,org,as,asname,hosting,proxy,query,mobile", timeout=8.0)
        if r.status_code == 200:
            d = r.json()
            if d.get("status") == "success":
                d["_source"] = "ip-api"
                return d
    except Exception:
        pass
    raise RuntimeError(f"IP enrichment failed for {ip}")

async def fetch_rdap(domain: str) -> dict:
    for url in [f"https://rdap.org/domain/{domain}",
                f"https://rdap.verisign.com/com/v1/domain/{domain.upper()}"]:
        try:
            r = await client.get(url, headers={"Accept":"application/rdap+json"}, timeout=12.0)
            if r.status_code == 200: return r.json()
        except Exception:
            continue
    raise RuntimeError(f"RDAP unavailable for {domain}")

async def fetch_urlscan(domain: str) -> dict:
    """urlscan.io — free, no auth needed for search, ~1000 req/day unauthenticated."""
    try:
        r = await client.get(
            f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=20",
            headers={"Accept": "application/json"}, timeout=15.0)
        if r.status_code == 200:
            data = r.json()
            results = data.get("results", [])
            screenshots, ips_seen, asns = [], set(), set()
            for res in results:
                page = res.get("page", {})
                if page.get("ip"): ips_seen.add(page["ip"])
                if page.get("asn"): asns.add(page["asn"])
                if res.get("screenshot"): screenshots.append(res["screenshot"])
            return {
                "total": data.get("total", 0), "results": results[:10],
                "unique_ips": list(ips_seen), "unique_asns": list(asns),
                "screenshots": screenshots[:3],
            }
    except Exception:
        pass
    return {"total": 0, "results": [], "unique_ips": [], "unique_asns": [], "screenshots": []}

async def scan_js_for_wallet_drain(domain: str) -> dict:
    """Fetch the domain's HTML then any linked JS bundles, scan for wallet drain patterns."""
    findings = {"max_uint": False, "erc20": False, "trc20": False,
                "approve_calls": [], "suspicious_patterns": [], "bundles_checked": 0}
    try:
        r = await client.get(f"https://{domain}", timeout=10.0,
                             headers={"User-Agent":"Mozilla/5.0 (compatible; CRUCIBLE-SIGINT/5.0)"})
        if r.status_code not in (200, 206): return findings
        html = r.text[:100000]

        # Find JS bundle URLs
        js_urls = re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', html)
        chunk_urls = [u for u in js_urls if any(kw in u.lower() for kw in ("chunk","bundle","app","main"))]

        # Also check inline script
        inline = " ".join(re.findall(r'<script[^>]*>(.*?)</script>', html, re.DOTALL))
        all_js = inline

        for js_url in chunk_urls[:5]:
            try:
                if not js_url.startswith("http"):
                    js_url = f"https://{domain}/{js_url.lstrip('/')}"
                jr = await client.get(js_url, timeout=10.0)
                if jr.status_code == 200:
                    all_js += jr.text
                    findings["bundles_checked"] += 1
            except Exception:
                pass

        # Ryan's key pattern: MAX_UINT approve()
        if re.search(r'0xf{60,}', all_js, re.IGNORECASE):
            findings["max_uint"] = True
            findings["approve_calls"].append("MAX_UINT (0xfff...fff) detected in approve() call")
        if re.search(r'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', all_js, re.IGNORECASE):
            findings["max_uint"] = True
            findings["approve_calls"].append("MAX_UINT hex string detected")
        if "window.ethereum" in all_js: findings["erc20"] = True
        if "window.tronWeb" in all_js:  findings["trc20"] = True
        if re.search(r'approve\s*\(', all_js): findings["suspicious_patterns"].append("approve() call found")
        if re.search(r'transferFrom\s*\(', all_js): findings["suspicious_patterns"].append("transferFrom() call found")
        if re.search(r'\.mobileconfig', html): findings["suspicious_patterns"].append(".mobileconfig Web Clip detected (App Store bypass)")
        if re.search(r'CN=Android Debug', all_js): findings["suspicious_patterns"].append("Android debug cert signature detected (sideload-only APK)")

    except Exception:
        pass
    return findings

async def fetch_cert_timeline(domain: str, certs: list[dict]) -> list[dict]:
    """Build cert issuance timeline from crt.sh results."""
    timeline = []
    for c in certs:
        date_str = c.get("not_before","")
        if not date_str: continue
        try:
            dt = datetime.fromisoformat(date_str.replace("Z","+00:00"))
            names = [n.strip().lstrip("*.") for n in (c.get("name_value","")).split("\n") if n.strip()]
            timeline.append({
                "date": dt.strftime("%Y-%m-%d"),
                "month": dt.strftime("%Y-%m"),
                "issuer": (c.get("issuer_name","?").split("O=")[1].split(",")[0] if "O=" in c.get("issuer_name","") else "?"),
                "names": names[:3],
                "count": len(names),
            })
        except Exception:
            pass
    timeline.sort(key=lambda x: x["date"])
    return timeline

# ════════════════════════════════════════════════════════════
# DOMAIN EXTRACTION
# ════════════════════════════════════════════════════════════

def extract_domains_from_certs(certs: list[dict], seed: str) -> list[dict]:
    seen = {seed}
    domains = [{"name": seed, "source": "seed", "flag": None}]
    for c in certs:
        for name in (c.get("name_value") or "").split("\n"):
            n = name.strip().lower().lstrip("*.")
            if n and n not in seen and DOMAIN_RE.match(n):
                seen.add(n)
                flag = "NEIBU" if n.startswith("neibu") else None
                src = "certspotter" if c.get("_source") == "certspotter" else "cert"
                domains.append({"name": n, "source": src, "flag": flag})
    return domains

# ════════════════════════════════════════════════════════════
# THREAT SCORING — 12 signals, weighted additive model
# ════════════════════════════════════════════════════════════

def compute_threat_score(data: dict) -> dict:
    domains    = data.get("domains", [])
    ips        = data.get("ip_results", [])
    rdap       = data.get("rdap") or {}
    urlscan    = data.get("urlscan") or {}
    js_scan    = data.get("js_scan") or {}
    all_names  = " ".join(d["name"] for d in domains).lower()
    all_isps   = " ".join((ip.get("isp","")+" "+ip.get("org","")+" "+ip.get("as","")).lower() for ip in ips)

    signals = {}

    # S1 — Domain cluster volume
    n = len(domains)
    signals["domain_volume"] = (min(100, n*4) if n>=2 else 0, 2.0)

    # S2 — NEIBU 内部 admin portals
    has_neibu = any(d.get("flag")=="NEIBU" for d in domains) or "neibu" in all_names
    signals["neibu_admin_portal"] = (100 if has_neibu else 0, 3.0)

    # S3 — Scam-kit naming patterns
    scam_kws = ("dsj","ffs8","ge776","exofdsj","neibu","bgwealth","bggrace",
                "copypasteandconfirm","bgwealthalert","wxpass","ddjea","ddjeb",
                "dsjhout","exloading","exshare","fwqsw","coinbase-verify",
                "wallet-connect","metamask-update","eth-airdrop")
    scam_match = any(kw in all_names for kw in scam_kws)
    susp_tlds = sum(1 for d in domains if re.search(r'\.(cc|top|xyz|tk|pw|click|gq|cf|ga|icu)$', d["name"]))
    signals["scam_naming_pattern"] = (max(100 if scam_match else 0, min(100, susp_tlds*25)), 2.5)

    # S4 — Chinese cloud infra
    chinese_kws = ("alibaba","tencent","baidu","huawei","china telecom","chinanet","aliyun","tencentcloud")
    signals["chinese_cloud_infra"] = (90 if any(kw in all_isps for kw in chinese_kws) else 0, 2.0)

    # S5 — CDN/cloud origin masking
    masking_asns = {"as13335","as16509","as14618"}
    has_cf  = any("cloudflare" in ip.get("isp","").lower() for ip in ips)
    has_aws = any(ip.get("as","").lower() in masking_asns for ip in ips)
    signals["cdn_origin_masking"] = (80 if has_cf else 70 if has_aws else 0, 1.5)

    # S6 — Registrar risk
    entities = rdap.get("entities", [])
    registrar_name = ""
    for e in entities:
        if "registrar" in e.get("roles", []):
            for field in e.get("vcardArray",[[],([])])[1]:
                if field[0] == "fn": registrar_name = field[3]; break
    reg_lo = registrar_name.lower()
    reg_score = (90 if any(r in reg_lo for r in ("gname","nicenic","west.cn","bizcn","hichina"))
                 else 60 if any(r in reg_lo for r in ("hostinger","namesilo","namecheap","porkbun","dynadot"))
                 else 10 if registrar_name else 0)
    signals["registrar_risk"] = (reg_score, 1.5)

    # S7 — Domain freshness
    events = rdap.get("events", [])
    reg_date = next((e["eventDate"] for e in events if e.get("eventAction")=="registration"), None)
    age_score, age_days = 0, None
    if reg_date:
        try:
            age_days = (datetime.now(timezone.utc) - datetime.fromisoformat(reg_date.replace("Z","+00:00"))).days
            age_score = (100 if age_days<30 else 80 if age_days<90 else
                         60 if age_days<180 else 40 if age_days<365 else
                         15 if age_days<730 else 0)
        except Exception: pass
    signals["domain_freshness"] = (age_score, 1.5)

    # S8 — API failover triplet
    api_doms = [d["name"] for d in domains if d["name"].startswith("api.")]
    signals["api_failover_triplet"] = (85 if len(api_doms)>=2 else 0, 1.5)

    # S9 — Suspicious infra (parking, scam hosting ASNs, internal subdomains)
    nameservers = " ".join(ns.get("ldhName","").lower() for ns in rdap.get("nameservers",[]))
    has_parking = any(kw in nameservers for kw in ("parking","sedopark","bodis","above.com"))
    scam_asns = {"as47583","as24940","as16276","as51167","as9009","as20473","as39572","as62240"}
    has_scam_host = any(ip.get("as","").lower() in scam_asns for ip in ips)
    internal_pat = bool(re.search(r'(kyc|admin|panel|internal|backend|manage|operator|neibu)\.', all_names))
    signals["suspicious_infra"] = (max(80 if has_parking else 0, 70 if has_scam_host else 0, 80 if internal_pat else 0), 1.5)

    # S10 — urlscan.io corroboration
    us_total = urlscan.get("total", 0)
    us_score = (80 if us_total >= 10 else 50 if us_total >= 3 else 20 if us_total >= 1 else 0)
    signals["urlscan_presence"] = (us_score, 1.0)

    # S11 — JS wallet drain (Ryan's MAX_UINT pattern)
    js_score = 0
    if js_scan.get("max_uint"): js_score = 100
    elif js_scan.get("erc20") or js_scan.get("trc20"): js_score = 70
    elif js_scan.get("suspicious_patterns"): js_score = 40
    signals["js_wallet_drain"] = (js_score, 3.0)  # highest weight — direct evidence

    # S12 — Known operation fingerprint
    known_kws = ("dsj","dsjexchange","bgwealth","bggrace","copypasteandconfirm",
                 "exofdsj","neibu168","neibud123","ddjea","ddjeb","dsjhout","bgwealthalert")
    signals["known_operation_match"] = (100 if any(kw in all_names for kw in known_kws) else 0, 3.0)

    # Determine which signals have backing data — skip those we couldn't evaluate
    has_ct   = len(domains) > 1           # CT returned more than just the seed
    has_rdap = bool(rdap)                 # RDAP query succeeded
    has_ip   = bool(ips)                  # at least one IP resolved
    # urlscan always runs and always returns a result dict (total may be 0)
    has_js   = (js_scan.get("bundles_checked", 0) > 0
                or js_scan.get("max_uint") is not None)

    skip = set()
    if not has_ct:   skip.update({"domain_volume","neibu_admin_portal","scam_naming_pattern",
                                   "api_failover_triplet","suspicious_infra"})
    if not has_rdap: skip.update({"registrar_risk","domain_freshness"})
    if not has_ip:   skip.update({"chinese_cloud_infra","cdn_origin_masking"})
    if not has_js:   skip.add("js_wallet_drain")

    total_weight = weighted_sum = 0.0
    for name, (score, weight) in signals.items():
        if name in skip: continue
        weighted_sum += score * weight
        total_weight += weight * 100

    composite = min(100, round((weighted_sum/total_weight)*100)) if total_weight > 0 else 0

    # Escalation floors
    is_known = signals["known_operation_match"][0] > 0
    if is_known:   composite = max(composite, 70)
    if has_neibu and sum(1 for s,(v,_) in signals.items() if v>0) >= 2:
        composite = max(composite, 80)
    if signals["js_wallet_drain"][0] == 100:
        composite = max(composite, 90)  # confirmed wallet drain = critical

    # Confidence: based on independent data sources that contributed
    # urlscan always runs so we count it if it returned any results
    has_us_data = urlscan.get("total", 0) > 0
    sources_available = sum([has_ct, has_rdap, has_ip, has_us_data, has_js])
    confidence = ("HIGH" if sources_available >= 4 else "MEDIUM" if sources_available >= 2 else "LOW")

    factors = {name: score for name,(score,_) in signals.items()}
    return {
        "factors": factors, "composite": composite,
        "registrar": registrar_name, "age_days": age_days,
        "confidence": confidence, "sources_available": sources_available,
        "signals_fired": [n for n,(s,_) in signals.items() if s>0],
        "js_scan": js_scan, "urlscan_hits": us_total,
    }

def parse_rdap_summary(rdap: dict) -> dict:
    events = {e["eventAction"]: e["eventDate"] for e in rdap.get("events",[])}
    registrar = "?"
    for e in rdap.get("entities",[]):
        if "registrar" in e.get("roles",[]):
            for field in e.get("vcardArray",[[],([])])[1]:
                if field[0]=="fn": registrar=field[3]; break
    nameservers = [ns.get("ldhName","") for ns in rdap.get("nameservers",[])]
    return {"handle":rdap.get("handle","?"),"registrar":registrar,
            "status":", ".join(rdap.get("status",[])),"created":events.get("registration","?"),
            "updated":events.get("last changed","?"),"expires":events.get("expiration","?"),
            "nameservers":", ".join(nameservers)}

# ════════════════════════════════════════════════════════════
# SSE PIPELINE
# ════════════════════════════════════════════════════════════

def sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"

async def run_standard_pipeline(seed: str):
    result = {"seed":seed,"domains":[],"dns":{},"ip_results":[],"rdap":None,
              "urlscan":{},"js_scan":{},"cert_timeline":[]}

    yield sse("log",{"msg":f"Pipeline v5.0 initiated for: {seed}","type":"info","stage":"INIT"})
    yield sse("log",{"msg":"12-signal weighted scoring · urlscan · JS scan · cert timeline","type":"info","stage":"INIT"})

    # ── S1: Cert Transparency ──
    yield sse("stage",{"n":1,"state":"active"})
    yield sse("log",{"msg":f"S1: crt.sh wildcard query for %.{seed}","type":"live","stage":"S1"})
    certs = []
    try:
        certs = await fetch_crtsh(seed)
        src = "certspotter" if (certs and certs[0].get("_source")=="certspotter") else "crt.sh"
        result["domains"] = extract_domains_from_certs(certs, seed)
        yield sse("log",{"msg":f"S1: {len(certs)} certs via {src} → {len(result['domains'])} domains","type":"ok","stage":"S1"})
        neibu = [d for d in result["domains"] if d.get("flag")=="NEIBU"]
        if neibu: yield sse("log",{"msg":f"S1: {len(neibu)} NEIBU (内部) admin portals flagged — Chinese admin panel tell","type":"err","stage":"S1"})
        yield sse("domains",{"domains":result["domains"],"source":src})
        yield sse("chip",{"id":"crtsh","state":"live" if src=="crt.sh" else "pend"})
        yield sse("chip",{"id":"certspotter","state":"live"})
        # Build cert timeline
        result["cert_timeline"] = await fetch_cert_timeline(seed, certs)
        if result["cert_timeline"]:
            months = Counter(c["month"] for c in result["cert_timeline"])
            peak = max(months, key=months.get)
            yield sse("certTimeline",{"timeline":result["cert_timeline"],"months":dict(months),"peak_month":peak,"peak_count":months[peak]})
            yield sse("log",{"msg":f"S1: Cert timeline built — {len(result['cert_timeline'])} issuances, peak: {peak} ({months[peak]} certs)","type":"ok","stage":"S1"})
    except Exception as e:
        yield sse("log",{"msg":f"S1: CT unavailable — {e}","type":"warn","stage":"S1"})
        yield sse("chip",{"id":"crtsh","state":"fail"})
        yield sse("chip",{"id":"certspotter","state":"fail"})
        result["domains"] = DEMO_DOMAINS[:]
        yield sse("domains",{"domains":result["domains"],"source":"demo"})
        yield sse("corsNote",{"msg":"CT sources unavailable. Demo data shown. Retry in a few minutes."})
    yield sse("stage",{"n":1,"state":"done"})

    # ── S2: DNS ──
    yield sse("stage",{"n":2,"state":"active"})
    dns_records = []
    for rtype in ["A","AAAA","MX","NS","TXT","CNAME","SOA"]:
        try:
            res = await fetch_dns(seed, rtype)
            if res.get("Answer"):
                result["dns"][rtype] = res["Answer"]
                for a in res["Answer"]:
                    dns_records.append({"type":rtype,"value":a["data"],"ttl":a["TTL"]})
                    yield sse("dnsRecord",{"type":rtype,"value":a["data"],"ttl":a["TTL"]})
        except Exception:
            pass
    yield sse("chip",{"id":"dns","state":"live"})
    yield sse("log",{"msg":f"S2: {len(dns_records)} DNS records resolved","type":"ok","stage":"S2"})
    ips = [a["data"] for a in result["dns"].get("A",[]) if validate_ip(a["data"])]
    if ips: yield sse("log",{"msg":f"S2: A records: {', '.join(ips)}","type":"ok","stage":"S2"})
    else:   yield sse("log",{"msg":"S2: No A records — behind CDN or domain parked","type":"warn","stage":"S2"})
    yield sse("stage",{"n":2,"state":"done"})

    # ── S3: IP Intel ──
    yield sse("stage",{"n":3,"state":"active"})
    for ip in ips[:5]:
        try:
            await asyncio.sleep(0.3)
            info = await fetch_ipinfo(ip)
            result["ip_results"].append(info)
            yield sse("ipInfo",{"ip":ip,"info":info})
            yield sse("log",{"msg":f"S3: {ip} → {info.get('isp','?')} | {info.get('as','?')} | {info.get('country','?')}","type":"ok","stage":"S3"})
            isp = info.get("isp","").lower()
            if any(kw in isp for kw in ("alibaba","tencent","chinanet")):
                yield sse("log",{"msg":f"S3: Chinese cloud provider detected — {info['isp']}","type":"err","stage":"S3"})
            elif "cloudflare" in isp:
                yield sse("log",{"msg":"S3: Cloudflare masking — true origin IP hidden","type":"warn","stage":"S3"})
            elif info.get("hosting"):
                yield sse("log",{"msg":f"S3: Datacenter/hosting IP ({info.get('as','?')})","type":"warn","stage":"S3"})
        except Exception as e:
            yield sse("log",{"msg":f"S3: {ip} enrichment failed — {e}","type":"warn","stage":"S3"})
    yield sse("chip",{"id":"ipapi","state":"live" if result["ip_results"] else "fail"})
    yield sse("stage",{"n":3,"state":"done"})

    # ── S4: RDAP ──
    yield sse("stage",{"n":4,"state":"active"})
    try:
        rdap = await fetch_rdap(seed)
        result["rdap"] = rdap
        summary = parse_rdap_summary(rdap)
        yield sse("rdap",{"summary":summary})
        yield sse("chip",{"id":"rdap","state":"live"})
        created_short = summary["created"][:10] if summary["created"]!="?" else "?"
        yield sse("log",{"msg":f"S4: {summary['registrar']} | Created: {created_short} | {summary['status']}","type":"ok","stage":"S4"})
        scam_primary = ("gname","nicenic","west.cn","bizcn","hichina")
        if any(r in summary["registrar"].lower() for r in scam_primary):
            yield sse("log",{"msg":f"S4: REGISTRAR FLAGGED: {summary['registrar']} — primary scam-kit registrar","type":"err","stage":"S4"})
        if created_short != "?":
            try:
                age = (datetime.now(timezone.utc)-datetime.fromisoformat(summary["created"].replace("Z","+00:00"))).days
                if age < 90: yield sse("log",{"msg":f"S4: FRESH DOMAIN — {age} days old. High risk.","type":"err","stage":"S4"})
            except Exception: pass
    except Exception as e:
        yield sse("chip",{"id":"rdap","state":"fail"})
        yield sse("log",{"msg":f"S4: RDAP unavailable — {e}","type":"warn","stage":"S4"})
    yield sse("stage",{"n":4,"state":"done"})

    # ── S5: urlscan.io ──
    yield sse("stage",{"n":5,"state":"active"})
    yield sse("log",{"msg":f"S5: urlscan.io corroboration — scanning for {seed}","type":"live","stage":"S5"})
    result["urlscan"] = await fetch_urlscan(seed)
    us = result["urlscan"]
    if us.get("total",0) > 0:
        yield sse("log",{"msg":f"S5: urlscan found {us['total']} scans · {len(us['unique_ips'])} unique IPs · {len(us.get('unique_asns',[]))} ASNs","type":"ok","stage":"S5"})
        yield sse("urlscan",{"data":us})
        yield sse("chip",{"id":"urlscan","state":"live"})
    else:
        yield sse("log",{"msg":"S5: No urlscan.io history — domain may be new or not yet scanned","type":"info","stage":"S5"})
        yield sse("chip",{"id":"urlscan","state":"pend"})
    yield sse("stage",{"n":5,"state":"done"})

    # ── S6: JS Wallet Drain Scan ──
    yield sse("stage",{"n":6,"state":"active"})
    yield sse("log",{"msg":f"S6: JS bundle scan for wallet drain patterns (Ryan McDonald methodology)","type":"live","stage":"S6"})
    result["js_scan"] = await scan_js_for_wallet_drain(seed)
    js = result["js_scan"]
    yield sse("jsScan",{"data":js})
    if js.get("max_uint"):
        yield sse("log",{"msg":"S6: !! MAX_UINT APPROVE DETECTED — approve(0xffff...ffff) in deposit flow","type":"err","stage":"S6"})
        yield sse("log",{"msg":"S6: Persistent wallet drain — operator can drain all USDT at any time","type":"err","stage":"S6"})
        yield sse("walletAlert",{"show":True})
    elif js.get("erc20") or js.get("trc20"):
        yield sse("log",{"msg":"S6: Crypto wallet interfaces detected (window.ethereum / window.tronWeb)","type":"warn","stage":"S6"})
    elif js.get("bundles_checked",0)>0:
        yield sse("log",{"msg":f"S6: {js['bundles_checked']} bundles scanned — no MAX_UINT pattern found","type":"ok","stage":"S6"})
    else:
        yield sse("log",{"msg":"S6: JS scan inconclusive — domain may use Cloudflare bot protection or be offline","type":"info","stage":"S6"})
    for pat in js.get("suspicious_patterns",[]):
        yield sse("log",{"msg":f"S6: Pattern → {pat}","type":"warn","stage":"S6"})
    yield sse("stage",{"n":6,"state":"done"})

    # ── S7: Threat Score ──
    yield sse("stage",{"n":7,"state":"active"})
    yield sse("log",{"msg":"S7: Computing composite threat score — 12 weighted signals","type":"info","stage":"S7"})
    score_data = compute_threat_score(result)
    result["score"] = score_data
    for sig in score_data.get("signals_fired",[]):
        v = score_data["factors"].get(sig,0)
        yield sse("log",{"msg":f"S7: ↑ {sig.replace('_',' ').upper()} [{v}/100]",
                         "type":"err" if v>=90 else "warn","stage":"S7"})
    yield sse("score",score_data)
    composite = score_data["composite"]
    level = "err" if composite>=75 else "warn" if composite>=45 else "ok"
    yield sse("log",{"msg":f"S7: Score {composite}/100 — Confidence: {score_data['confidence']} — {len(score_data.get('signals_fired',[]))} signals fired","type":level,"stage":"S7"})

    # DSJ wallet drain
    all_names = " ".join(d["name"] for d in result["domains"])
    if re.search(r'dsj|dsjexchange|bgwealth|copypasteandconfirm|exofdsj|neibu168|ddjea',all_names):
        yield sse("walletAlert",{"show":True})
        yield sse("log",{"msg":"INTEL: DSJ Exchange / BG Wealth Sharing — confirmed $150M pig-butchering operation","type":"err","stage":"INTEL"})
        yield sse("log",{"msg":"INTEL: FBI Operation Level Up, Scam Center Strike Force — $41M frozen","type":"err","stage":"INTEL"})

    yield sse("stage",{"n":7,"state":"done"})
    yield sse("complete",{"result":result})
    yield sse("log",{"msg":f"Pipeline complete — {len(result['domains'])} domains · score {composite}/100 · confidence {score_data['confidence']}","type":"ok","stage":"DONE"})

# ════════════════════════════════════════════════════════════
# DEMO SEEDS
# ════════════════════════════════════════════════════════════

DEMO_DOMAINS = [
    {"name":"exofdsj09.net","source":"seed","flag":None},
    {"name":"dsj0026.cc","source":"cert","flag":None},
    {"name":"dsj200.com","source":"cert","flag":None},
    {"name":"dsj321.com","source":"cert","flag":None},
    {"name":"dsjexchange.com","source":"cert","flag":None},
    {"name":"neibu168x.cc","source":"cert","flag":"NEIBU"},
    {"name":"neibud123x.cc","source":"cert","flag":"NEIBU"},
    {"name":"api.ddjea.com","source":"cert","flag":None},
    {"name":"api.ddjeb.com","source":"cert","flag":None},
    {"name":"bggracefulwealth.com","source":"cert","flag":None},
    {"name":"bgwealthalert.com","source":"cert","flag":None},
    {"name":"copypasteandconfirm.com","source":"cert","flag":None},
    {"name":"wxpass.net","source":"cert","flag":None},
]

# ════════════════════════════════════════════════════════════
# API ROUTES
# ════════════════════════════════════════════════════════════

@app.get("/api/pipeline/standard")
async def pipeline_standard(seed: str = Query(...)):
    validated, kind = validate_seed(seed)
    if not validated or kind != "domain":
        return JSONResponse({"error":"Invalid domain"},status_code=400)
    return StreamingResponse(run_standard_pipeline(validated),
        media_type="text/event-stream",
        headers={"Cache-Control":"no-cache","X-Accel-Buffering":"no","Connection":"keep-alive"})

@app.get("/api/dns")
async def api_dns(domain: str = Query(...), types: str = Query("A,AAAA,MX,NS,TXT,CNAME,SOA,CAA")):
    validated, kind = validate_seed(domain)
    if not validated or kind!="domain": return JSONResponse({"error":"Invalid domain"},status_code=400)
    results = {}
    for rtype in types.split(","):
        try:
            res = await fetch_dns(validated, rtype.strip().upper())
            if res.get("Answer"): results[rtype.strip().upper()] = res["Answer"]
        except Exception: pass
    return JSONResponse(results)

@app.get("/api/ip/{ip}")
async def api_ip(ip: str):
    validated = validate_ip(ip)
    if not validated: return JSONResponse({"error":"Invalid or private IP"},status_code=400)
    try: return JSONResponse(await fetch_ipinfo(validated))
    except Exception as e: return JSONResponse({"error":str(e)},status_code=502)

@app.get("/api/rdap/{domain}")
async def api_rdap(domain: str):
    validated, kind = validate_seed(domain)
    if not validated or kind!="domain": return JSONResponse({"error":"Invalid domain"},status_code=400)
    try: return JSONResponse(await fetch_rdap(validated))
    except Exception as e: return JSONResponse({"error":str(e)},status_code=502)

@app.get("/api/certs/{domain:path}")
async def api_certs(domain: str):
    raw = domain.lstrip("%.").lstrip("*.")
    validated = validate_domain(raw)
    if not validated: return JSONResponse({"error":"Invalid domain"},status_code=400)
    try:
        certs = await fetch_crtsh(validated)
        return JSONResponse({"count":len(certs),"certs":certs[:200]})
    except Exception as e: return JSONResponse({"error":str(e)},status_code=502)

@app.get("/api/urlscan/{domain}")
async def api_urlscan(domain: str):
    validated, kind = validate_seed(domain)
    if not validated or kind!="domain": return JSONResponse({"error":"Invalid domain"},status_code=400)
    return JSONResponse(await fetch_urlscan(validated))

@app.get("/api/jsscan/{domain}")
async def api_jsscan(domain: str):
    validated, kind = validate_seed(domain)
    if not validated or kind!="domain": return JSONResponse({"error":"Invalid domain"},status_code=400)
    return JSONResponse(await scan_js_for_wallet_drain(validated))

@app.get("/api/bulk")
async def api_bulk(iocs: str = Query(...)):
    raw_list = [i.strip() for i in iocs.split(",") if i.strip()][:50]
    results = []
    for raw in raw_list:
        validated, kind = validate_seed(raw)
        if not validated: continue
        r = {"ioc":validated,"type":kind,"resolves":False,"isp":"?","asn":"?","country":"?","created":"?","status":"?"}
        try:
            if kind=="domain":
                dns = await fetch_dns(validated,"A")
                ips_found = [a["data"] for a in (dns.get("Answer") or []) if validate_ip(a["data"])]
                r["resolves"] = bool(ips_found)
                if ips_found:
                    await asyncio.sleep(0.3)
                    info = await fetch_ipinfo(ips_found[0])
                    r.update({"isp":info.get("isp","?"),"asn":info.get("as","?"),"country":info.get("countryCode","?")})
                try:
                    rdap = await fetch_rdap(validated)
                    s = parse_rdap_summary(rdap)
                    r["created"] = s["created"][:10] if s["created"]!="?" else "?"
                    r["status"] = s["status"][:30]
                except Exception: pass
            else:
                info = await fetch_ipinfo(validated)
                r.update({"resolves":True,"isp":info.get("isp","?"),"asn":info.get("as","?"),"country":info.get("countryCode","?")})
        except Exception as e: r["error"]=str(e)
        results.append(r)
        await asyncio.sleep(0.2)
    return JSONResponse({"results":results})

@app.get("/api/phishing")
async def api_phishing(brand: str = Query(...)):
    validated = validate_domain(brand)
    if not validated: return JSONResponse({"error":"Invalid domain"},status_code=400)
    base = validated.split(".")[0]
    certs = []
    try:
        r = await client.get(f"https://crt.sh/?q=%25{base}%25&output=json",timeout=25.0)
        if r.status_code==200: certs = r.json() or []
    except Exception: pass
    if not certs:
        try:
            r = await client.get(f"https://api.certspotter.com/v1/issuances?domain={validated}&include_subdomains=true&expand=dns_names&limit=1000",timeout=20.0)
            if r.status_code==200:
                certs = [{"name_value":"\n".join(i.get("dns_names",[])),"issuer_name":i.get("cert",{}).get("issuer","?"),"not_before":i.get("not_before","")} for i in (r.json() or [])]
        except Exception as e: return JSONResponse({"error":str(e)},status_code=502)
    seen,lookalikes = set(),[]
    for c in certs:
        for name in (c.get("name_value") or "").split("\n"):
            n = name.strip().lower().lstrip("*.")
            if n and n not in seen and DOMAIN_RE.match(n) and n!=validated and base in n:
                seen.add(n)
                score = sum([40 if base in n.split(".")[0] else 0,
                             20 if any(f"-{base}" in n or f"{base}-" in n for _ in [1]) else 0,
                             sum(12 for kw in ("login","secure","verify","update","support","wallet","crypto","exchange") if kw in n),
                             10 if re.search(r'\.(cc|top|xyz|tk|pw|click|gq|cf)$',n) else 0])
                lookalikes.append({"name":n,"score":min(100,score),"issuer":c.get("issuer_name","?"),"not_before":c.get("not_before","")})
    lookalikes.sort(key=lambda x:x["score"],reverse=True)
    return JSONResponse({"brand":validated,"count":len(lookalikes),"lookalikes":lookalikes[:100]})

@app.get("/health")
async def health():
    return {"status":"ok","tool":"CRUCIBLE SIGINT","version":"5.0"}

@app.get("/", response_class=HTMLResponse)
async def root():
    try: return TEMPLATE.read_text(encoding="utf-8")
    except FileNotFoundError:
        return HTMLResponse(f"<pre>ERROR: templates/index.html not found\nExpected: {TEMPLATE}</pre>",status_code=500)

if __name__ == "__main__":
    import sys, socket
    try:
        if sys.stdout.encoding and sys.stdout.encoding.lower()!="utf-8":
            sys.stdout.reconfigure(encoding="utf-8",errors="replace")
    except Exception: pass

    preferred = int(os.environ.get("PORT",8000))
    chosen = None
    for p in [preferred,8080,8888,9000,9090]:
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            try: s.bind(("127.0.0.1",p)); chosen=p; break
            except OSError: print(f"  Port {p} in use, trying next...")

    if not chosen: print("  ERROR: No free port found."); sys.exit(1)
    print(f"\n  CRUCIBLE SIGINT v5.0")
    print(f"  http://localhost:{chosen}")
    print(f"  Template: {TEMPLATE}")
    print(f"  Ctrl+C to stop\n")
    uvicorn.run("crucible_app:app",host="127.0.0.1",port=chosen,reload=False,log_level="info")
