# Prototype: Domain Trust Scoring POC with Proxy/Anonymity and Whitelist Support
# ---------------------------------------------------------------------------
# DISCLAIMER:
#  - Performs WHOIS lookups, DNS variant generation, and SSL/TLS handshakes.
#  - Exposes IP unless routed through a proxy (e.g., Tor).
#  - For full anonymity, run in an isolated VM or container with Tor and disable DNS leaks.
# Requirements:
#   pip install python-whois tldextract idna dnstwist pysocks requests

import sys
import argparse
import whois
import idna
import ssl
import socket
import socks
import difflib
from datetime import datetime
import dnstwist
import tldextract
import requests
import asyncio
import aiohttp
import os
import math

# Configure anonymizing proxy (e.g., SOCKS5/Tor)
def configure_proxy(proxy_url=None):
    """Configure SOCKS or HTTP(S) proxy. Returns a requests-style proxy dict."""
    if not proxy_url:
        return {}
    scheme, rest = proxy_url.split('://', 1)
    host, port = rest.split(':', 1)
    port = int(port)
    proxies = {}
    if scheme.startswith('socks'):
        socks.setdefaultproxy(socks.SOCKS5, host, port)
        socks.wrapmodule(socket)
        proxies['http'] = proxy_url
        proxies['https'] = proxy_url
        print(f"[*] Proxy enabled: {proxy_url}")
    elif scheme in ("http", "https"):
        proxy = f"{scheme}://{host}:{port}"
        os.environ['HTTP_PROXY'] = proxy
        os.environ['HTTPS_PROXY'] = proxy
        proxies['http'] = proxy
        proxies['https'] = proxy
        print(f"[*] HTTP(S) proxy enabled: {proxy}")
    else:
        print(f"[!] Unsupported proxy scheme: {scheme}")
    return proxies

# Load whitelist of known benign domains
def load_whitelist(path):
    try:
        with open(path) as f:
            return [line.strip().lower() for line in f if line.strip()]
    except Exception as e:
        print(f"[!] Could not load whitelist: {e}")
        return []

# Load open-source threat feed (local file or URL)
async def load_threat_feed(source, proxies=None):
    if not source:
        return []
    if source.startswith('http'):
        try:
            async with aiohttp.ClientSession(trust_env=True) as session:
                async with session.get(source, proxy=proxies.get('http')) as resp:
                    text = await resp.text()
            return [line.strip().lower() for line in text.splitlines() if line.strip()]
        except Exception as e:
            print(f"[!] Could not fetch threat feed: {e}")
            return []
    else:
        try:
            return await asyncio.to_thread(
                lambda: [line.strip().lower() for line in open(source) if line.strip()]
            )
        except Exception as e:
            print(f"[!] Could not load threat feed: {e}")
            return []

# Check fuzzy similarity against whitelist
def is_whitelisted(domain, whitelist, threshold=0.9):
    for w in whitelist:
        if domain == w:
            return True
        if difflib.SequenceMatcher(None, domain, w).ratio() >= threshold:
            print(f"[*] Domain '{domain}' is similar to whitelist entry '{w}' (>= {threshold})")
            return True
    return False

# WHOIS info & domain age
async def get_domain_info(domain):
    def _inner():
        try:
            w = whois.whois(domain)
            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            age_days = (datetime.utcnow() - creation).days
            return {"creation_date": creation, "age_days": age_days}
        except Exception as e:
            return {"error": str(e)}

    return await asyncio.to_thread(_inner)

# Typo/homograph variants via dnstwist
async def detect_typosquats(domain):
    def _inner():
        try:
            fuzzer = dnstwist.Fuzzer(domain)
            fuzzer.generate()
            variants = fuzzer.permutations()
            return [v.get('domain-name') for v in variants[:5] if v.get('domain-name')]
        except Exception as e:
            return {"error": str(e)}

    return await asyncio.to_thread(_inner)

# SSL certificate details
async def get_ssl_cert_info(domain):
    def _inner():
        context = ssl.create_default_context()
        try:
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    subj = dict(x[0] for x in cert.get('subject', []))
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    return {"subject_CN": subj.get('commonName'), "issuer": issuer.get('organizationName')}
        except Exception as e:
            return {"error": str(e)}

    return await asyncio.to_thread(_inner)

# Simple machine learning style scoring using logistic function
def ml_score(info, ssl_info, typos):
    age = info.get('age_days') or 0 if isinstance(info, dict) else 0
    ssl_ok = 0 if isinstance(ssl_info, dict) and ssl_info.get('error') else 1
    typo_count = len(typos) if isinstance(typos, list) else 0
    x = 0.01 * age + 1.0 * ssl_ok - 0.5 * typo_count
    prob = 1 / (1 + math.exp(-x))
    return int(prob * 100)

# Combine signals into trust score
async def score_domain(domain, whitelist=None, threat_list=None):
    if whitelist and is_whitelisted(domain, whitelist):
        return {"domain": domain, "score": 100, "details": {"message": "Domain whitelisted; assumed benign."}}

    if threat_list and domain.lower() in threat_list:
        return {"domain": domain, "score": 0, "details": {"message": "Domain found in threat feed"}}

    info_task = asyncio.create_task(get_domain_info(domain))
    ssl_task = asyncio.create_task(get_ssl_cert_info(domain))
    typo_task = asyncio.create_task(detect_typosquats(domain))
    info, ssl_info, typos = await asyncio.gather(info_task, ssl_task, typo_task)

    score = 100
    # Penalize new domains
    if isinstance(info, dict) and "age_days" in info:
        days = info.get('age_days') or 0
        if days < 30:
            score -= 30
        elif days < 365:
            score -= 10
    # Penalize SSL lookup failures
    if isinstance(ssl_info, dict) and ssl_info.get('error'):
        score -= 20
    # Penalize typo variants
    if isinstance(typos, list) and typos:
        score -= min(len(typos) * 5, 25)
    ml = ml_score(info, ssl_info, typos)
    final_score = int((score + ml) / 2)
    return {"domain": domain, "score": max(final_score, 0), "details": {"domain_info": info, "ssl_info": ssl_info, "typo_variants": typos, "ml_score": ml}}

# Main CLI
async def main():
    parser = argparse.ArgumentParser(description='Domain Trust Scoring POC with whitelist support')
    parser.add_argument('domain', help='Domain to assess')
    parser.add_argument('--proxy', help='Proxy URL (socks5:// or http://)')
    parser.add_argument('--whitelist', help='Path to newline-delimited whitelist file')
    parser.add_argument('--threat-feed', help='URL or file path to threat feed list')
    parser.add_argument('--threshold', type=float, default=0.9, help='Fuzzy match threshold (0-1)')
    
    args = parser.parse_args()

    proxies = configure_proxy(args.proxy)
    whitelist = load_whitelist(args.whitelist) if args.whitelist else None
    threat_list = await load_threat_feed(args.threat_feed, proxies) if args.threat_feed else None

    try:
        encoded = idna.encode(args.domain).decode('ascii')
    except idna.IDNAError:
        encoded = args.domain
    
    ext = tldextract.extract(encoded)
    domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain

    result = await score_domain(domain, whitelist, threat_list)
    print(f"Trust Score for {domain}: {result['score']}")
    print("Details:")
    for k, v in result['details'].items():
        print(f"- {k}: {v}")


if __name__ == '__main__':
    asyncio.run(main())
