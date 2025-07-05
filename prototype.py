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

# Configure anonymizing proxy (e.g., SOCKS5/Tor)
def configure_proxy(proxy_url=None):
    if not proxy_url:
        return
    scheme, rest = proxy_url.split('://', 1)
    host, port = rest.split(':', 1)
    port = int(port)
    if scheme.startswith('socks'):
        socks.setdefaultproxy(socks.SOCKS5, host, port)
        socks.wrapmodule(socket)
        print(f"[*] Proxy enabled: {proxy_url}")
    else:
        print(f"[!] Unsupported proxy scheme: {scheme}")

# Load whitelist of known benign domains
def load_whitelist(path):
    try:
        with open(path) as f:
            return [line.strip().lower() for line in f if line.strip()]
    except Exception as e:
        print(f"[!] Could not load whitelist: {e}")
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
def get_domain_info(domain):
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        age_days = (datetime.utcnow() - creation).days
        return {"creation_date": creation, "age_days": age_days}
    except Exception as e:
        return {"error": str(e)}

# Typo/homograph variants via dnstwist
def detect_typosquats(domain):
    try:
        fuzzer = dnstwist.Fuzzer(domain)
        fuzzer.generate()
        variants = fuzzer.permutations()
        return [v.get('domain-name') for v in variants[:5] if v.get('domain-name')]
    except Exception as e:
        return {"error": str(e)}

# SSL certificate details
def get_ssl_cert_info(domain):
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

# Combine signals into trust score
def score_domain(domain, whitelist=None):
    if whitelist and is_whitelisted(domain, whitelist):
        return {"domain": domain, "score": 100, "details": {"message": "Domain whitelisted; assumed benign."}}

    info = get_domain_info(domain)
    ssl_info = get_ssl_cert_info(domain)
    typos = detect_typosquats(domain)
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
    return {"domain": domain, "score": max(score, 0), "details": {"domain_info": info, "ssl_info": ssl_info, "typo_variants": typos}}

# Main CLI
def main():
    parser = argparse.ArgumentParser(description='Domain Trust Scoring POC with whitelist support')
    parser.add_argument('domain', help='Domain to assess')
    parser.add_argument('--proxy', help='SOCKS5 proxy URL (e.g., socks5h://127.0.0.1:9050)')
    parser.add_argument('--whitelist', help='Path to newline-delimited whitelist file')
    parser.add_argument('--threshold', type=float, default=0.9, help='Fuzzy match threshold (0-1)')
    
    args = parser.parse_args()

    configure_proxy(args.proxy)
    whitelist = load_whitelist(args.whitelist) if args.whitelist else None

    try:
        encoded = idna.encode(args.domain).decode('ascii')
    except idna.IDNAError:
        encoded = args.domain
    
    ext = tldextract.extract(encoded)
    domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain

    result = score_domain(domain, whitelist)
    print(f"Trust Score for {domain}: {result['score']}")
    print("Details:")
    for k, v in result['details'].items():
        print(f"- {k}: {v}")


if __name__ == '__main__':
    main()
