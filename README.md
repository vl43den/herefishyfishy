# HereFishyFishy 

A Python-based domain trust scoring proof-of-concept (POC) designed to assess the trustworthiness of domains through multiple security indicators. This tool combines domain age analysis, SSL certificate validation, typosquatting detection, and whitelist support to provide a comprehensive trust score.

## Features

- **Domain Age Analysis**: Evaluates domain registration age via WHOIS lookups
- **SSL Certificate Validation**: Checks SSL/TLS certificate details and validity
- **Typosquatting Detection**: Uses dnstwist to identify potential phishing variants
- **Whitelist Support**: Fuzzy matching against known benign domains
- **Proxy Support**: SOCKS5 proxy integration for anonymized analysis
- **Trust Scoring**: Combines multiple signals into a numerical trust score (0-100)

## Security Considerations

**DISCLAIMER**: This tool performs WHOIS lookups, DNS variant generation, and SSL/TLS handshakes that may expose your IP address unless routed through a proxy. For full anonymity, run in an isolated VM or container with Tor and ensure DNS leak protection.

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd herefishyfishy
```

2. Create a virtual environment (recommended):
```bash
python -m venv .venv
```

3. Activate the virtual environment:
- **Windows**: `.venv\Scripts\activate`
- **macOS/Linux**: `source .venv/bin/activate`

4. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage
```bash
python prototype.py <domain>
```

### With Proxy (Tor)
```bash
python prototype.py <domain> --proxy socks5h://127.0.0.1:9050
```

### With Whitelist
```bash
python prototype.py <domain> --whitelist whitelist.txt
```

### All Options
```bash
python prototype.py <domain> --proxy socks5h://127.0.0.1:9050 --whitelist whitelist.txt --threshold 0.85
```

## Command Line Options

- `domain`: Domain to assess (required)
- `--proxy`: SOCKS5 proxy URL (e.g., `socks5h://127.0.0.1:9050` for Tor)
- `--whitelist`: Path to newline-delimited whitelist file
- `--threshold`: Fuzzy match threshold for whitelist (0-1, default: 0.9)

## Examples

### Analyze a trusted domain:
```bash
python prototype.py google.com
```
Output:
```
Trust Score for google.com: 100
Details:
- domain_info: {'creation_date': datetime.datetime(1997, 9, 15, 4, 0), 'age_days': 10155}
- ssl_info: {'subject_CN': '*.google.com', 'issuer': 'Google Trust Services'}
- typo_variants: []
```

### Analyze through Tor proxy:
```bash
python prototype.py suspicious-domain.com --proxy socks5h://127.0.0.1:9050
```

### Use with whitelist:
```bash
echo -e "google.com\nfacebook.com\ntwitter.com" > whitelist.txt
python prototype.py google.com --whitelist whitelist.txt
```

## Trust Scoring Algorithm

The trust score starts at 100 and applies penalties based on:

- **New Domains**: -30 points if < 30 days old, -10 points if < 365 days old
- **SSL Issues**: -20 points for SSL certificate problems
- **Typosquatting**: -5 points per variant found (max -25 points)
- **Whitelist**: Domains matching whitelist entries receive a score of 100

## Whitelist Format

Create a text file with one domain per line:
```
google.com
facebook.com
github.com
microsoft.com
```

## Dependencies

- `python-whois`: WHOIS lookups
- `tldextract`: Domain parsing
- `idna`: Internationalized domain name support
- `dnstwist`: Typosquatting detection
- `pysocks`: SOCKS proxy support
- `requests`: HTTP requests

## Privacy & Anonymity

For enhanced privacy when analyzing suspicious domains:

1. **Use Tor**: Install Tor Browser and use `--proxy socks5h://127.0.0.1:9050`
2. **VM/Container**: Run in an isolated environment
3. **DNS Protection**: Ensure DNS queries are routed through your proxy
4. **VPN**: Consider additional VPN protection

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is provided as-is for educational and research purposes. Use responsibly and in accordance with applicable laws.

## Acknowledgments

- [dnstwist](https://github.com/elceef/dnstwist) for typosquatting detection
- [python-whois](https://pypi.org/project/python-whois/) for WHOIS functionality
- [tldextract](https://pypi.org/project/tldextract/) for domain parsing
