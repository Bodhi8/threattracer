# ThreatTracer

Open-source threat intelligence & IP tracing platform for tracking threat actor infrastructure.

## Features

- **Enrichment** — ASN, GeoIP, WHOIS, VirusTotal
- **Fingerprinting** — JARM (TLS), Favicon hashing, Certificates
- **Hunting** — Shodan integration, C2 detection
- **Known Signatures** — Cobalt Strike, Metasploit, Mythic, Sliver, and more

## Install
```bash
pip install -e .
cp config.example.yaml config.yaml
# Add your API keys to config.yaml
```

## Usage
```bash
# Enrich an IP
threattracer enrich ip 192.0.2.1 --modules asn,geoip,jarm

# Hunt C2 infrastructure
threattracer c2hunt cobalt-strike

# Run web UI
threattracer web --port 8080

# Run REST API
threattracer api --port 8000
```

## API Keys

| Service | Required | Get Key |
|---------|----------|---------|
| Shodan | Yes (for hunting) | https://account.shodan.io |
| VirusTotal | Optional | https://virustotal.com/gui/my-apikey |

## License

MIT
