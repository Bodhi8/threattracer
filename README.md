# ThreatTracer 🔍

**Open-Source Threat Intelligence & IP Tracing Platform**

ThreatTracer is a comprehensive, modular platform for tracking threat actor infrastructure, enriching indicators of compromise (IOCs), and discovering related malicious infrastructure through advanced pivoting techniques.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

## Features

###  Multi-Source Enrichment
- **Passive DNS** - Historical domain-to-IP mappings
- **WHOIS Intelligence** - Registration details and patterns
- **ASN/BGP Analysis** - Network ownership and relationships
- **Threat Intelligence Feeds** - VirusTotal, AbuseIPDB, AlienVault OTX

###  Advanced Fingerprinting
- **JARM** - Active TLS server fingerprinting
- **Favicon Hashing** - MurmurHash3 favicon identification
- **Certificate Analysis** - X.509 field extraction and pivoting

###  Internet-Wide Scanning Integration
- **Shodan** - Query and pivot on device metadata
- **Censys** - Deep certificate and service analysis

###  Visualization & Analysis
- **Infrastructure Graphs** - Visualize relationships between IOCs
- **Cluster Detection** - Identify related infrastructure
- **Export Formats** - STIX 2.1, MISP, CSV, JSON

###  Multiple Interfaces
- **CLI** - Powerful command-line interface
- **REST API** - Full-featured API for integration
- **Web UI** - Intuitive dashboard for investigations

## Quick Start

### Installation
```bash
git clone https://github.com/yourusername/threattracer.git
cd threattracer
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -e .
cp config.example.yaml config.yaml
```

### Configuration

Edit `config.yaml` with your API keys:
```yaml
api_keys:
  shodan: "your-shodan-api-key"
  virustotal: "your-virustotal-key"
```

### Usage
```bash
# Enrich an IP
threattracer enrich ip 192.0.2.1 --modules asn,geoip,jarm

# Hunt for C2 servers
threattracer c2hunt cobalt-strike

# Start Web UI
threattracer web --port 8080

# Start API server
threattracer api --port 8000
```

## Docker
```bash
cp .env.example .env
# Add API keys to .env
docker-compose up -d
```

## API Reference
```bash
# Enrich
POST /api/v1/enrich
{"indicator": "192.0.2.1", "type": "ip", "modules": ["asn", "jarm"]}

# Hunt
POST /api/v1/hunt
{"seed": {"ip": "192.0.2.1"}, "pivots": ["jarm", "favicon"]}

# Search
POST /api/v1/search
{"platform": "shodan", "query": "http.favicon.hash:-1018312697"}
```

## License

MIT

## Disclaimer

This tool is intended for legitimate security research and defensive purposes only. Users are responsible for ensuring compliance with applicable laws and regulations.
