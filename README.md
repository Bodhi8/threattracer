# ThreatTracer 🔍

**Open-Source Threat Intelligence & IP Tracing Platform**

ThreatTracer is a comprehensive, modular platform for tracking threat actor infrastructure, enriching indicators of compromise (IOCs), and discovering related malicious infrastructure through advanced pivoting techniques.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

## Features

### 🔎 Multi-Source Enrichment
- **Passive DNS** - Historical domain-to-IP mappings
- **WHOIS Intelligence** - Registration details and patterns
- **ASN/BGP Analysis** - Network ownership and relationships
- **Threat Intelligence Feeds** - VirusTotal, AbuseIPDB, AlienVault OTX

### 🔐 Advanced Fingerprinting
- **JARM** - Active TLS server fingerprinting
- **Favicon Hashing** - MurmurHash3 favicon identification
- **Certificate Analysis** - X.509 field extraction and pivoting

### 🌐 Internet-Wide Scanning Integration
- **Shodan** - Query and pivot on device metadata
- **Censys** - Deep certificate and service analysis

### 📊 Visualization & Analysis
- **Infrastructure Graphs** - Visualize relationships between IOCs
- **Cluster Detection** - Identify related infrastructure
- **Export Formats** - STIX 2.1, MISP, CSV, JSON

### 🖥️ Multiple Interfaces
- **CLI** - Powerful command-line interface
- **REST API** - Full-featured API for integration
- **Web UI** - Intuitive dashboard for investigations

## Quick Start

### Installation
```bash
