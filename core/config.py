"""
ThreatTracer Configuration Management

Handles loading and validating configuration from YAML files
and environment variables.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Optional
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings
import yaml


class APIKeys(BaseModel):
    """API keys for external services"""
    shodan: Optional[str] = None
    censys_id: Optional[str] = None
    censys_secret: Optional[str] = None
    virustotal: Optional[str] = None
    securitytrails: Optional[str] = None
    passivetotal_user: Optional[str] = None
    passivetotal_key: Optional[str] = None
    abuseipdb: Optional[str] = None
    otx: Optional[str] = None
    greynoise: Optional[str] = None


class DatabaseConfig(BaseModel):
    """Database configuration"""
    type: str = "sqlite"
    path: str = "threattracer.db"
    url: Optional[str] = None  # For PostgreSQL, etc.


class CacheConfig(BaseModel):
    """Cache configuration"""
    enabled: bool = True
    type: str = "memory"  # memory, redis
    ttl_seconds: int = 3600
    redis_url: Optional[str] = None


class RateLimitConfig(BaseModel):
    """Rate limiting configuration"""
    enabled: bool = True
    requests_per_minute: int = 60
    burst_size: int = 10


class ScannerConfig(BaseModel):
    """Scanner module configuration"""
    timeout_seconds: int = 30
    max_concurrent: int = 10
    retry_count: int = 3
    retry_delay_seconds: int = 5


class EnricherConfig(BaseModel):
    """Enricher module configuration"""
    timeout_seconds: int = 30
    max_concurrent: int = 5
    enabled_modules: list[str] = Field(default_factory=lambda: [
        "whois", "asn", "geoip", "pdns", "virustotal"
    ])


class HuntConfig(BaseModel):
    """Threat hunting configuration"""
    max_depth: int = 2
    max_results_per_pivot: int = 100
    enabled_pivots: list[str] = Field(default_factory=lambda: [
        "jarm", "favicon", "certificate", "asn"
    ])
    exclude_asns: list[int] = Field(default_factory=list)
    exclude_orgs: list[str] = Field(default_factory=lambda: [
        "Microsoft", "Amazon", "Google", "Cloudflare"
    ])


class WebConfig(BaseModel):
    """Web interface configuration"""
    host: str = "127.0.0.1"
    port: int = 8080
    debug: bool = False
    secret_key: Optional[str] = None


class APIConfig(BaseModel):
    """REST API configuration"""
    host: str = "127.0.0.1"
    port: int = 8000
    debug: bool = False
    api_key: Optional[str] = None  # API key for authentication
    cors_origins: list[str] = Field(default_factory=lambda: ["*"])


class LoggingConfig(BaseModel):
    """Logging configuration"""
    level: str = "INFO"
    format: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    file: Optional[str] = None


class Config(BaseSettings):
    """Main configuration container"""
    
    # API Keys
    api_keys: APIKeys = Field(default_factory=APIKeys)
    
    # Component configs
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    cache: CacheConfig = Field(default_factory=CacheConfig)
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)
    scanner: ScannerConfig = Field(default_factory=ScannerConfig)
    enricher: EnricherConfig = Field(default_factory=EnricherConfig)
    hunt: HuntConfig = Field(default_factory=HuntConfig)
    web: WebConfig = Field(default_factory=WebConfig)
    api: APIConfig = Field(default_factory=APIConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    
    class Config:
        env_prefix = "THREATTRACER_"
        env_nested_delimiter = "__"


def load_config(config_path: Optional[str] = None) -> Config:
    """
    Load configuration from YAML file and environment variables.
    
    Priority (highest to lowest):
    1. Environment variables (THREATTRACER_*)
    2. Config file (config.yaml)
    3. Default values
    """
    config_data: dict[str, Any] = {}
    
    # Determine config file path
    if config_path is None:
        # Look for config in standard locations
        search_paths = [
            Path("config.yaml"),
            Path("config.yml"),
            Path.home() / ".config" / "threattracer" / "config.yaml",
            Path("/etc/threattracer/config.yaml"),
        ]
        for path in search_paths:
            if path.exists():
                config_path = str(path)
                break
    
    # Load from YAML if found
    if config_path and Path(config_path).exists():
        with open(config_path, "r") as f:
            config_data = yaml.safe_load(f) or {}
    
    # Override with environment variables
    # API keys from environment
    env_mapping = {
        "SHODAN_API_KEY": ("api_keys", "shodan"),
        "CENSYS_API_ID": ("api_keys", "censys_id"),
        "CENSYS_API_SECRET": ("api_keys", "censys_secret"),
        "VIRUSTOTAL_API_KEY": ("api_keys", "virustotal"),
        "SECURITYTRAILS_API_KEY": ("api_keys", "securitytrails"),
        "ABUSEIPDB_API_KEY": ("api_keys", "abuseipdb"),
        "OTX_API_KEY": ("api_keys", "otx"),
    }
    
    for env_var, (section, key) in env_mapping.items():
        value = os.environ.get(env_var)
        if value:
            if section not in config_data:
                config_data[section] = {}
            config_data[section][key] = value
    
    return Config(**config_data)


def create_example_config() -> str:
    """Generate an example configuration file"""
    return """# ThreatTracer Configuration
# Copy this file to config.yaml and fill in your API keys

api_keys:
  # Shodan - https://account.shodan.io/
  shodan: "your-shodan-api-key"
  
  # Censys - https://search.censys.io/account/api
  censys_id: "your-censys-id"
  censys_secret: "your-censys-secret"
  
  # VirusTotal - https://www.virustotal.com/gui/my-apikey
  virustotal: "your-virustotal-key"
  
  # SecurityTrails - https://securitytrails.com/app/account/credentials
  securitytrails: "your-securitytrails-key"
  
  # AbuseIPDB - https://www.abuseipdb.com/account/api
  abuseipdb: "your-abuseipdb-key"
  
  # AlienVault OTX - https://otx.alienvault.com/api
  otx: "your-otx-key"

database:
  type: sqlite
  path: threattracer.db

cache:
  enabled: true
  type: memory  # memory or redis
  ttl_seconds: 3600
  # redis_url: "redis://localhost:6379/0"

rate_limit:
  enabled: true
  requests_per_minute: 60
  burst_size: 10

scanner:
  timeout_seconds: 30
  max_concurrent: 10
  retry_count: 3
  retry_delay_seconds: 5

enricher:
  timeout_seconds: 30
  max_concurrent: 5
  enabled_modules:
    - whois
    - asn
    - geoip
    - pdns
    - virustotal

hunt:
  max_depth: 2
  max_results_per_pivot: 100
  enabled_pivots:
    - jarm
    - favicon
    - certificate
    - asn
  exclude_orgs:
    - Microsoft
    - Amazon
    - Google
    - Cloudflare
    - Akamai

web:
  host: "127.0.0.1"
  port: 8080
  debug: false

api:
  host: "127.0.0.1"
  port: 8000
  debug: false
  cors_origins:
    - "*"

logging:
  level: INFO
  # file: /var/log/threattracer/threattracer.log
"""


# Global config instance
_config: Optional[Config] = None


def get_config() -> Config:
    """Get the global configuration instance"""
    global _config
    if _config is None:
        _config = load_config()
    return _config


def set_config(config: Config) -> None:
    """Set the global configuration instance"""
    global _config
    _config = config
