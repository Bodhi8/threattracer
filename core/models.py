"""
ThreatTracer Core Models

Data models for indicators of compromise (IOCs), infrastructure,
and analysis results.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel, Field, field_validator
import ipaddress


class IndicatorType(str, Enum):
    """Types of indicators supported by ThreatTracer"""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    HASH_MD5 = "hash_md5"
    HASH_SHA1 = "hash_sha1"
    HASH_SHA256 = "hash_sha256"
    EMAIL = "email"
    JARM = "jarm"
    JA3 = "ja3"
    FAVICON_HASH = "favicon_hash"
    CERT_FINGERPRINT = "cert_fingerprint"


class ThreatLevel(str, Enum):
    """Threat classification levels"""
    UNKNOWN = "unknown"
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class Confidence(str, Enum):
    """Confidence levels for assessments"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"


# =============================================================================
# Base Indicator Model
# =============================================================================

class Indicator(BaseModel):
    """Base model for all indicators of compromise"""
    value: str
    type: IndicatorType
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    tags: list[str] = Field(default_factory=list)
    threat_level: ThreatLevel = ThreatLevel.UNKNOWN
    confidence: Confidence = Confidence.LOW
    source: Optional[str] = None
    notes: Optional[str] = None
    
    def __hash__(self):
        return hash((self.value, self.type))
    
    def __eq__(self, other):
        if isinstance(other, Indicator):
            return self.value == other.value and self.type == other.type
        return False


# =============================================================================
# IP Address Models
# =============================================================================

class GeoLocation(BaseModel):
    """Geographic location data"""
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timezone: Optional[str] = None


class ASNInfo(BaseModel):
    """Autonomous System Number information"""
    asn: Optional[int] = None
    asn_org: Optional[str] = None
    asn_country: Optional[str] = None
    asn_registry: Optional[str] = None
    asn_cidr: Optional[str] = None
    asn_description: Optional[str] = None


class IPIndicator(Indicator):
    """Extended model for IP address indicators"""
    type: IndicatorType = IndicatorType.IP
    version: int = 4  # 4 or 6
    
    # Enrichment data
    geolocation: Optional[GeoLocation] = None
    asn_info: Optional[ASNInfo] = None
    hostname: Optional[str] = None
    ptr_record: Optional[str] = None
    
    # Reputation
    abuse_score: Optional[float] = None
    malware_families: list[str] = Field(default_factory=list)
    
    # Passive DNS
    domains: list[str] = Field(default_factory=list)
    domain_count: int = 0
    
    # Fingerprints
    jarm: Optional[str] = None
    open_ports: list[int] = Field(default_factory=list)
    services: list[dict] = Field(default_factory=list)
    
    @field_validator('value')
    @classmethod
    def validate_ip(cls, v: str) -> str:
        try:
            ip = ipaddress.ip_address(v)
            return str(ip)
        except ValueError:
            raise ValueError(f"Invalid IP address: {v}")
    
    @property
    def is_private(self) -> bool:
        """Check if IP is in private range"""
        try:
            return ipaddress.ip_address(self.value).is_private
        except ValueError:
            return False
    
    @property
    def is_global(self) -> bool:
        """Check if IP is globally routable"""
        try:
            return ipaddress.ip_address(self.value).is_global
        except ValueError:
            return False


# =============================================================================
# Domain Models
# =============================================================================

class WHOISInfo(BaseModel):
    """WHOIS registration information"""
    registrar: Optional[str] = None
    registrant_name: Optional[str] = None
    registrant_org: Optional[str] = None
    registrant_email: Optional[str] = None
    registrant_country: Optional[str] = None
    creation_date: Optional[datetime] = None
    expiration_date: Optional[datetime] = None
    updated_date: Optional[datetime] = None
    name_servers: list[str] = Field(default_factory=list)
    status: list[str] = Field(default_factory=list)
    dnssec: Optional[bool] = None


class DNSRecord(BaseModel):
    """DNS record information"""
    record_type: str  # A, AAAA, CNAME, MX, NS, TXT, etc.
    value: str
    ttl: Optional[int] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None


class DomainIndicator(Indicator):
    """Extended model for domain indicators"""
    type: IndicatorType = IndicatorType.DOMAIN
    
    # WHOIS data
    whois: Optional[WHOISInfo] = None
    
    # DNS data
    dns_records: list[DNSRecord] = Field(default_factory=list)
    resolved_ips: list[str] = Field(default_factory=list)
    
    # Related domains
    subdomains: list[str] = Field(default_factory=list)
    sibling_domains: list[str] = Field(default_factory=list)
    
    # Reputation
    category: Optional[str] = None
    abuse_score: Optional[float] = None
    
    @property
    def age_days(self) -> Optional[int]:
        """Calculate domain age in days"""
        if self.whois and self.whois.creation_date:
            delta = datetime.now() - self.whois.creation_date
            return delta.days
        return None


# =============================================================================
# Certificate Models
# =============================================================================

class CertificateSubject(BaseModel):
    """X.509 certificate subject/issuer"""
    common_name: Optional[str] = None
    organization: Optional[str] = None
    organizational_unit: Optional[str] = None
    country: Optional[str] = None
    state: Optional[str] = None
    locality: Optional[str] = None


class Certificate(BaseModel):
    """X.509 certificate information"""
    fingerprint_sha256: str
    fingerprint_sha1: Optional[str] = None
    serial_number: Optional[str] = None
    
    subject: Optional[CertificateSubject] = None
    issuer: Optional[CertificateSubject] = None
    
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    
    # Subject Alternative Names
    san_dns: list[str] = Field(default_factory=list)
    san_ip: list[str] = Field(default_factory=list)
    san_email: list[str] = Field(default_factory=list)
    
    # Properties
    is_self_signed: bool = False
    is_expired: bool = False
    is_wildcard: bool = False
    
    key_algorithm: Optional[str] = None
    key_size: Optional[int] = None
    signature_algorithm: Optional[str] = None


# =============================================================================
# Fingerprint Models
# =============================================================================

class JARMFingerprint(BaseModel):
    """JARM TLS fingerprint"""
    fingerprint: str
    cipher_hash: str  # First 30 bytes
    extension_hash: str  # Last 32 bytes
    scan_time: datetime = Field(default_factory=datetime.now)
    port: int = 443
    
    @field_validator('fingerprint')
    @classmethod
    def validate_jarm(cls, v: str) -> str:
        if len(v) != 62:
            raise ValueError(f"JARM fingerprint must be 62 characters, got {len(v)}")
        return v.lower()


class JA3Fingerprint(BaseModel):
    """JA3/JA3S TLS fingerprint"""
    ja3_hash: str
    ja3_string: Optional[str] = None
    is_server: bool = False  # True for JA3S
    
    @field_validator('ja3_hash')
    @classmethod
    def validate_ja3(cls, v: str) -> str:
        if len(v) != 32:
            raise ValueError(f"JA3 hash must be 32 characters (MD5), got {len(v)}")
        return v.lower()


class JA4Fingerprint(BaseModel):
    """JA4+ fingerprint"""
    fingerprint: str
    fingerprint_type: str = "ja4"  # ja4, ja4s, ja4h, ja4x, ja4ssh
    
    # Parsed components
    part_a: Optional[str] = None  # Protocol info
    part_b: Optional[str] = None  # Cipher hash
    part_c: Optional[str] = None  # Extension hash


class FaviconHash(BaseModel):
    """Favicon MurmurHash3"""
    hash: int
    url: Optional[str] = None
    content_type: Optional[str] = None
    size_bytes: Optional[int] = None


# =============================================================================
# Infrastructure Models
# =============================================================================

class Service(BaseModel):
    """Network service running on a host"""
    port: int
    protocol: str = "tcp"
    service_name: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None
    
    # TLS info if applicable
    certificate: Optional[Certificate] = None
    jarm: Optional[JARMFingerprint] = None
    
    # HTTP info if applicable
    http_title: Optional[str] = None
    http_server: Optional[str] = None
    http_status: Optional[int] = None
    favicon_hash: Optional[int] = None


class Infrastructure(BaseModel):
    """Complete infrastructure record for an IP"""
    ip: str
    timestamp: datetime = Field(default_factory=datetime.now)
    
    # Basic info
    geolocation: Optional[GeoLocation] = None
    asn_info: Optional[ASNInfo] = None
    hostnames: list[str] = Field(default_factory=list)
    
    # Services
    services: list[Service] = Field(default_factory=list)
    
    # Fingerprints
    jarm: Optional[str] = None
    favicon_hashes: list[int] = Field(default_factory=list)
    
    # Threat assessment
    threat_level: ThreatLevel = ThreatLevel.UNKNOWN
    confidence: Confidence = Confidence.LOW
    malware_families: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    
    # Related infrastructure
    related_ips: list[str] = Field(default_factory=list)
    related_domains: list[str] = Field(default_factory=list)


# =============================================================================
# Relationship Models
# =============================================================================

class RelationshipType(str, Enum):
    """Types of relationships between indicators"""
    RESOLVES_TO = "resolves_to"
    HOSTED_ON = "hosted_on"
    SHARES_CERT = "shares_cert"
    SHARES_JARM = "shares_jarm"
    SHARES_FAVICON = "shares_favicon"
    SAME_ASN = "same_asn"
    SAME_REGISTRANT = "same_registrant"
    SUBDOMAIN_OF = "subdomain_of"
    COMMUNICATES_WITH = "communicates_with"
    DOWNLOADS_FROM = "downloads_from"
    CONTAINS = "contains"


class Relationship(BaseModel):
    """Relationship between two indicators"""
    source: Indicator
    target: Indicator
    relationship_type: RelationshipType
    confidence: Confidence = Confidence.MEDIUM
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    source_module: Optional[str] = None
    metadata: dict[str, Any] = Field(default_factory=dict)


# =============================================================================
# Cluster Models
# =============================================================================

class InfrastructureCluster(BaseModel):
    """A cluster of related infrastructure"""
    cluster_id: str
    name: Optional[str] = None
    description: Optional[str] = None
    
    # Members
    ips: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    certificates: list[str] = Field(default_factory=list)
    
    # Shared attributes
    shared_jarm: list[str] = Field(default_factory=list)
    shared_favicon: list[int] = Field(default_factory=list)
    shared_asn: list[int] = Field(default_factory=list)
    shared_registrant: list[str] = Field(default_factory=list)
    
    # Assessment
    threat_level: ThreatLevel = ThreatLevel.UNKNOWN
    confidence: Confidence = Confidence.LOW
    attributed_actor: Optional[str] = None
    campaign: Optional[str] = None
    
    # Metadata
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)
    tags: list[str] = Field(default_factory=list)


# =============================================================================
# Hunt/Investigation Models
# =============================================================================

class PivotType(str, Enum):
    """Types of pivots for infrastructure hunting"""
    JARM = "jarm"
    FAVICON = "favicon"
    CERTIFICATE = "certificate"
    ASN = "asn"
    WHOIS = "whois"
    PASSIVE_DNS = "passive_dns"
    HTTP_HEADERS = "http_headers"
    SERVICE_BANNER = "service_banner"


class HuntResult(BaseModel):
    """Result of a threat hunting operation"""
    hunt_id: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    
    # Seed indicator(s)
    seeds: list[Indicator]
    
    # Pivot configuration
    pivot_types: list[PivotType]
    max_depth: int = 2
    
    # Results
    discovered_infrastructure: list[Infrastructure] = Field(default_factory=list)
    relationships: list[Relationship] = Field(default_factory=list)
    clusters: list[InfrastructureCluster] = Field(default_factory=list)
    
    # Statistics
    total_ips: int = 0
    total_domains: int = 0
    total_certificates: int = 0
    total_pivots: int = 0
    
    # Status
    status: str = "running"  # running, completed, failed
    error: Optional[str] = None


# =============================================================================
# Enrichment Result Models
# =============================================================================

class EnrichmentResult(BaseModel):
    """Result of enriching an indicator"""
    indicator: Indicator
    enriched_at: datetime = Field(default_factory=datetime.now)
    
    # Module results
    module_results: dict[str, Any] = Field(default_factory=dict)
    
    # Aggregated data
    ip_data: Optional[IPIndicator] = None
    domain_data: Optional[DomainIndicator] = None
    infrastructure: Optional[Infrastructure] = None
    
    # Related indicators discovered
    related_indicators: list[Indicator] = Field(default_factory=list)
    relationships: list[Relationship] = Field(default_factory=list)
    
    # Errors from individual modules
    errors: dict[str, str] = Field(default_factory=dict)


# =============================================================================
# Export Models (STIX, etc.)
# =============================================================================

class ExportFormat(str, Enum):
    """Supported export formats"""
    JSON = "json"
    CSV = "csv"
    STIX = "stix"
    MISP = "misp"
    YARA = "yara"
