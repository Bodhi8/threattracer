"""
ThreatTracer Export Utilities

Export indicators and infrastructure to STIX 2.1, MISP, and other formats.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any, Optional

from threattracer.core.models import (
    Indicator,
    IndicatorType,
    IPIndicator,
    DomainIndicator,
    Infrastructure,
    InfrastructureCluster,
    ThreatLevel,
    Relationship,
    RelationshipType,
)


# =============================================================================
# STIX 2.1 Export
# =============================================================================

def generate_stix_id(stix_type: str) -> str:
    """Generate a STIX 2.1 compliant ID"""
    return f"{stix_type}--{uuid.uuid4()}"


def threat_level_to_stix_confidence(level: ThreatLevel) -> int:
    """Convert ThreatLevel to STIX confidence score (0-100)"""
    mapping = {
        ThreatLevel.UNKNOWN: 0,
        ThreatLevel.BENIGN: 10,
        ThreatLevel.SUSPICIOUS: 50,
        ThreatLevel.MALICIOUS: 90,
    }
    return mapping.get(level, 0)


def indicator_to_stix(indicator: Indicator) -> dict:
    """Convert an Indicator to STIX 2.1 Indicator object"""
    
    # Build pattern based on type
    if indicator.type == IndicatorType.IP:
        pattern = f"[ipv4-addr:value = '{indicator.value}']"
    elif indicator.type == IndicatorType.DOMAIN:
        pattern = f"[domain-name:value = '{indicator.value}']"
    elif indicator.type == IndicatorType.URL:
        pattern = f"[url:value = '{indicator.value}']"
    elif indicator.type in (IndicatorType.HASH_MD5, IndicatorType.HASH_SHA1, IndicatorType.HASH_SHA256):
        hash_type = indicator.type.value.replace("hash_", "")
        pattern = f"[file:hashes.'{hash_type.upper()}' = '{indicator.value}']"
    else:
        pattern = f"[x-threattracer:{indicator.type.value} = '{indicator.value}']"
    
    stix_indicator = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": generate_stix_id("indicator"),
        "created": datetime.utcnow().isoformat() + "Z",
        "modified": datetime.utcnow().isoformat() + "Z",
        "name": f"{indicator.type.value}: {indicator.value}",
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": indicator.first_seen.isoformat() + "Z" if indicator.first_seen else datetime.utcnow().isoformat() + "Z",
        "confidence": threat_level_to_stix_confidence(indicator.threat_level),
        "labels": indicator.tags,
    }
    
    if indicator.notes:
        stix_indicator["description"] = indicator.notes
    
    return stix_indicator


def infrastructure_to_stix(infra: Infrastructure) -> list[dict]:
    """Convert Infrastructure to STIX 2.1 objects (Infrastructure + Observables)"""
    objects = []
    
    # Create IPv4 Observable
    ipv4_id = generate_stix_id("ipv4-addr")
    ipv4_obj = {
        "type": "ipv4-addr",
        "spec_version": "2.1",
        "id": ipv4_id,
        "value": infra.ip,
    }
    objects.append(ipv4_obj)
    
    # Create Infrastructure object
    infra_id = generate_stix_id("infrastructure")
    infra_obj = {
        "type": "infrastructure",
        "spec_version": "2.1",
        "id": infra_id,
        "created": datetime.utcnow().isoformat() + "Z",
        "modified": datetime.utcnow().isoformat() + "Z",
        "name": f"Infrastructure: {infra.ip}",
        "infrastructure_types": ["command-and-control"] if infra.threat_level == ThreatLevel.MALICIOUS else ["unknown"],
    }
    
    if infra.geolocation:
        infra_obj["x_country"] = infra.geolocation.country_code
    if infra.asn_info:
        infra_obj["x_asn"] = infra.asn_info.asn
        infra_obj["x_asn_org"] = infra.asn_info.asn_org
    if infra.jarm:
        infra_obj["x_jarm"] = infra.jarm
    
    objects.append(infra_obj)
    
    # Create relationship
    rel_obj = {
        "type": "relationship",
        "spec_version": "2.1",
        "id": generate_stix_id("relationship"),
        "created": datetime.utcnow().isoformat() + "Z",
        "modified": datetime.utcnow().isoformat() + "Z",
        "relationship_type": "consists-of",
        "source_ref": infra_id,
        "target_ref": ipv4_id,
    }
    objects.append(rel_obj)
    
    return objects


def export_to_stix_bundle(
    indicators: list[Indicator] = None,
    infrastructure: list[Infrastructure] = None,
    relationships: list[Relationship] = None,
) -> dict:
    """
    Export indicators and infrastructure to a STIX 2.1 Bundle.
    """
    objects = []
    
    # Add indicators
    if indicators:
        for ind in indicators:
            objects.append(indicator_to_stix(ind))
    
    # Add infrastructure
    if infrastructure:
        for infra in infrastructure:
            objects.extend(infrastructure_to_stix(infra))
    
    # Create bundle
    bundle = {
        "type": "bundle",
        "id": generate_stix_id("bundle"),
        "objects": objects,
    }
    
    return bundle


# =============================================================================
# MISP Export
# =============================================================================

def indicator_type_to_misp_type(indicator_type: IndicatorType) -> str:
    """Map indicator type to MISP attribute type"""
    mapping = {
        IndicatorType.IP: "ip-dst",
        IndicatorType.DOMAIN: "domain",
        IndicatorType.URL: "url",
        IndicatorType.HASH_MD5: "md5",
        IndicatorType.HASH_SHA1: "sha1",
        IndicatorType.HASH_SHA256: "sha256",
        IndicatorType.EMAIL: "email-src",
        IndicatorType.JARM: "x-misp-jarm",
        IndicatorType.FAVICON_HASH: "x-misp-favicon-hash",
    }
    return mapping.get(indicator_type, "text")


def threat_level_to_misp_threat_level(level: ThreatLevel) -> int:
    """Convert ThreatLevel to MISP threat level (1-4, 1 = high)"""
    mapping = {
        ThreatLevel.MALICIOUS: 1,
        ThreatLevel.SUSPICIOUS: 2,
        ThreatLevel.UNKNOWN: 3,
        ThreatLevel.BENIGN: 4,
    }
    return mapping.get(level, 3)


def indicator_to_misp_attribute(indicator: Indicator) -> dict:
    """Convert an Indicator to MISP attribute format"""
    return {
        "type": indicator_type_to_misp_type(indicator.type),
        "value": indicator.value,
        "category": "Network activity" if indicator.type in (IndicatorType.IP, IndicatorType.DOMAIN, IndicatorType.URL) else "Payload delivery",
        "to_ids": indicator.threat_level == ThreatLevel.MALICIOUS,
        "comment": indicator.notes or "",
        "first_seen": indicator.first_seen.isoformat() if indicator.first_seen else None,
        "last_seen": indicator.last_seen.isoformat() if indicator.last_seen else None,
        "Tag": [{"name": tag} for tag in indicator.tags],
    }


def export_to_misp_event(
    indicators: list[Indicator],
    event_info: str = "ThreatTracer Export",
    threat_level: ThreatLevel = ThreatLevel.UNKNOWN,
) -> dict:
    """
    Export indicators to MISP event format.
    """
    attributes = [indicator_to_misp_attribute(ind) for ind in indicators]
    
    event = {
        "Event": {
            "info": event_info,
            "threat_level_id": threat_level_to_misp_threat_level(threat_level),
            "analysis": 2,  # Completed
            "distribution": 0,  # Your organization only
            "date": datetime.utcnow().strftime("%Y-%m-%d"),
            "Attribute": attributes,
        }
    }
    
    return event


# =============================================================================
# CSV Export
# =============================================================================

def export_to_csv(
    indicators: list[Indicator],
    include_headers: bool = True,
) -> str:
    """Export indicators to CSV format"""
    lines = []
    
    if include_headers:
        lines.append("type,value,threat_level,confidence,first_seen,last_seen,tags,source")
    
    for ind in indicators:
        tags_str = "|".join(ind.tags)
        first_seen = ind.first_seen.isoformat() if ind.first_seen else ""
        last_seen = ind.last_seen.isoformat() if ind.last_seen else ""
        
        line = f"{ind.type.value},{ind.value},{ind.threat_level.value},{ind.confidence.value},{first_seen},{last_seen},{tags_str},{ind.source or ''}"
        lines.append(line)
    
    return "\n".join(lines)


# =============================================================================
# JSON Export
# =============================================================================

def export_to_json(
    indicators: list[Indicator] = None,
    infrastructure: list[Infrastructure] = None,
    clusters: list[InfrastructureCluster] = None,
    pretty: bool = True,
) -> str:
    """Export data to JSON format"""
    data = {
        "exported_at": datetime.utcnow().isoformat() + "Z",
        "version": "1.0",
    }
    
    if indicators:
        data["indicators"] = [
            {
                "type": ind.type.value,
                "value": ind.value,
                "threat_level": ind.threat_level.value,
                "confidence": ind.confidence.value,
                "tags": ind.tags,
                "first_seen": ind.first_seen.isoformat() if ind.first_seen else None,
                "last_seen": ind.last_seen.isoformat() if ind.last_seen else None,
            }
            for ind in indicators
        ]
    
    if infrastructure:
        data["infrastructure"] = [
            {
                "ip": infra.ip,
                "country": infra.geolocation.country_code if infra.geolocation else None,
                "asn": infra.asn_info.asn if infra.asn_info else None,
                "jarm": infra.jarm,
                "threat_level": infra.threat_level.value,
            }
            for infra in infrastructure
        ]
    
    if clusters:
        data["clusters"] = [
            {
                "cluster_id": c.cluster_id,
                "ips": c.ips,
                "domains": c.domains,
                "shared_jarm": c.shared_jarm,
                "shared_favicon": c.shared_favicon,
                "threat_level": c.threat_level.value,
            }
            for c in clusters
        ]
    
    if pretty:
        return json.dumps(data, indent=2)
    return json.dumps(data)
