"""
ThreatTracer VirusTotal Enricher

Enriches indicators with VirusTotal reputation and relationship data.
"""

from __future__ import annotations

import logging
from typing import Any, Optional
from datetime import datetime

from threattracer.core.models import IndicatorType, ThreatLevel, Confidence
from threattracer.enrichers.base import BaseEnricher, EnricherError, enricher


logger = logging.getLogger(__name__)


@enricher
class VirusTotalEnricher(BaseEnricher):
    """
    Enricher for VirusTotal threat intelligence.
    
    Requires a VirusTotal API key.
    Free tier: 4 requests/minute, 500 requests/day
    """
    
    name = "virustotal"
    description = "VirusTotal reputation and relationships"
    version = "1.0.0"
    supported_types = [
        IndicatorType.IP,
        IndicatorType.DOMAIN,
        IndicatorType.URL,
        IndicatorType.HASH_MD5,
        IndicatorType.HASH_SHA1,
        IndicatorType.HASH_SHA256,
    ]
    required_config = ["virustotal"]
    requests_per_minute = 4  # Free tier limit
    
    BASE_URL = "https://www.virustotal.com/api/v3"
    
    def _get_headers(self) -> dict:
        """Get headers with API key"""
        api_key = self.get_api_key("virustotal")
        return {
            "x-apikey": api_key,
            "Accept": "application/json",
        }
    
    async def enrich_ip(self, ip: str) -> dict[str, Any]:
        """Enrich an IP address with VirusTotal data"""
        try:
            response = await self._get(
                f"{self.BASE_URL}/ip_addresses/{ip}",
                headers=self._get_headers()
            )
            
            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            
            # Parse detection stats
            stats = attributes.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total = malicious + suspicious + harmless + undetected
            
            result = {
                "ip": ip,
                "reputation": attributes.get("reputation", 0),
                "country": attributes.get("country"),
                "continent": attributes.get("continent"),
                "asn": attributes.get("asn"),
                "as_owner": attributes.get("as_owner"),
                "network": attributes.get("network"),
                
                # Detection stats
                "malicious_count": malicious,
                "suspicious_count": suspicious,
                "harmless_count": harmless,
                "undetected_count": undetected,
                "total_engines": total,
                "detection_ratio": f"{malicious}/{total}" if total > 0 else "0/0",
                
                # Threat assessment
                "threat_level": self._assess_threat_level(malicious, suspicious, total),
                "confidence": self._assess_confidence(total),
                
                # Tags
                "tags": attributes.get("tags", []),
                
                # Timestamps
                "last_analysis_date": self._parse_timestamp(attributes.get("last_analysis_date")),
                "last_modification_date": self._parse_timestamp(attributes.get("last_modification_date")),
                
                # JARM fingerprint if available
                "jarm": attributes.get("jarm"),
                
                # SSL certificate info
                "last_https_certificate": attributes.get("last_https_certificate", {}),
            }
            
            # Get relationships (communicating files, URLs, etc.)
            result["relationships"] = await self._get_ip_relationships(ip)
            
            return result
            
        except Exception as e:
            logger.exception(f"VirusTotal error for IP {ip}")
            raise EnricherError(f"VirusTotal lookup failed: {e}")
    
    async def enrich_domain(self, domain: str) -> dict[str, Any]:
        """Enrich a domain with VirusTotal data"""
        try:
            response = await self._get(
                f"{self.BASE_URL}/domains/{domain}",
                headers=self._get_headers()
            )
            
            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            
            # Parse detection stats
            stats = attributes.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values())
            
            result = {
                "domain": domain,
                "reputation": attributes.get("reputation", 0),
                "registrar": attributes.get("registrar"),
                "creation_date": self._parse_timestamp(attributes.get("creation_date")),
                "last_update_date": self._parse_timestamp(attributes.get("last_update_date")),
                
                # Detection stats
                "malicious_count": malicious,
                "suspicious_count": suspicious,
                "total_engines": total,
                "detection_ratio": f"{malicious}/{total}" if total > 0 else "0/0",
                
                # Threat assessment
                "threat_level": self._assess_threat_level(malicious, suspicious, total),
                
                # Categories
                "categories": attributes.get("categories", {}),
                "tags": attributes.get("tags", []),
                
                # DNS records
                "last_dns_records": attributes.get("last_dns_records", []),
                
                # Popularity ranks
                "popularity_ranks": attributes.get("popularity_ranks", {}),
                
                # JARM
                "jarm": attributes.get("jarm"),
                
                # Whois
                "whois": attributes.get("whois"),
            }
            
            return result
            
        except Exception as e:
            logger.exception(f"VirusTotal error for domain {domain}")
            raise EnricherError(f"VirusTotal lookup failed: {e}")
    
    async def enrich_hash(self, hash_value: str, hash_type: IndicatorType) -> dict[str, Any]:
        """Enrich a file hash with VirusTotal data"""
        try:
            response = await self._get(
                f"{self.BASE_URL}/files/{hash_value}",
                headers=self._get_headers()
            )
            
            data = response.json()
            attributes = data.get("data", {}).get("attributes", {})
            
            # Parse detection stats
            stats = attributes.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values())
            
            result = {
                "hash": hash_value,
                "hash_type": hash_type.value,
                
                # File info
                "md5": attributes.get("md5"),
                "sha1": attributes.get("sha1"),
                "sha256": attributes.get("sha256"),
                "ssdeep": attributes.get("ssdeep"),
                "tlsh": attributes.get("tlsh"),
                "vhash": attributes.get("vhash"),
                
                "size": attributes.get("size"),
                "type_description": attributes.get("type_description"),
                "type_tag": attributes.get("type_tag"),
                "magic": attributes.get("magic"),
                
                # Detection stats
                "malicious_count": malicious,
                "suspicious_count": suspicious,
                "total_engines": total,
                "detection_ratio": f"{malicious}/{total}" if total > 0 else "0/0",
                
                # Threat assessment
                "threat_level": self._assess_threat_level(malicious, suspicious, total),
                
                # Signature info
                "signature_info": attributes.get("signature_info", {}),
                
                # Names
                "names": attributes.get("names", []),
                "meaningful_name": attributes.get("meaningful_name"),
                
                # Tags and labels
                "tags": attributes.get("tags", []),
                "popular_threat_classification": attributes.get("popular_threat_classification", {}),
                
                # Timestamps
                "first_submission_date": self._parse_timestamp(attributes.get("first_submission_date")),
                "last_submission_date": self._parse_timestamp(attributes.get("last_submission_date")),
                "last_analysis_date": self._parse_timestamp(attributes.get("last_analysis_date")),
            }
            
            return result
            
        except Exception as e:
            logger.exception(f"VirusTotal error for hash {hash_value}")
            raise EnricherError(f"VirusTotal lookup failed: {e}")
    
    async def _get_ip_relationships(self, ip: str) -> dict[str, Any]:
        """Get relationships for an IP (communicating files, URLs, etc.)"""
        relationships = {}
        
        try:
            # Get communicating files
            response = await self._get(
                f"{self.BASE_URL}/ip_addresses/{ip}/communicating_files",
                headers=self._get_headers(),
                params={"limit": 10}
            )
            data = response.json()
            relationships["communicating_files"] = [
                item.get("id") for item in data.get("data", [])
            ]
            relationships["communicating_files_count"] = data.get("meta", {}).get("count", 0)
        except Exception as e:
            logger.debug(f"Failed to get communicating files for {ip}: {e}")
        
        try:
            # Get URLs on this IP
            response = await self._get(
                f"{self.BASE_URL}/ip_addresses/{ip}/urls",
                headers=self._get_headers(),
                params={"limit": 10}
            )
            data = response.json()
            relationships["urls"] = [
                item.get("id") for item in data.get("data", [])
            ]
            relationships["urls_count"] = data.get("meta", {}).get("count", 0)
        except Exception as e:
            logger.debug(f"Failed to get URLs for {ip}: {e}")
        
        return relationships
    
    def _parse_timestamp(self, ts: Optional[int]) -> Optional[str]:
        """Convert Unix timestamp to ISO format"""
        if ts:
            return datetime.fromtimestamp(ts).isoformat()
        return None
    
    def _assess_threat_level(self, malicious: int, suspicious: int, total: int) -> str:
        """Assess threat level based on detection counts"""
        if total == 0:
            return ThreatLevel.UNKNOWN.value
        
        mal_ratio = malicious / total
        sus_ratio = suspicious / total
        
        if mal_ratio >= 0.5:
            return ThreatLevel.MALICIOUS.value
        elif mal_ratio >= 0.1 or sus_ratio >= 0.3:
            return ThreatLevel.SUSPICIOUS.value
        elif malicious == 0 and suspicious == 0:
            return ThreatLevel.BENIGN.value
        else:
            return ThreatLevel.SUSPICIOUS.value
    
    def _assess_confidence(self, total: int) -> str:
        """Assess confidence based on number of engines"""
        if total >= 60:
            return Confidence.HIGH.value
        elif total >= 30:
            return Confidence.MEDIUM.value
        else:
            return Confidence.LOW.value
