"""
ThreatTracer ASN Enricher

Enriches IP indicators with ASN and BGP information.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Optional

from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError, ASNRegistryError

from threattracer.core.models import IndicatorType, ASNInfo, GeoLocation
from threattracer.enrichers.base import BaseEnricher, EnricherError, enricher


logger = logging.getLogger(__name__)


# Known bulletproof/suspicious ASNs (this is a sample - maintain your own list)
SUSPICIOUS_ASNS = {
    # Add known suspicious ASNs here
    # These are examples - verify with current threat intel
}


@enricher
class ASNEnricher(BaseEnricher):
    """
    Enricher for ASN and BGP information.
    
    No API key required - uses ipwhois library.
    """
    
    name = "asn"
    description = "ASN and BGP information lookup"
    version = "1.0.0"
    supported_types = [IndicatorType.IP]
    required_config = []
    requests_per_minute = 60
    
    async def enrich_ip(self, ip: str) -> dict[str, Any]:
        """
        Enrich an IP with ASN information.
        
        Returns:
            dict with ASN and network information
        """
        try:
            # ipwhois is synchronous, run in executor
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, self._lookup_ip, ip)
            return result
            
        except IPDefinedError:
            return {
                "ip": ip,
                "error": "Private or reserved IP address",
                "is_private": True
            }
        except ASNRegistryError as e:
            logger.warning(f"ASN lookup failed for {ip}: {e}")
            return {"ip": ip, "error": str(e)}
        except Exception as e:
            logger.exception(f"ASN error for {ip}")
            raise EnricherError(f"ASN lookup failed: {e}")
    
    def _lookup_ip(self, ip: str) -> dict[str, Any]:
        """Perform the actual IP lookup (synchronous)"""
        obj = IPWhois(ip)
        
        # Try RDAP first (more detailed), fall back to legacy whois
        try:
            results = obj.lookup_rdap(depth=1)
        except Exception:
            results = obj.lookup_whois()
        
        # Extract ASN info
        asn = results.get("asn")
        asn_int = int(asn) if asn and asn != "NA" else None
        
        result = {
            "ip": ip,
            "asn": asn_int,
            "asn_cidr": results.get("asn_cidr"),
            "asn_country_code": results.get("asn_country_code"),
            "asn_date": results.get("asn_date"),
            "asn_description": results.get("asn_description"),
            "asn_registry": results.get("asn_registry"),
        }
        
        # Extract network info
        network = results.get("network", {})
        if network:
            result.update({
                "network_name": network.get("name"),
                "network_cidr": network.get("cidr"),
                "network_country": network.get("country"),
                "network_handle": network.get("handle"),
                "network_start_address": network.get("start_address"),
                "network_end_address": network.get("end_address"),
            })
        
        # Extract entity/organization info
        entities = results.get("entities", [])
        if entities:
            result["entities"] = entities
        
        # Check for suspicious ASN
        if asn_int and asn_int in SUSPICIOUS_ASNS:
            result["suspicious_asn"] = True
            result["asn_notes"] = SUSPICIOUS_ASNS.get(asn_int, "Known suspicious ASN")
        
        # Add abuse contact if available
        objects = results.get("objects", {})
        for obj_key, obj_data in objects.items():
            if obj_data.get("contact"):
                abuse_emails = []
                for contact in obj_data.get("contact", {}).get("email", []):
                    if contact.get("value"):
                        abuse_emails.append(contact["value"])
                if abuse_emails:
                    result["abuse_contacts"] = abuse_emails
                    break
        
        return result
    
    def to_asn_info(self, data: dict) -> Optional[ASNInfo]:
        """Convert enrichment result to ASNInfo model"""
        if "error" in data or data.get("is_private"):
            return None
        
        return ASNInfo(
            asn=data.get("asn"),
            asn_org=data.get("asn_description"),
            asn_country=data.get("asn_country_code"),
            asn_registry=data.get("asn_registry"),
            asn_cidr=data.get("asn_cidr"),
            asn_description=data.get("asn_description"),
        )


@enricher  
class GeoIPEnricher(BaseEnricher):
    """
    Enricher for IP geolocation.
    
    Uses free ip-api.com service (no API key for limited use).
    """
    
    name = "geoip"
    description = "IP geolocation lookup"
    version = "1.0.0"
    supported_types = [IndicatorType.IP]
    required_config = []
    requests_per_minute = 45  # ip-api.com limit
    
    BASE_URL = "http://ip-api.com/json"
    
    async def enrich_ip(self, ip: str) -> dict[str, Any]:
        """
        Enrich an IP with geolocation data.
        
        Returns:
            dict with geolocation information
        """
        try:
            # Request fields we want
            fields = "status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
            
            response = await self._get(
                f"{self.BASE_URL}/{ip}",
                params={"fields": fields}
            )
            
            data = response.json()
            
            if data.get("status") == "fail":
                return {
                    "ip": ip,
                    "error": data.get("message", "Lookup failed")
                }
            
            result = {
                "ip": ip,
                "country": data.get("country"),
                "country_code": data.get("countryCode"),
                "region": data.get("regionName"),
                "region_code": data.get("region"),
                "city": data.get("city"),
                "postal_code": data.get("zip"),
                "latitude": data.get("lat"),
                "longitude": data.get("lon"),
                "timezone": data.get("timezone"),
                "isp": data.get("isp"),
                "org": data.get("org"),
                "as_info": data.get("as"),
            }
            
            return result
            
        except Exception as e:
            logger.exception(f"GeoIP error for {ip}")
            raise EnricherError(f"GeoIP lookup failed: {e}")
    
    def to_geolocation(self, data: dict) -> Optional[GeoLocation]:
        """Convert enrichment result to GeoLocation model"""
        if "error" in data:
            return None
        
        return GeoLocation(
            country=data.get("country"),
            country_code=data.get("country_code"),
            region=data.get("region"),
            city=data.get("city"),
            latitude=data.get("latitude"),
            longitude=data.get("longitude"),
            timezone=data.get("timezone"),
        )
