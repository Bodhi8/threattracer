"""
ThreatTracer WHOIS Enricher

Enriches domain indicators with WHOIS registration data.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Optional

import whois

from threattracer.core.models import IndicatorType, WHOISInfo
from threattracer.enrichers.base import BaseEnricher, EnricherError, enricher


logger = logging.getLogger(__name__)


@enricher
class WHOISEnricher(BaseEnricher):
    """
    Enricher for WHOIS domain registration data.
    
    No API key required - uses python-whois library.
    """
    
    name = "whois"
    description = "WHOIS domain registration lookup"
    version = "1.0.0"
    supported_types = [IndicatorType.DOMAIN]
    required_config = []
    requests_per_minute = 30  # Be gentle with WHOIS servers
    
    async def enrich_domain(self, domain: str) -> dict[str, Any]:
        """
        Enrich a domain with WHOIS data.
        
        Returns:
            dict with WHOIS information
        """
        try:
            # python-whois is synchronous, so we run it in executor
            import asyncio
            loop = asyncio.get_event_loop()
            w = await loop.run_in_executor(None, whois.whois, domain)
            
            if not w or not w.domain_name:
                return {"error": "No WHOIS data found", "domain": domain}
            
            # Parse dates
            creation_date = self._parse_date(w.creation_date)
            expiration_date = self._parse_date(w.expiration_date)
            updated_date = self._parse_date(w.updated_date)
            
            # Build result
            result = {
                "domain": domain,
                "registrar": w.registrar,
                "registrant_name": self._safe_get(w, "name"),
                "registrant_org": self._safe_get(w, "org"),
                "registrant_email": self._get_email(w),
                "registrant_country": self._safe_get(w, "country"),
                "creation_date": creation_date.isoformat() if creation_date else None,
                "expiration_date": expiration_date.isoformat() if expiration_date else None,
                "updated_date": updated_date.isoformat() if updated_date else None,
                "name_servers": self._normalize_list(w.name_servers),
                "status": self._normalize_list(w.status),
                "dnssec": self._safe_get(w, "dnssec"),
                "whois_server": self._safe_get(w, "whois_server"),
            }
            
            # Calculate domain age
            if creation_date:
                age_days = (datetime.now() - creation_date).days
                result["age_days"] = age_days
                result["is_newly_registered"] = age_days < 30
            
            # Red flags
            red_flags = []
            if result.get("is_newly_registered"):
                red_flags.append("newly_registered")
            if result.get("registrant_email") and "privacy" in result["registrant_email"].lower():
                red_flags.append("privacy_protected")
            if result.get("registrant_email") and "proxy" in result["registrant_email"].lower():
                red_flags.append("proxy_registration")
            
            result["red_flags"] = red_flags
            
            return result
            
        except whois.parser.PywhoisError as e:
            logger.warning(f"WHOIS lookup failed for {domain}: {e}")
            return {"error": str(e), "domain": domain}
        except Exception as e:
            logger.exception(f"WHOIS error for {domain}")
            raise EnricherError(f"WHOIS lookup failed: {e}")
    
    def _parse_date(self, date_value) -> Optional[datetime]:
        """Parse date from WHOIS response (can be list or single value)"""
        if date_value is None:
            return None
        
        if isinstance(date_value, list):
            date_value = date_value[0] if date_value else None
        
        if isinstance(date_value, datetime):
            return date_value
        
        if isinstance(date_value, str):
            # Try common formats
            formats = [
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%d",
                "%d-%b-%Y",
            ]
            for fmt in formats:
                try:
                    return datetime.strptime(date_value, fmt)
                except ValueError:
                    continue
        
        return None
    
    def _safe_get(self, whois_obj, attr: str) -> Optional[str]:
        """Safely get attribute from WHOIS object"""
        try:
            value = getattr(whois_obj, attr, None)
            if isinstance(value, list):
                return value[0] if value else None
            return value
        except Exception:
            return None
    
    def _get_email(self, whois_obj) -> Optional[str]:
        """Get email from WHOIS, checking multiple fields"""
        for attr in ["emails", "email", "registrant_email"]:
            value = self._safe_get(whois_obj, attr)
            if value:
                return value
        return None
    
    def _normalize_list(self, value) -> list[str]:
        """Normalize a value to a list of strings"""
        if value is None:
            return []
        if isinstance(value, str):
            return [value.lower()]
        if isinstance(value, list):
            return [str(v).lower() for v in value if v]
        return []
    
    def to_whois_info(self, data: dict) -> Optional[WHOISInfo]:
        """Convert enrichment result to WHOISInfo model"""
        if "error" in data:
            return None
        
        return WHOISInfo(
            registrar=data.get("registrar"),
            registrant_name=data.get("registrant_name"),
            registrant_org=data.get("registrant_org"),
            registrant_email=data.get("registrant_email"),
            registrant_country=data.get("registrant_country"),
            creation_date=datetime.fromisoformat(data["creation_date"]) if data.get("creation_date") else None,
            expiration_date=datetime.fromisoformat(data["expiration_date"]) if data.get("expiration_date") else None,
            updated_date=datetime.fromisoformat(data["updated_date"]) if data.get("updated_date") else None,
            name_servers=data.get("name_servers", []),
            status=data.get("status", []),
        )
