"""
ThreatTracer Shodan Scanner

Integration with Shodan API for internet-wide scanning and host lookups.
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import shodan

from threattracer.core.config import Config, get_config
from threattracer.core.models import (
    Infrastructure,
    Service,
    GeoLocation,
    ASNInfo,
    Certificate,
    CertificateSubject,
    ThreatLevel,
)


logger = logging.getLogger(__name__)


class ShodanScanner:
    """
    Shodan API integration for threat hunting.
    
    Provides methods for:
    - Host lookups
    - Search queries
    - DNS lookups
    - Exploit searches
    """
    
    def __init__(self, config: Optional[Config] = None):
        self.config = config or get_config()
        self._api: Optional[shodan.Shodan] = None
    
    @property
    def api(self) -> shodan.Shodan:
        if self._api is None:
            api_key = self.config.api_keys.shodan
            if not api_key:
                raise ValueError("Shodan API key not configured")
            self._api = shodan.Shodan(api_key)
        return self._api
    
    def is_configured(self) -> bool:
        """Check if Shodan API key is configured"""
        return bool(self.config.api_keys.shodan)
    
    # =========================================================================
    # Host Lookups
    # =========================================================================
    
    async def lookup_host(self, ip: str) -> Optional[Infrastructure]:
        """
        Look up an IP address in Shodan.
        
        Args:
            ip: IP address to look up
            
        Returns:
            Infrastructure object with Shodan data
        """
        try:
            import asyncio
            loop = asyncio.get_event_loop()
            host = await loop.run_in_executor(None, self.api.host, ip)
            
            return self._parse_host(host)
            
        except shodan.APIError as e:
            if "No information available" in str(e):
                logger.debug(f"No Shodan data for {ip}")
                return None
            logger.error(f"Shodan API error for {ip}: {e}")
            raise
        except Exception as e:
            logger.exception(f"Shodan lookup error for {ip}")
            raise
    
    def _parse_host(self, host: dict) -> Infrastructure:
        """Parse Shodan host response into Infrastructure model"""
        
        # Parse geolocation
        geo = GeoLocation(
            country=host.get("country_name"),
            country_code=host.get("country_code"),
            region=host.get("region_code"),
            city=host.get("city"),
            latitude=host.get("latitude"),
            longitude=host.get("longitude"),
        )
        
        # Parse ASN info
        asn_info = ASNInfo(
            asn=host.get("asn"),
            asn_org=host.get("org"),
            asn_country=host.get("country_code"),
        )
        
        # Parse services
        services = []
        for data in host.get("data", []):
            service = self._parse_service(data)
            services.append(service)
        
        # Get JARM if available
        jarm = None
        for data in host.get("data", []):
            if data.get("ssl", {}).get("jarm"):
                jarm = data["ssl"]["jarm"]
                break
        
        # Get favicon hashes
        favicon_hashes = []
        for data in host.get("data", []):
            if data.get("http", {}).get("favicon", {}).get("hash"):
                favicon_hashes.append(data["http"]["favicon"]["hash"])
        
        return Infrastructure(
            ip=host.get("ip_str"),
            geolocation=geo,
            asn_info=asn_info,
            hostnames=host.get("hostnames", []),
            services=services,
            jarm=jarm,
            favicon_hashes=favicon_hashes,
            tags=host.get("tags", []),
        )
    
    def _parse_service(self, data: dict) -> Service:
        """Parse a single service from Shodan data"""
        
        # Parse certificate if present
        cert = None
        ssl_data = data.get("ssl", {})
        if ssl_data:
            cert_data = ssl_data.get("cert", {})
            if cert_data:
                cert = Certificate(
                    fingerprint_sha256=cert_data.get("fingerprint", {}).get("sha256", ""),
                    fingerprint_sha1=cert_data.get("fingerprint", {}).get("sha1"),
                    serial_number=str(cert_data.get("serial")),
                    subject=CertificateSubject(
                        common_name=cert_data.get("subject", {}).get("CN"),
                        organization=cert_data.get("subject", {}).get("O"),
                        country=cert_data.get("subject", {}).get("C"),
                    ),
                    issuer=CertificateSubject(
                        common_name=cert_data.get("issuer", {}).get("CN"),
                        organization=cert_data.get("issuer", {}).get("O"),
                        country=cert_data.get("issuer", {}).get("C"),
                    ),
                    is_expired=cert_data.get("expired", False),
                )
        
        # Parse HTTP info
        http_data = data.get("http", {})
        
        return Service(
            port=data.get("port"),
            protocol=data.get("transport", "tcp"),
            service_name=data.get("_shodan", {}).get("module"),
            product=data.get("product"),
            version=data.get("version"),
            banner=data.get("data", "")[:500],  # Truncate banner
            certificate=cert,
            http_title=http_data.get("title"),
            http_server=http_data.get("server"),
            http_status=http_data.get("status"),
            favicon_hash=http_data.get("favicon", {}).get("hash"),
        )
    
    # =========================================================================
    # Search
    # =========================================================================
    
    async def search(
        self,
        query: str,
        limit: int = 100,
        page: int = 1,
        minify: bool = True,
    ) -> list[dict]:
        """
        Search Shodan with a query.
        
        Args:
            query: Shodan search query
            limit: Maximum results to return
            page: Page number for pagination
            minify: Return minimal data (faster)
            
        Returns:
            List of matching hosts
        """
        try:
            import asyncio
            loop = asyncio.get_event_loop()
            
            results = await loop.run_in_executor(
                None,
                lambda: self.api.search(query, page=page, limit=limit, minify=minify)
            )
            
            return results.get("matches", [])
            
        except shodan.APIError as e:
            logger.error(f"Shodan search error: {e}")
            raise
    
    async def search_count(self, query: str) -> int:
        """Get count of results for a query"""
        try:
            import asyncio
            loop = asyncio.get_event_loop()
            
            results = await loop.run_in_executor(
                None,
                lambda: self.api.count(query)
            )
            
            return results.get("total", 0)
            
        except shodan.APIError as e:
            logger.error(f"Shodan count error: {e}")
            raise
    
    # =========================================================================
    # Convenience Search Methods
    # =========================================================================
    
    async def search_jarm(self, jarm: str, limit: int = 100) -> list[dict]:
        """Search for hosts with a specific JARM fingerprint"""
        query = f'ssl.jarm:"{jarm}"'
        return await self.search(query, limit=limit)
    
    async def search_favicon(self, favicon_hash: int, limit: int = 100) -> list[dict]:
        """Search for hosts with a specific favicon hash"""
        query = f"http.favicon.hash:{favicon_hash}"
        return await self.search(query, limit=limit)
    
    async def search_cert_serial(self, serial: str, limit: int = 100) -> list[dict]:
        """Search for hosts with a specific certificate serial number"""
        query = f"ssl.cert.serial:{serial}"
        return await self.search(query, limit=limit)
    
    async def search_html_hash(self, html_hash: int, limit: int = 100) -> list[dict]:
        """Search for hosts with a specific HTML hash"""
        query = f"http.html_hash:{html_hash}"
        return await self.search(query, limit=limit)
    
    async def search_product(self, product: str, limit: int = 100) -> list[dict]:
        """Search for hosts running a specific product"""
        query = f'product:"{product}"'
        return await self.search(query, limit=limit)
    
    async def search_org(self, org: str, limit: int = 100) -> list[dict]:
        """Search for hosts in a specific organization"""
        query = f'org:"{org}"'
        return await self.search(query, limit=limit)
    
    async def search_asn(self, asn: int, limit: int = 100) -> list[dict]:
        """Search for hosts in a specific ASN"""
        query = f"asn:AS{asn}"
        return await self.search(query, limit=limit)
    
    # =========================================================================
    # C2 Hunting Queries
    # =========================================================================
    
    async def hunt_cobalt_strike(self, limit: int = 100) -> list[dict]:
        """Hunt for Cobalt Strike infrastructure"""
        queries = [
            'ssl.cert.serial:146473198',  # Default cert serial
            'ssl.jarm:"07d14d16d21d21d00042d41d00041de5fb3038e22f33f93c9a4ce6880e8b63"',
            'http.favicon.hash:-1018312697',  # Default favicon
        ]
        
        results = []
        for query in queries:
            try:
                matches = await self.search(query, limit=limit // len(queries))
                results.extend(matches)
            except Exception as e:
                logger.warning(f"Cobalt Strike hunt query failed: {e}")
        
        # Deduplicate by IP
        seen_ips = set()
        unique_results = []
        for result in results:
            ip = result.get("ip_str")
            if ip and ip not in seen_ips:
                seen_ips.add(ip)
                unique_results.append(result)
        
        return unique_results
    
    async def hunt_metasploit(self, limit: int = 100) -> list[dict]:
        """Hunt for Metasploit infrastructure"""
        queries = [
            'ssl.jarm:"07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1"',
            'http.favicon.hash:-127886975',
        ]
        
        results = []
        for query in queries:
            try:
                matches = await self.search(query, limit=limit // len(queries))
                results.extend(matches)
            except Exception as e:
                logger.warning(f"Metasploit hunt query failed: {e}")
        
        return self._deduplicate_results(results)
    
    async def hunt_open_directories(self, keywords: list[str] = None, limit: int = 100) -> list[dict]:
        """Hunt for open directories potentially hosting malware"""
        if keywords is None:
            keywords = ["mimikatz", "beacon", "payload", "shell"]
        
        results = []
        for keyword in keywords:
            query = f'http.html:"Index of /" http.html:"{keyword}"'
            try:
                matches = await self.search(query, limit=limit // len(keywords))
                results.extend(matches)
            except Exception as e:
                logger.warning(f"Open directory hunt failed: {e}")
        
        return self._deduplicate_results(results)
    
    def _deduplicate_results(self, results: list[dict]) -> list[dict]:
        """Deduplicate results by IP address"""
        seen_ips = set()
        unique = []
        for result in results:
            ip = result.get("ip_str")
            if ip and ip not in seen_ips:
                seen_ips.add(ip)
                unique.append(result)
        return unique
    
    # =========================================================================
    # DNS
    # =========================================================================
    
    async def dns_lookup(self, hostnames: list[str]) -> dict[str, str]:
        """Look up DNS for hostnames"""
        try:
            import asyncio
            loop = asyncio.get_event_loop()
            
            results = await loop.run_in_executor(
                None,
                lambda: self.api.dns.domain_info(hostnames)
            )
            
            return results
            
        except shodan.APIError as e:
            logger.error(f"Shodan DNS error: {e}")
            raise
    
    async def reverse_dns(self, ips: list[str]) -> dict[str, list[str]]:
        """Reverse DNS lookup for IPs"""
        try:
            import asyncio
            loop = asyncio.get_event_loop()
            
            results = await loop.run_in_executor(
                None,
                lambda: self.api.dns.reverse(ips)
            )
            
            return results
            
        except shodan.APIError as e:
            logger.error(f"Shodan reverse DNS error: {e}")
            raise


def build_shodan_query(**kwargs) -> str:
    """
    Build a Shodan query from keyword arguments.
    
    Args:
        jarm: JARM fingerprint
        favicon_hash: Favicon MurmurHash3
        cert_serial: SSL certificate serial number
        html_hash: HTTP HTML hash
        product: Product name
        org: Organization name
        asn: ASN number
        country: Country code
        port: Port number
        hostname: Hostname pattern
        exclude_orgs: List of organizations to exclude
        
    Returns:
        Shodan query string
    """
    parts = []
    
    if kwargs.get("jarm"):
        parts.append(f'ssl.jarm:"{kwargs["jarm"]}"')
    
    if kwargs.get("favicon_hash"):
        parts.append(f'http.favicon.hash:{kwargs["favicon_hash"]}')
    
    if kwargs.get("cert_serial"):
        parts.append(f'ssl.cert.serial:{kwargs["cert_serial"]}')
    
    if kwargs.get("html_hash"):
        parts.append(f'http.html_hash:{kwargs["html_hash"]}')
    
    if kwargs.get("product"):
        parts.append(f'product:"{kwargs["product"]}"')
    
    if kwargs.get("org"):
        parts.append(f'org:"{kwargs["org"]}"')
    
    if kwargs.get("asn"):
        parts.append(f'asn:AS{kwargs["asn"]}')
    
    if kwargs.get("country"):
        parts.append(f'country:{kwargs["country"]}')
    
    if kwargs.get("port"):
        parts.append(f'port:{kwargs["port"]}')
    
    if kwargs.get("hostname"):
        parts.append(f'hostname:{kwargs["hostname"]}')
    
    # Exclusions
    for org in kwargs.get("exclude_orgs", []):
        parts.append(f'-org:"{org}"')
    
    return " ".join(parts)
