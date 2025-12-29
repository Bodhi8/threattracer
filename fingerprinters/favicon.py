"""
ThreatTracer Favicon Hash Fingerprinter

Calculates MurmurHash3 favicon hashes compatible with Shodan.
"""

from __future__ import annotations

import base64
import logging
import re
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx
import mmh3

from threattracer.core.models import FaviconHash


logger = logging.getLogger(__name__)


class FaviconScanner:
    """
    Favicon hash scanner.
    
    Calculates MurmurHash3 hashes of favicons compatible with
    Shodan's http.favicon.hash search filter.
    """
    
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None
    
    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self.timeout,
                follow_redirects=True,
                verify=False,  # Some C2s have invalid certs
            )
        return self._client
    
    async def close(self):
        if self._client:
            await self._client.aclose()
            self._client = None
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
    
    async def scan(self, target: str, port: int = 443) -> Optional[FaviconHash]:
        """
        Scan a target for its favicon and calculate the hash.
        
        Args:
            target: Hostname or IP address
            port: Target port
            
        Returns:
            FaviconHash object or None if favicon not found
        """
        # Try HTTPS first, then HTTP
        schemes = ["https"] if port == 443 else ["http"]
        if port == 80:
            schemes = ["http"]
        elif port not in (80, 443):
            schemes = ["https", "http"]
        
        for scheme in schemes:
            base_url = f"{scheme}://{target}:{port}"
            
            # Method 1: Try /favicon.ico directly
            result = await self._fetch_favicon(f"{base_url}/favicon.ico")
            if result:
                return result
            
            # Method 2: Parse HTML for favicon link
            result = await self._find_favicon_in_html(base_url)
            if result:
                return result
        
        return None
    
    async def scan_url(self, url: str) -> Optional[FaviconHash]:
        """
        Scan a specific URL for its favicon.
        
        Args:
            url: Full URL to scan
            
        Returns:
            FaviconHash object or None
        """
        parsed = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Method 1: Try /favicon.ico
        result = await self._fetch_favicon(f"{base_url}/favicon.ico")
        if result:
            return result
        
        # Method 2: Parse HTML
        return await self._find_favicon_in_html(base_url)
    
    async def hash_url(self, favicon_url: str) -> Optional[FaviconHash]:
        """
        Directly hash a favicon from a URL.
        
        Args:
            favicon_url: Direct URL to favicon
            
        Returns:
            FaviconHash object or None
        """
        return await self._fetch_favicon(favicon_url)
    
    async def _fetch_favicon(self, url: str) -> Optional[FaviconHash]:
        """Fetch and hash a favicon from URL"""
        try:
            response = await self.client.get(url)
            
            if response.status_code != 200:
                return None
            
            content_type = response.headers.get("content-type", "")
            
            # Verify it looks like an image
            valid_types = ["image/", "application/octet-stream"]
            if not any(t in content_type.lower() for t in valid_types):
                # Check if content looks like an image
                if not self._looks_like_image(response.content):
                    return None
            
            # Calculate hash
            favicon_hash = self.calculate_hash(response.content)
            
            return FaviconHash(
                hash=favicon_hash,
                url=url,
                content_type=content_type,
                size_bytes=len(response.content),
            )
            
        except Exception as e:
            logger.debug(f"Failed to fetch favicon from {url}: {e}")
            return None
    
    async def _find_favicon_in_html(self, base_url: str) -> Optional[FaviconHash]:
        """Parse HTML to find favicon link"""
        try:
            response = await self.client.get(base_url)
            
            if response.status_code != 200:
                return None
            
            html = response.text
            
            # Look for favicon link tags
            patterns = [
                r'<link[^>]*rel=["\'](?:shortcut )?icon["\'][^>]*href=["\']([^"\']+)["\']',
                r'<link[^>]*href=["\']([^"\']+)["\'][^>]*rel=["\'](?:shortcut )?icon["\']',
                r'<link[^>]*rel=["\']apple-touch-icon["\'][^>]*href=["\']([^"\']+)["\']',
            ]
            
            for pattern in patterns:
                match = re.search(pattern, html, re.IGNORECASE)
                if match:
                    favicon_path = match.group(1)
                    favicon_url = urljoin(base_url, favicon_path)
                    result = await self._fetch_favicon(favicon_url)
                    if result:
                        return result
            
            return None
            
        except Exception as e:
            logger.debug(f"Failed to parse HTML from {base_url}: {e}")
            return None
    
    def _looks_like_image(self, content: bytes) -> bool:
        """Check if content appears to be an image based on magic bytes"""
        if len(content) < 4:
            return False
        
        # Common image magic bytes
        magic_bytes = [
            b"\x00\x00\x01\x00",  # ICO
            b"\x89PNG",  # PNG
            b"\xff\xd8\xff",  # JPEG
            b"GIF8",  # GIF
            b"RIFF",  # WEBP (starts with RIFF)
            b"<svg",  # SVG
        ]
        
        for magic in magic_bytes:
            if content.startswith(magic):
                return True
        
        return False
    
    @staticmethod
    def calculate_hash(content: bytes) -> int:
        """
        Calculate Shodan-compatible favicon hash.
        
        Shodan uses MurmurHash3 on base64-encoded content
        with newlines inserted every 76 characters (RFC 2045).
        
        Args:
            content: Raw favicon bytes
            
        Returns:
            MurmurHash3 hash value
        """
        # Step 1: Base64 encode
        b64_data = base64.b64encode(content)
        
        # Step 2: Convert to string
        b64_string = b64_data.decode("utf-8")
        
        # Step 3: Insert newlines every 76 characters (RFC 2045 MIME)
        # Also add trailing newline
        with_newlines = re.sub("(.{76})", "\\1\n", b64_string, 0, re.DOTALL)
        if not with_newlines.endswith("\n"):
            with_newlines += "\n"
        
        # Step 4: Calculate MurmurHash3
        return mmh3.hash(with_newlines)
    
    @staticmethod
    def calculate_hash_from_file(filepath: str) -> int:
        """Calculate hash from a local file"""
        with open(filepath, "rb") as f:
            content = f.read()
        return FaviconScanner.calculate_hash(content)


# Known favicon hashes for common C2 frameworks and tools
KNOWN_FAVICON_HASHES = {
    -1018312697: {
        "name": "Cobalt Strike",
        "confidence": "high",
        "notes": "Default Cobalt Strike favicon"
    },
    -127886975: {
        "name": "Metasploit",
        "confidence": "high",
        "notes": "Default Metasploit favicon"
    },
    298876636: {
        "name": "Empire",
        "confidence": "high",
        "notes": "PowerShell Empire favicon"
    },
    1982692064: {
        "name": "Mythic",
        "confidence": "high",
        "notes": "Mythic C2 favicon"
    },
    -1957161625: {
        "name": "Brute Ratel C4",
        "confidence": "high",
        "notes": "Brute Ratel C4 favicon"
    },
    116323821: {
        "name": "Covenant",
        "confidence": "high",
        "notes": "Covenant C2 favicon"
    },
    -305179312: {
        "name": "Gophish",
        "confidence": "medium",
        "notes": "Gophish phishing framework"
    },
    -941272559: {
        "name": "Evilginx",
        "confidence": "medium",
        "notes": "Evilginx phishing framework"
    },
}


def lookup_favicon_hash(hash_value: int) -> Optional[dict]:
    """Look up a favicon hash in the known hashes database"""
    return KNOWN_FAVICON_HASHES.get(hash_value)


async def scan_favicon(target: str, port: int = 443, timeout: float = 10.0) -> Optional[FaviconHash]:
    """
    Convenience function to scan a target for its favicon hash.
    
    Args:
        target: Hostname or IP
        port: Target port
        timeout: Connection timeout
        
    Returns:
        FaviconHash or None
    """
    async with FaviconScanner(timeout=timeout) as scanner:
        return await scanner.scan(target, port)


def calculate_favicon_hash(content: bytes) -> int:
    """
    Calculate Shodan-compatible favicon hash from raw bytes.
    
    Args:
        content: Raw favicon image bytes
        
    Returns:
        MurmurHash3 hash value
    """
    return FaviconScanner.calculate_hash(content)
