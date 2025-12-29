"""
ThreatTracer Base Enricher

Abstract base class for all enrichment modules.
"""

from __future__ import annotations

import asyncio
import logging
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Any, Optional, Type

import httpx

from threattracer.core.config import Config, get_config
from threattracer.core.models import (
    Indicator,
    IndicatorType,
    IPIndicator,
    DomainIndicator,
)


logger = logging.getLogger(__name__)


class EnricherError(Exception):
    """Base exception for enricher errors"""
    pass


class RateLimitError(EnricherError):
    """Raised when rate limit is exceeded"""
    pass


class AuthenticationError(EnricherError):
    """Raised when authentication fails"""
    pass


class BaseEnricher(ABC):
    """
    Abstract base class for all enrichment modules.
    
    Subclasses must implement at least one of:
    - enrich_ip()
    - enrich_domain()
    
    Example:
        class MyEnricher(BaseEnricher):
            name = "my_enricher"
            supported_types = [IndicatorType.IP, IndicatorType.DOMAIN]
            required_config = ["api_key"]
            
            async def enrich_ip(self, ip: str) -> dict:
                # Your implementation
                return {"data": "value"}
    """
    
    # Module identification
    name: str = "base"
    description: str = "Base enricher"
    version: str = "1.0.0"
    
    # Capabilities
    supported_types: list[IndicatorType] = []
    required_config: list[str] = []  # Required config keys
    
    # Rate limiting
    requests_per_minute: int = 60
    
    def __init__(self, config: Optional[Config] = None):
        self.config = config or get_config()
        self._client: Optional[httpx.AsyncClient] = None
        self._last_request_time: Optional[datetime] = None
        self._request_count: int = 0
        
        # Validate configuration
        self._validate_config()
    
    def _validate_config(self) -> None:
        """Validate that required configuration is present"""
        for key in self.required_config:
            # Check in api_keys section
            if hasattr(self.config.api_keys, key):
                value = getattr(self.config.api_keys, key)
                if not value:
                    logger.warning(f"{self.name}: Missing required config: {key}")
    
    @property
    def client(self) -> httpx.AsyncClient:
        """Get or create HTTP client"""
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self.config.enricher.timeout_seconds,
                follow_redirects=True,
            )
        return self._client
    
    async def close(self) -> None:
        """Close HTTP client"""
        if self._client:
            await self._client.aclose()
            self._client = None
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
    
    # =========================================================================
    # Rate Limiting
    # =========================================================================
    
    async def _check_rate_limit(self) -> None:
        """Check and enforce rate limiting"""
        if not self.config.rate_limit.enabled:
            return
        
        now = datetime.now()
        
        if self._last_request_time:
            elapsed = (now - self._last_request_time).total_seconds()
            
            # Reset counter after a minute
            if elapsed >= 60:
                self._request_count = 0
                self._last_request_time = now
            
            # Check if we've exceeded rate limit
            if self._request_count >= self.requests_per_minute:
                wait_time = 60 - elapsed
                if wait_time > 0:
                    logger.debug(f"{self.name}: Rate limit reached, waiting {wait_time:.1f}s")
                    await asyncio.sleep(wait_time)
                    self._request_count = 0
        else:
            self._last_request_time = now
        
        self._request_count += 1
    
    # =========================================================================
    # HTTP Helpers
    # =========================================================================
    
    async def _get(
        self,
        url: str,
        params: Optional[dict] = None,
        headers: Optional[dict] = None,
        **kwargs
    ) -> httpx.Response:
        """Make a GET request with rate limiting"""
        await self._check_rate_limit()
        
        try:
            response = await self.client.get(url, params=params, headers=headers, **kwargs)
            response.raise_for_status()
            return response
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:
                raise RateLimitError(f"{self.name}: Rate limit exceeded")
            elif e.response.status_code in (401, 403):
                raise AuthenticationError(f"{self.name}: Authentication failed")
            raise EnricherError(f"{self.name}: HTTP error: {e}")
        except httpx.RequestError as e:
            raise EnricherError(f"{self.name}: Request failed: {e}")
    
    async def _post(
        self,
        url: str,
        data: Optional[dict] = None,
        json: Optional[dict] = None,
        headers: Optional[dict] = None,
        **kwargs
    ) -> httpx.Response:
        """Make a POST request with rate limiting"""
        await self._check_rate_limit()
        
        try:
            response = await self.client.post(
                url, data=data, json=json, headers=headers, **kwargs
            )
            response.raise_for_status()
            return response
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 429:
                raise RateLimitError(f"{self.name}: Rate limit exceeded")
            elif e.response.status_code in (401, 403):
                raise AuthenticationError(f"{self.name}: Authentication failed")
            raise EnricherError(f"{self.name}: HTTP error: {e}")
        except httpx.RequestError as e:
            raise EnricherError(f"{self.name}: Request failed: {e}")
    
    # =========================================================================
    # Main Enrichment Methods
    # =========================================================================
    
    async def enrich(self, indicator: Indicator) -> dict[str, Any]:
        """
        Main entry point for enrichment.
        
        Routes to appropriate method based on indicator type.
        """
        if indicator.type not in self.supported_types:
            raise EnricherError(
                f"{self.name} does not support indicator type: {indicator.type}"
            )
        
        try:
            if indicator.type == IndicatorType.IP:
                return await self.enrich_ip(indicator.value)
            elif indicator.type == IndicatorType.DOMAIN:
                return await self.enrich_domain(indicator.value)
            elif indicator.type == IndicatorType.URL:
                return await self.enrich_url(indicator.value)
            elif indicator.type in (
                IndicatorType.HASH_MD5,
                IndicatorType.HASH_SHA1,
                IndicatorType.HASH_SHA256
            ):
                return await self.enrich_hash(indicator.value, indicator.type)
            else:
                raise EnricherError(f"Unsupported indicator type: {indicator.type}")
        except EnricherError:
            raise
        except Exception as e:
            logger.exception(f"{self.name}: Error enriching {indicator.value}")
            raise EnricherError(f"{self.name}: {str(e)}")
    
    async def enrich_ip(self, ip: str) -> dict[str, Any]:
        """
        Enrich an IP address indicator.
        
        Override this method in subclasses.
        """
        raise NotImplementedError(f"{self.name} does not support IP enrichment")
    
    async def enrich_domain(self, domain: str) -> dict[str, Any]:
        """
        Enrich a domain indicator.
        
        Override this method in subclasses.
        """
        raise NotImplementedError(f"{self.name} does not support domain enrichment")
    
    async def enrich_url(self, url: str) -> dict[str, Any]:
        """
        Enrich a URL indicator.
        
        Override this method in subclasses.
        """
        raise NotImplementedError(f"{self.name} does not support URL enrichment")
    
    async def enrich_hash(self, hash_value: str, hash_type: IndicatorType) -> dict[str, Any]:
        """
        Enrich a file hash indicator.
        
        Override this method in subclasses.
        """
        raise NotImplementedError(f"{self.name} does not support hash enrichment")
    
    # =========================================================================
    # Utility Methods
    # =========================================================================
    
    def is_configured(self) -> bool:
        """Check if all required configuration is present"""
        for key in self.required_config:
            if hasattr(self.config.api_keys, key):
                value = getattr(self.config.api_keys, key)
                if not value:
                    return False
        return True
    
    def get_api_key(self, key_name: str) -> Optional[str]:
        """Get an API key from configuration"""
        if hasattr(self.config.api_keys, key_name):
            return getattr(self.config.api_keys, key_name)
        return None


class EnricherRegistry:
    """Registry of available enricher modules"""
    
    _enrichers: dict[str, Type[BaseEnricher]] = {}
    
    @classmethod
    def register(cls, enricher_class: Type[BaseEnricher]) -> Type[BaseEnricher]:
        """Register an enricher class"""
        cls._enrichers[enricher_class.name] = enricher_class
        return enricher_class
    
    @classmethod
    def get(cls, name: str) -> Optional[Type[BaseEnricher]]:
        """Get an enricher class by name"""
        return cls._enrichers.get(name)
    
    @classmethod
    def get_all(cls) -> dict[str, Type[BaseEnricher]]:
        """Get all registered enrichers"""
        return cls._enrichers.copy()
    
    @classmethod
    def get_for_type(cls, indicator_type: IndicatorType) -> list[Type[BaseEnricher]]:
        """Get all enrichers that support a given indicator type"""
        return [
            e for e in cls._enrichers.values()
            if indicator_type in e.supported_types
        ]


def enricher(cls: Type[BaseEnricher]) -> Type[BaseEnricher]:
    """Decorator to register an enricher"""
    return EnricherRegistry.register(cls)
