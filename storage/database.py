"""ThreatTracer Storage Layer - SQLite-based storage for IOCs and infrastructure."""

from __future__ import annotations
import json
from datetime import datetime
from typing import Any, Optional
from sqlalchemy import create_engine, Column, String, Integer, DateTime, Text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.future import select
from threattracer.core.config import get_config

Base = declarative_base()

class IndicatorRecord(Base):
    __tablename__ = "indicators"
    id = Column(Integer, primary_key=True, autoincrement=True)
    value = Column(String(255), nullable=False, index=True)
    type = Column(String(50), nullable=False, index=True)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    threat_level = Column(String(20), default="unknown")
    tags = Column(Text, default="[]")
    enrichment_data = Column(Text, default="{}")

class InfrastructureRecord(Base):
    __tablename__ = "infrastructure"
    id = Column(Integer, primary_key=True, autoincrement=True)
    ip = Column(String(45), nullable=False, index=True)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    country_code = Column(String(10), nullable=True)
    asn = Column(Integer, nullable=True, index=True)
    asn_org = Column(String(255), nullable=True)
    jarm = Column(String(62), nullable=True, index=True)
    favicon_hash = Column(Integer, nullable=True, index=True)
    threat_level = Column(String(20), default="unknown")
    services_data = Column(Text, default="[]")

class DatabaseManager:
    def __init__(self, db_path: Optional[str] = None):
        config = get_config()
        self.db_path = db_path or config.database.path
        self.engine = None
        self.async_session = None
    
    async def initialize(self):
        db_url = f"sqlite+aiosqlite:///{self.db_path}"
        self.engine = create_async_engine(db_url, echo=False)
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        self.async_session = sessionmaker(self.engine, class_=AsyncSession, expire_on_commit=False)
    
    async def close(self):
        if self.engine:
            await self.engine.dispose()
    
    async def add_indicator(self, value: str, indicator_type: str, threat_level: str = "unknown", enrichment_data: dict = None):
        async with self.async_session() as session:
            record = IndicatorRecord(value=value, type=indicator_type, threat_level=threat_level, enrichment_data=json.dumps(enrichment_data or {}))
            session.add(record)
            await session.commit()
            return record
    
    async def add_infrastructure(self, ip: str, jarm: str = None, favicon_hash: int = None, asn: int = None):
        async with self.async_session() as session:
            record = InfrastructureRecord(ip=ip, jarm=jarm, favicon_hash=favicon_hash, asn=asn)
            session.add(record)
            await session.commit()
            return record

class MemoryCache:
    def __init__(self, ttl_seconds: int = 3600):
        self.ttl = ttl_seconds
        self._cache: dict[str, tuple[datetime, Any]] = {}
    
    def get(self, key: str) -> Optional[Any]:
        if key in self._cache:
            timestamp, value = self._cache[key]
            if (datetime.now() - timestamp).total_seconds() < self.ttl:
                return value
        return None
    
    def set(self, key: str, value: Any) -> None:
        self._cache[key] = (datetime.now(), value)

_cache: Optional[MemoryCache] = None

def get_cache() -> MemoryCache:
    global _cache
    if _cache is None:
        _cache = MemoryCache()
    return _cache
