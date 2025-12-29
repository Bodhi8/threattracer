"""
ThreatTracer REST API

FastAPI-based REST API for threat intelligence operations.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from threattracer.core.config import get_config, Config
from threattracer.core.models import IndicatorType, ThreatLevel, Confidence


# =============================================================================
# Request/Response Models
# =============================================================================

class EnrichRequest(BaseModel):
    indicator: str
    type: IndicatorType
    modules: list[str] = Field(default_factory=lambda: ["all"])


class EnrichResponse(BaseModel):
    indicator: str
    type: IndicatorType
    enriched_at: datetime
    modules: dict[str, Any]
    threat_level: Optional[ThreatLevel] = None
    errors: dict[str, str] = Field(default_factory=dict)


class HuntRequest(BaseModel):
    seed: dict[str, Any]
    pivots: list[str] = Field(default_factory=lambda: ["jarm", "favicon"])
    max_results: int = Field(default=100, ge=1, le=1000)
    exclude_orgs: list[str] = Field(default_factory=list)


class HuntResponse(BaseModel):
    hunt_id: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    status: str
    total_results: int
    results: list[dict[str, Any]]


class SearchRequest(BaseModel):
    platform: str
    query: str
    limit: int = Field(default=100, ge=1, le=1000)


class FingerprintRequest(BaseModel):
    target: str
    port: int = 443
    types: list[str] = Field(default_factory=lambda: ["jarm", "favicon"])


class HealthResponse(BaseModel):
    status: str
    version: str
    timestamp: datetime
    services: dict[str, bool]


# =============================================================================
# Dependencies
# =============================================================================

def get_app_config() -> Config:
    return get_config()


# =============================================================================
# Application
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    yield

app = FastAPI(
    title="ThreatTracer API",
    description="Open-Source Threat Intelligence & IP Tracing Platform",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =============================================================================
# Health Endpoints
# =============================================================================

@app.get("/", tags=["Info"])
async def root():
    return {"name": "ThreatTracer API", "version": "0.1.0", "docs": "/docs"}


@app.get("/health", response_model=HealthResponse, tags=["Info"])
async def health_check(config: Config = Depends(get_app_config)):
    return HealthResponse(
        status="healthy",
        version="0.1.0",
        timestamp=datetime.now(),
        services={
            "shodan": bool(config.api_keys.shodan),
            "virustotal": bool(config.api_keys.virustotal),
            "censys": bool(config.api_keys.censys_id),
        }
    )


# =============================================================================
# Enrichment Endpoints
# =============================================================================

@app.post("/api/v1/enrich", response_model=EnrichResponse, tags=["Enrichment"])
async def enrich_indicator(request: EnrichRequest, config: Config = Depends(get_app_config)):
    from threattracer.enrichers.whois_enricher import WHOISEnricher
    from threattracer.enrichers.asn_enricher import ASNEnricher, GeoIPEnricher
    from threattracer.enrichers.virustotal_enricher import VirusTotalEnricher
    from threattracer.fingerprinters.jarm import scan_jarm, lookup_jarm
    from threattracer.fingerprinters.favicon import scan_favicon, lookup_favicon_hash
    
    modules_to_run = request.modules
    if "all" in modules_to_run:
        if request.type == IndicatorType.IP:
            modules_to_run = ["asn", "geoip", "virustotal", "jarm", "favicon"]
        elif request.type == IndicatorType.DOMAIN:
            modules_to_run = ["whois", "virustotal"]
    
    results = {}
    errors = {}
    
    if request.type == IndicatorType.IP:
        if "asn" in modules_to_run:
            try:
                enricher = ASNEnricher(config)
                results["asn"] = await enricher.enrich_ip(request.indicator)
            except Exception as e:
                errors["asn"] = str(e)
        
        if "geoip" in modules_to_run:
            try:
                enricher = GeoIPEnricher(config)
                results["geoip"] = await enricher.enrich_ip(request.indicator)
            except Exception as e:
                errors["geoip"] = str(e)
        
        if "jarm" in modules_to_run:
            try:
                jarm_result = await scan_jarm(request.indicator)
                if jarm_result:
                    results["jarm"] = {
                        "fingerprint": jarm_result.fingerprint,
                        "known_match": lookup_jarm(jarm_result.fingerprint),
                    }
            except Exception as e:
                errors["jarm"] = str(e)
        
        if "favicon" in modules_to_run:
            try:
                favicon_result = await scan_favicon(request.indicator)
                if favicon_result:
                    results["favicon"] = {
                        "hash": favicon_result.hash,
                        "known_match": lookup_favicon_hash(favicon_result.hash),
                    }
            except Exception as e:
                errors["favicon"] = str(e)
    
    if request.type == IndicatorType.DOMAIN:
        if "whois" in modules_to_run:
            try:
                enricher = WHOISEnricher(config)
                results["whois"] = await enricher.enrich_domain(request.indicator)
            except Exception as e:
                errors["whois"] = str(e)
    
    if "virustotal" in modules_to_run and config.api_keys.virustotal:
        try:
            enricher = VirusTotalEnricher(config)
            if request.type == IndicatorType.IP:
                results["virustotal"] = await enricher.enrich_ip(request.indicator)
            elif request.type == IndicatorType.DOMAIN:
                results["virustotal"] = await enricher.enrich_domain(request.indicator)
        except Exception as e:
            errors["virustotal"] = str(e)
    
    threat_level = ThreatLevel.UNKNOWN
    vt_data = results.get("virustotal", {})
    if vt_data.get("threat_level"):
        threat_level = ThreatLevel(vt_data["threat_level"])
    
    return EnrichResponse(
        indicator=request.indicator,
        type=request.type,
        enriched_at=datetime.now(),
        modules=results,
        threat_level=threat_level,
        errors=errors,
    )


@app.get("/api/v1/enrich/ip/{ip}", tags=["Enrichment"])
async def enrich_ip_quick(ip: str, modules: str = "asn,geoip", config: Config = Depends(get_app_config)):
    request = EnrichRequest(indicator=ip, type=IndicatorType.IP, modules=modules.split(","))
    return await enrich_indicator(request, config)


@app.get("/api/v1/enrich/domain/{domain}", tags=["Enrichment"])
async def enrich_domain_quick(domain: str, modules: str = "whois", config: Config = Depends(get_app_config)):
    request = EnrichRequest(indicator=domain, type=IndicatorType.DOMAIN, modules=modules.split(","))
    return await enrich_indicator(request, config)


# =============================================================================
# Fingerprinting Endpoints
# =============================================================================

@app.post("/api/v1/fingerprint", tags=["Fingerprinting"])
async def fingerprint_target(request: FingerprintRequest):
    from threattracer.fingerprinters.jarm import scan_jarm, lookup_jarm
    from threattracer.fingerprinters.favicon import scan_favicon, lookup_favicon_hash
    
    fingerprints = {}
    known_matches = []
    
    if "jarm" in request.types:
        try:
            result = await scan_jarm(request.target, request.port)
            if result:
                fingerprints["jarm"] = result.fingerprint
                known = lookup_jarm(result.fingerprint)
                if known:
                    known_matches.append({"type": "jarm", **known})
        except Exception as e:
            fingerprints["jarm_error"] = str(e)
    
    if "favicon" in request.types:
        try:
            result = await scan_favicon(request.target, request.port)
            if result:
                fingerprints["favicon"] = result.hash
                known = lookup_favicon_hash(result.hash)
                if known:
                    known_matches.append({"type": "favicon", **known})
        except Exception as e:
            fingerprints["favicon_error"] = str(e)
    
    return {
        "target": request.target,
        "port": request.port,
        "fingerprints": fingerprints,
        "known_matches": known_matches,
    }


@app.get("/api/v1/fingerprint/jarm/{target}", tags=["Fingerprinting"])
async def get_jarm(target: str, port: int = 443):
    from threattracer.fingerprinters.jarm import scan_jarm, lookup_jarm
    
    result = await scan_jarm(target, port)
    if not result:
        raise HTTPException(status_code=404, detail="Could not get JARM fingerprint")
    
    return {
        "target": target,
        "port": port,
        "jarm": result.fingerprint,
        "known_match": lookup_jarm(result.fingerprint),
    }


@app.get("/api/v1/fingerprint/favicon/{target}", tags=["Fingerprinting"])
async def get_favicon(target: str, port: int = 443):
    from threattracer.fingerprinters.favicon import scan_favicon, lookup_favicon_hash
    
    result = await scan_favicon(target, port)
    if not result:
        raise HTTPException(status_code=404, detail="Could not get favicon")
    
    return {
        "target": target,
        "port": port,
        "favicon_hash": result.hash,
        "shodan_query": f"http.favicon.hash:{result.hash}",
        "known_match": lookup_favicon_hash(result.hash),
    }


# =============================================================================
# Search Endpoints
# =============================================================================

@app.post("/api/v1/search", tags=["Search"])
async def search_platform(request: SearchRequest, config: Config = Depends(get_app_config)):
    if request.platform.lower() == "shodan":
        if not config.api_keys.shodan:
            raise HTTPException(status_code=400, detail="Shodan API key not configured")
        
        from threattracer.scanners.shodan_scanner import ShodanScanner
        scanner = ShodanScanner(config)
        
        try:
            results = await scanner.search(request.query, limit=request.limit)
            total = await scanner.search_count(request.query)
            return {"platform": "shodan", "query": request.query, "total": total, "results": results}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    raise HTTPException(status_code=400, detail=f"Unknown platform: {request.platform}")


@app.get("/api/v1/search/shodan", tags=["Search"])
async def search_shodan_quick(query: str, limit: int = 100, config: Config = Depends(get_app_config)):
    request = SearchRequest(platform="shodan", query=query, limit=limit)
    return await search_platform(request, config)


# =============================================================================
# Hunt Endpoints
# =============================================================================

@app.post("/api/v1/hunt", response_model=HuntResponse, tags=["Hunting"])
async def hunt_infrastructure(request: HuntRequest, config: Config = Depends(get_app_config)):
    import uuid
    from threattracer.scanners.shodan_scanner import ShodanScanner
    
    hunt_id = str(uuid.uuid4())[:8]
    started_at = datetime.now()
    all_results = []
    
    seed_ip = request.seed.get("ip")
    seed_jarm = request.seed.get("jarm")
    seed_favicon = request.seed.get("favicon_hash")
    
    if not config.api_keys.shodan:
        raise HTTPException(status_code=400, detail="Shodan API key required")
    
    scanner = ShodanScanner(config)
    
    if seed_ip and not seed_jarm and "jarm" in request.pivots:
        from threattracer.fingerprinters.jarm import scan_jarm
        jarm_result = await scan_jarm(seed_ip)
        if jarm_result:
            seed_jarm = jarm_result.fingerprint
    
    if seed_ip and not seed_favicon and "favicon" in request.pivots:
        from threattracer.fingerprinters.favicon import scan_favicon
        favicon_result = await scan_favicon(seed_ip)
        if favicon_result:
            seed_favicon = favicon_result.hash
    
    if seed_jarm and "jarm" in request.pivots:
        try:
            results = await scanner.search_jarm(seed_jarm, limit=request.max_results)
            for r in results:
                r["pivot_type"] = "jarm"
            all_results.extend(results)
        except Exception:
            pass
    
    if seed_favicon and "favicon" in request.pivots:
        try:
            results = await scanner.search_favicon(seed_favicon, limit=request.max_results)
            for r in results:
                r["pivot_type"] = "favicon"
            all_results.extend(results)
        except Exception:
            pass
    
    seen_ips = set()
    unique_results = []
    for r in all_results:
        ip = r.get("ip_str")
        if ip and ip not in seen_ips:
            seen_ips.add(ip)
            unique_results.append(r)
    
    if request.exclude_orgs:
        unique_results = [
            r for r in unique_results
            if not any(org.lower() in (r.get("org") or "").lower() for org in request.exclude_orgs)
        ]
    
    return HuntResponse(
        hunt_id=hunt_id,
        started_at=started_at,
        completed_at=datetime.now(),
        status="completed",
        total_results=len(unique_results),
        results=unique_results[:request.max_results],
    )


# =============================================================================
# C2 Hunting Endpoints
# =============================================================================

@app.get("/api/v1/c2/hunt/{framework}", tags=["C2 Hunting"])
async def hunt_c2_framework(framework: str, limit: int = 100, config: Config = Depends(get_app_config)):
    if not config.api_keys.shodan:
        raise HTTPException(status_code=400, detail="Shodan API key required")
    
    from threattracer.scanners.shodan_scanner import ShodanScanner
    scanner = ShodanScanner(config)
    
    framework = framework.lower()
    
    if framework in ("cobalt-strike", "cobaltstrike", "cs"):
        results = await scanner.hunt_cobalt_strike(limit=limit)
    elif framework in ("metasploit", "msf"):
        results = await scanner.hunt_metasploit(limit=limit)
    else:
        raise HTTPException(status_code=400, detail=f"Unknown framework: {framework}")
    
    return {"framework": framework, "total": len(results), "results": results}


# =============================================================================
# Lookup Endpoints
# =============================================================================

@app.get("/api/v1/lookup/jarm/{fingerprint}", tags=["Lookups"])
async def lookup_jarm_signature(fingerprint: str):
    from threattracer.fingerprinters.jarm import lookup_jarm, KNOWN_JARM_SIGNATURES
    result = lookup_jarm(fingerprint)
    return {"fingerprint": fingerprint, "match": result, "known_count": len(KNOWN_JARM_SIGNATURES)}


@app.get("/api/v1/lookup/favicon/{hash_value}", tags=["Lookups"])
async def lookup_favicon_signature(hash_value: int):
    from threattracer.fingerprinters.favicon import lookup_favicon_hash, KNOWN_FAVICON_HASHES
    result = lookup_favicon_hash(hash_value)
    return {"hash": hash_value, "match": result, "known_count": len(KNOWN_FAVICON_HASHES)}


@app.get("/api/v1/signatures/jarm", tags=["Lookups"])
async def list_known_jarm_signatures():
    from threattracer.fingerprinters.jarm import KNOWN_JARM_SIGNATURES
    return {"signatures": KNOWN_JARM_SIGNATURES}


@app.get("/api/v1/signatures/favicon", tags=["Lookups"])
async def list_known_favicon_hashes():
    from threattracer.fingerprinters.favicon import KNOWN_FAVICON_HASHES
    return {"hashes": KNOWN_FAVICON_HASHES}
