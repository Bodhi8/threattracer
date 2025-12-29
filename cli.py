"""
ThreatTracer CLI

Command-line interface for threat intelligence operations.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import print as rprint

from threattracer.core.config import load_config, create_example_config, set_config
from threattracer.core.models import Indicator, IndicatorType


console = Console()


# =============================================================================
# Main CLI Group
# =============================================================================

@click.group()
@click.option("--config", "-c", type=click.Path(exists=True), help="Path to config file")
@click.option("--debug/--no-debug", default=False, help="Enable debug output")
@click.version_option(version="0.1.0", prog_name="ThreatTracer")
@click.pass_context
def main(ctx, config: Optional[str], debug: bool):
    """
    ThreatTracer - Open-Source Threat Intelligence Platform
    
    Enrich indicators, hunt for infrastructure, and track threat actors.
    """
    ctx.ensure_object(dict)
    
    # Load configuration
    cfg = load_config(config)
    set_config(cfg)
    ctx.obj["config"] = cfg
    ctx.obj["debug"] = debug
    
    if debug:
        import logging
        logging.basicConfig(level=logging.DEBUG)


# =============================================================================
# Enrich Command
# =============================================================================

@main.group()
def enrich():
    """Enrich indicators with threat intelligence"""
    pass


@enrich.command("ip")
@click.argument("ip_address")
@click.option("--modules", "-m", default="all", help="Comma-separated list of modules (or 'all')")
@click.option("--format", "-f", "output_format", type=click.Choice(["table", "json"]), default="table")
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.pass_context
def enrich_ip(ctx, ip_address: str, modules: str, output_format: str, output: Optional[str]):
    """Enrich an IP address with threat intelligence"""
    asyncio.run(_enrich_ip(ctx, ip_address, modules, output_format, output))


async def _enrich_ip(ctx, ip_address: str, modules: str, output_format: str, output: Optional[str]):
    """Async implementation of IP enrichment"""
    from threattracer.enrichers.whois_enricher import WHOISEnricher
    from threattracer.enrichers.asn_enricher import ASNEnricher, GeoIPEnricher
    from threattracer.enrichers.virustotal_enricher import VirusTotalEnricher
    from threattracer.fingerprinters.jarm import scan_jarm
    from threattracer.fingerprinters.favicon import scan_favicon
    
    config = ctx.obj["config"]
    results = {"ip": ip_address, "enrichments": {}}
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        
        # Determine which modules to run
        if modules == "all":
            module_list = ["asn", "geoip", "jarm", "favicon"]
            if config.api_keys.virustotal:
                module_list.append("virustotal")
        else:
            module_list = [m.strip() for m in modules.split(",")]
        
        # ASN Enrichment
        if "asn" in module_list:
            task = progress.add_task("ASN lookup...", total=None)
            try:
                enricher = ASNEnricher(config)
                results["enrichments"]["asn"] = await enricher.enrich_ip(ip_address)
            except Exception as e:
                results["enrichments"]["asn"] = {"error": str(e)}
            progress.remove_task(task)
        
        # GeoIP Enrichment
        if "geoip" in module_list:
            task = progress.add_task("GeoIP lookup...", total=None)
            try:
                enricher = GeoIPEnricher(config)
                results["enrichments"]["geoip"] = await enricher.enrich_ip(ip_address)
            except Exception as e:
                results["enrichments"]["geoip"] = {"error": str(e)}
            progress.remove_task(task)
        
        # JARM Fingerprint
        if "jarm" in module_list:
            task = progress.add_task("JARM fingerprinting...", total=None)
            try:
                jarm_result = await scan_jarm(ip_address)
                if jarm_result:
                    results["enrichments"]["jarm"] = {
                        "fingerprint": jarm_result.fingerprint,
                        "cipher_hash": jarm_result.cipher_hash,
                        "extension_hash": jarm_result.extension_hash,
                    }
                    # Check known signatures
                    from threattracer.fingerprinters.jarm import lookup_jarm
                    known = lookup_jarm(jarm_result.fingerprint)
                    if known:
                        results["enrichments"]["jarm"]["known_match"] = known
                else:
                    results["enrichments"]["jarm"] = {"error": "No response"}
            except Exception as e:
                results["enrichments"]["jarm"] = {"error": str(e)}
            progress.remove_task(task)
        
        # Favicon Hash
        if "favicon" in module_list:
            task = progress.add_task("Favicon hashing...", total=None)
            try:
                favicon_result = await scan_favicon(ip_address)
                if favicon_result:
                    results["enrichments"]["favicon"] = {
                        "hash": favicon_result.hash,
                        "url": favicon_result.url,
                        "shodan_query": f"http.favicon.hash:{favicon_result.hash}",
                    }
                    # Check known hashes
                    from threattracer.fingerprinters.favicon import lookup_favicon_hash
                    known = lookup_favicon_hash(favicon_result.hash)
                    if known:
                        results["enrichments"]["favicon"]["known_match"] = known
                else:
                    results["enrichments"]["favicon"] = {"error": "No favicon found"}
            except Exception as e:
                results["enrichments"]["favicon"] = {"error": str(e)}
            progress.remove_task(task)
        
        # VirusTotal
        if "virustotal" in module_list and config.api_keys.virustotal:
            task = progress.add_task("VirusTotal lookup...", total=None)
            try:
                enricher = VirusTotalEnricher(config)
                results["enrichments"]["virustotal"] = await enricher.enrich_ip(ip_address)
            except Exception as e:
                results["enrichments"]["virustotal"] = {"error": str(e)}
            progress.remove_task(task)
    
    # Output results
    if output_format == "json":
        output_text = json.dumps(results, indent=2, default=str)
        if output:
            Path(output).write_text(output_text)
            console.print(f"[green]Results saved to {output}[/green]")
        else:
            print(output_text)
    else:
        _display_enrichment_table(results)
        if output:
            Path(output).write_text(json.dumps(results, indent=2, default=str))
            console.print(f"[green]Results also saved to {output}[/green]")


def _display_enrichment_table(results: dict):
    """Display enrichment results as a rich table"""
    ip = results.get("ip", "Unknown")
    
    console.print(Panel(f"[bold]Enrichment Results for {ip}[/bold]"))
    
    for module, data in results.get("enrichments", {}).items():
        if isinstance(data, dict) and "error" not in data:
            table = Table(title=f"[bold cyan]{module.upper()}[/bold cyan]", show_header=True)
            table.add_column("Field", style="cyan")
            table.add_column("Value", style="white")
            
            for key, value in data.items():
                if value is not None and value != "":
                    if isinstance(value, (dict, list)):
                        value = json.dumps(value, indent=2)
                    table.add_row(key, str(value)[:100])
            
            console.print(table)
            console.print()
        elif isinstance(data, dict) and "error" in data:
            console.print(f"[red]{module}: {data['error']}[/red]")


@enrich.command("domain")
@click.argument("domain")
@click.option("--modules", "-m", default="all", help="Comma-separated list of modules")
@click.option("--format", "-f", "output_format", type=click.Choice(["table", "json"]), default="table")
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.pass_context
def enrich_domain(ctx, domain: str, modules: str, output_format: str, output: Optional[str]):
    """Enrich a domain with threat intelligence"""
    asyncio.run(_enrich_domain(ctx, domain, modules, output_format, output))


async def _enrich_domain(ctx, domain: str, modules: str, output_format: str, output: Optional[str]):
    """Async implementation of domain enrichment"""
    from threattracer.enrichers.whois_enricher import WHOISEnricher
    from threattracer.enrichers.virustotal_enricher import VirusTotalEnricher
    
    config = ctx.obj["config"]
    results = {"domain": domain, "enrichments": {}}
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        
        # WHOIS
        task = progress.add_task("WHOIS lookup...", total=None)
        try:
            enricher = WHOISEnricher(config)
            results["enrichments"]["whois"] = await enricher.enrich_domain(domain)
        except Exception as e:
            results["enrichments"]["whois"] = {"error": str(e)}
        progress.remove_task(task)
        
        # VirusTotal
        if config.api_keys.virustotal:
            task = progress.add_task("VirusTotal lookup...", total=None)
            try:
                enricher = VirusTotalEnricher(config)
                results["enrichments"]["virustotal"] = await enricher.enrich_domain(domain)
            except Exception as e:
                results["enrichments"]["virustotal"] = {"error": str(e)}
            progress.remove_task(task)
    
    # Output
    if output_format == "json":
        output_text = json.dumps(results, indent=2, default=str)
        if output:
            Path(output).write_text(output_text)
        else:
            print(output_text)
    else:
        _display_enrichment_table(results)


# =============================================================================
# Hunt Command
# =============================================================================

@main.group()
def hunt():
    """Hunt for threat actor infrastructure"""
    pass


@hunt.command("jarm")
@click.argument("fingerprint")
@click.option("--limit", "-l", default=100, help="Maximum results")
@click.option("--format", "-f", "output_format", type=click.Choice(["table", "json"]), default="table")
@click.pass_context
def hunt_jarm(ctx, fingerprint: str, limit: int, output_format: str):
    """Hunt for infrastructure with a specific JARM fingerprint"""
    asyncio.run(_hunt_jarm(ctx, fingerprint, limit, output_format))


async def _hunt_jarm(ctx, fingerprint: str, limit: int, output_format: str):
    """Hunt for JARM matches"""
    from threattracer.scanners.shodan_scanner import ShodanScanner
    
    config = ctx.obj["config"]
    
    if not config.api_keys.shodan:
        console.print("[red]Error: Shodan API key not configured[/red]")
        return
    
    scanner = ShodanScanner(config)
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task(f"Searching Shodan for JARM {fingerprint[:20]}...", total=None)
        
        try:
            results = await scanner.search_jarm(fingerprint, limit=limit)
            progress.remove_task(task)
            
            if output_format == "json":
                print(json.dumps(results, indent=2))
            else:
                _display_hunt_results(results, f"JARM: {fingerprint[:30]}...")
                
        except Exception as e:
            progress.remove_task(task)
            console.print(f"[red]Error: {e}[/red]")


@hunt.command("favicon")
@click.argument("hash_value", type=int)
@click.option("--limit", "-l", default=100, help="Maximum results")
@click.option("--format", "-f", "output_format", type=click.Choice(["table", "json"]), default="table")
@click.pass_context
def hunt_favicon(ctx, hash_value: int, limit: int, output_format: str):
    """Hunt for infrastructure with a specific favicon hash"""
    asyncio.run(_hunt_favicon(ctx, hash_value, limit, output_format))


async def _hunt_favicon(ctx, hash_value: int, limit: int, output_format: str):
    """Hunt for favicon hash matches"""
    from threattracer.scanners.shodan_scanner import ShodanScanner
    
    config = ctx.obj["config"]
    
    if not config.api_keys.shodan:
        console.print("[red]Error: Shodan API key not configured[/red]")
        return
    
    scanner = ShodanScanner(config)
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task(f"Searching Shodan for favicon {hash_value}...", total=None)
        
        try:
            results = await scanner.search_favicon(hash_value, limit=limit)
            progress.remove_task(task)
            
            if output_format == "json":
                print(json.dumps(results, indent=2))
            else:
                _display_hunt_results(results, f"Favicon Hash: {hash_value}")
                
        except Exception as e:
            progress.remove_task(task)
            console.print(f"[red]Error: {e}[/red]")


def _display_hunt_results(results: list, title: str):
    """Display hunt results as a table"""
    console.print(Panel(f"[bold]Hunt Results: {title}[/bold]"))
    console.print(f"[green]Found {len(results)} results[/green]\n")
    
    if not results:
        return
    
    table = Table(show_header=True)
    table.add_column("IP", style="cyan")
    table.add_column("Port", style="white")
    table.add_column("Org", style="yellow")
    table.add_column("Country", style="white")
    table.add_column("Product", style="magenta")
    
    for result in results[:50]:  # Limit display
        table.add_row(
            result.get("ip_str", ""),
            str(result.get("port", "")),
            result.get("org", "")[:30] if result.get("org") else "",
            result.get("location", {}).get("country_code", ""),
            result.get("product", "")[:20] if result.get("product") else "",
        )
    
    console.print(table)
    
    if len(results) > 50:
        console.print(f"\n[dim]Showing 50 of {len(results)} results[/dim]")


# =============================================================================
# C2 Hunt Command
# =============================================================================

@main.command("c2hunt")
@click.argument("framework", required=False)
@click.option("--jarm", help="Custom JARM fingerprint")
@click.option("--favicon-hash", type=int, help="Custom favicon hash")
@click.option("--limit", "-l", default=100, help="Maximum results")
@click.option("--format", "-f", "output_format", type=click.Choice(["table", "json"]), default="table")
@click.pass_context
def c2hunt(ctx, framework: Optional[str], jarm: Optional[str], favicon_hash: Optional[int], 
           limit: int, output_format: str):
    """
    Hunt for C2 infrastructure.
    
    Frameworks: cobalt-strike, metasploit, mythic, sliver, havoc
    
    Examples:
    
        threattracer c2hunt cobalt-strike
        
        threattracer c2hunt --jarm "07d14d16d21d..."
    """
    asyncio.run(_c2hunt(ctx, framework, jarm, favicon_hash, limit, output_format))


async def _c2hunt(ctx, framework: Optional[str], jarm: Optional[str], favicon_hash: Optional[int],
                  limit: int, output_format: str):
    """Hunt for C2 infrastructure"""
    from threattracer.scanners.shodan_scanner import ShodanScanner
    
    config = ctx.obj["config"]
    
    if not config.api_keys.shodan:
        console.print("[red]Error: Shodan API key not configured[/red]")
        return
    
    scanner = ShodanScanner(config)
    results = []
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        
        if framework:
            framework = framework.lower()
            task = progress.add_task(f"Hunting for {framework}...", total=None)
            
            if framework in ("cobalt-strike", "cobaltstrike", "cs"):
                results = await scanner.hunt_cobalt_strike(limit=limit)
            elif framework in ("metasploit", "msf"):
                results = await scanner.hunt_metasploit(limit=limit)
            else:
                progress.remove_task(task)
                console.print(f"[yellow]Unknown framework: {framework}[/yellow]")
                console.print("Available: cobalt-strike, metasploit")
                return
            
            progress.remove_task(task)
        
        elif jarm:
            task = progress.add_task(f"Hunting JARM...", total=None)
            results = await scanner.search_jarm(jarm, limit=limit)
            progress.remove_task(task)
        
        elif favicon_hash:
            task = progress.add_task(f"Hunting favicon...", total=None)
            results = await scanner.search_favicon(favicon_hash, limit=limit)
            progress.remove_task(task)
        
        else:
            console.print("[yellow]Please specify a framework or fingerprint[/yellow]")
            return
    
    # Output
    if output_format == "json":
        print(json.dumps(results, indent=2))
    else:
        title = framework or f"Custom ({jarm or favicon_hash})"
        _display_hunt_results(results, title)


# =============================================================================
# Config Commands
# =============================================================================

@main.group()
def config():
    """Configuration management"""
    pass


@config.command("init")
@click.option("--output", "-o", default="config.yaml", help="Output file path")
def config_init(output: str):
    """Generate example configuration file"""
    example = create_example_config()
    Path(output).write_text(example)
    console.print(f"[green]Configuration template created: {output}[/green]")
    console.print("[yellow]Edit this file and add your API keys[/yellow]")


@config.command("check")
@click.pass_context
def config_check(ctx):
    """Check configuration and API key status"""
    config = ctx.obj["config"]
    
    console.print(Panel("[bold]Configuration Status[/bold]"))
    
    table = Table(show_header=True)
    table.add_column("Service", style="cyan")
    table.add_column("Status", style="white")
    
    services = [
        ("Shodan", config.api_keys.shodan),
        ("Censys ID", config.api_keys.censys_id),
        ("Censys Secret", config.api_keys.censys_secret),
        ("VirusTotal", config.api_keys.virustotal),
        ("SecurityTrails", config.api_keys.securitytrails),
        ("AbuseIPDB", config.api_keys.abuseipdb),
        ("AlienVault OTX", config.api_keys.otx),
    ]
    
    for name, key in services:
        if key:
            status = "[green]✓ Configured[/green]"
        else:
            status = "[red]✗ Not configured[/red]"
        table.add_row(name, status)
    
    console.print(table)


# =============================================================================
# Web/API Commands
# =============================================================================

@main.command("web")
@click.option("--host", "-h", default="127.0.0.1", help="Host to bind to")
@click.option("--port", "-p", default=8080, help="Port to bind to")
@click.option("--debug/--no-debug", default=False, help="Enable debug mode")
@click.pass_context
def web(ctx, host: str, port: int, debug: bool):
    """Start the web interface"""
    console.print(f"[green]Starting web interface at http://{host}:{port}[/green]")
    console.print("[yellow]Press Ctrl+C to stop[/yellow]")
    
    # Import and run Flask app
    try:
        from web.app import create_app
        app = create_app(ctx.obj["config"])
        app.run(host=host, port=port, debug=debug)
    except ImportError:
        console.print("[red]Web dependencies not installed. Run: pip install flask[/red]")


@main.command("api")
@click.option("--host", "-h", default="127.0.0.1", help="Host to bind to")
@click.option("--port", "-p", default=8000, help="Port to bind to")
@click.option("--reload/--no-reload", default=False, help="Enable auto-reload")
@click.pass_context
def api(ctx, host: str, port: int, reload: bool):
    """Start the REST API server"""
    console.print(f"[green]Starting API server at http://{host}:{port}[/green]")
    console.print(f"[cyan]API docs at http://{host}:{port}/docs[/cyan]")
    
    try:
        import uvicorn
        uvicorn.run(
            "threattracer.api.main:app",
            host=host,
            port=port,
            reload=reload,
        )
    except ImportError:
        console.print("[red]API dependencies not installed. Run: pip install uvicorn fastapi[/red]")


# =============================================================================
# Entry Point
# =============================================================================

if __name__ == "__main__":
    main()
