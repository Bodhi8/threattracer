"""
ThreatTracer Certificate Fingerprinter

Extracts and analyzes X.509 certificates for threat hunting.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import socket
import ssl
from datetime import datetime
from typing import Optional

from threattracer.core.models import Certificate, CertificateSubject


logger = logging.getLogger(__name__)


class CertificateScanner:
    """
    X.509 certificate scanner and analyzer.
    """
    
    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
    
    async def scan(self, host: str, port: int = 443) -> Optional[Certificate]:
        """
        Scan a host and extract certificate information.
        """
        try:
            loop = asyncio.get_event_loop()
            cert_data = await loop.run_in_executor(None, self._get_certificate, host, port)
            
            if not cert_data:
                return None
            
            return self._parse_certificate(cert_data)
            
        except Exception as e:
            logger.debug(f"Certificate scan failed for {host}:{port}: {e}")
            return None
    
    def _get_certificate(self, host: str, port: int) -> Optional[dict]:
        """Get certificate from host (synchronous)"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    cert_dict = ssock.getpeercert()
                    
                    return {
                        "binary": cert,
                        "parsed": cert_dict,
                    }
        except Exception as e:
            logger.debug(f"Failed to get certificate from {host}:{port}: {e}")
            return None
    
    def _parse_certificate(self, cert_data: dict) -> Certificate:
        """Parse certificate data into Certificate model"""
        binary_cert = cert_data.get("binary", b"")
        parsed = cert_data.get("parsed", {})
        
        # Calculate fingerprints
        sha256_fp = hashlib.sha256(binary_cert).hexdigest()
        sha1_fp = hashlib.sha1(binary_cert).hexdigest()
        
        # Parse subject
        subject = self._parse_name(parsed.get("subject", ()))
        issuer = self._parse_name(parsed.get("issuer", ()))
        
        # Parse dates
        not_before = self._parse_date(parsed.get("notBefore"))
        not_after = self._parse_date(parsed.get("notAfter"))
        
        # Parse SANs
        san_dns = []
        san_ip = []
        san_email = []
        
        for san_type, san_value in parsed.get("subjectAltName", ()):
            if san_type == "DNS":
                san_dns.append(san_value)
            elif san_type == "IP Address":
                san_ip.append(san_value)
            elif san_type == "email":
                san_email.append(san_value)
        
        # Check properties
        is_self_signed = subject.common_name == issuer.common_name if subject and issuer else False
        is_expired = not_after < datetime.now() if not_after else False
        is_wildcard = any(cn.startswith("*.") for cn in [subject.common_name or ""] + san_dns)
        
        return Certificate(
            fingerprint_sha256=sha256_fp,
            fingerprint_sha1=sha1_fp,
            serial_number=str(parsed.get("serialNumber", "")),
            subject=subject,
            issuer=issuer,
            not_before=not_before,
            not_after=not_after,
            san_dns=san_dns,
            san_ip=san_ip,
            san_email=san_email,
            is_self_signed=is_self_signed,
            is_expired=is_expired,
            is_wildcard=is_wildcard,
        )
    
    def _parse_name(self, name_tuple: tuple) -> Optional[CertificateSubject]:
        """Parse X.509 name tuple into CertificateSubject"""
        if not name_tuple:
            return None
        
        name_dict = {}
        for rdn in name_tuple:
            for attr_type, attr_value in rdn:
                if attr_type == "commonName":
                    name_dict["common_name"] = attr_value
                elif attr_type == "organizationName":
                    name_dict["organization"] = attr_value
                elif attr_type == "organizationalUnitName":
                    name_dict["organizational_unit"] = attr_value
                elif attr_type == "countryName":
                    name_dict["country"] = attr_value
                elif attr_type == "stateOrProvinceName":
                    name_dict["state"] = attr_value
                elif attr_type == "localityName":
                    name_dict["locality"] = attr_value
        
        return CertificateSubject(**name_dict)
    
    def _parse_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """Parse certificate date string"""
        if not date_str:
            return None
        
        try:
            # Format: 'Mar  1 00:00:00 2023 GMT'
            return datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z")
        except ValueError:
            try:
                return datetime.strptime(date_str, "%b  %d %H:%M:%S %Y %Z")
            except ValueError:
                return None


# Known suspicious certificate patterns
SUSPICIOUS_CERT_PATTERNS = {
    "cobalt_strike_serial": "146473198",
    "metasploit_issuer": "MetasploitSelfSignedCA",
}


def analyze_certificate(cert: Certificate) -> dict:
    """Analyze a certificate for suspicious indicators"""
    findings = {
        "suspicious": False,
        "indicators": [],
        "known_match": None,
    }
    
    # Check for Cobalt Strike default serial
    if cert.serial_number == SUSPICIOUS_CERT_PATTERNS["cobalt_strike_serial"]:
        findings["suspicious"] = True
        findings["indicators"].append("Cobalt Strike default certificate serial")
        findings["known_match"] = "Cobalt Strike"
    
    # Check for self-signed
    if cert.is_self_signed:
        findings["indicators"].append("Self-signed certificate")
    
    # Check for expired
    if cert.is_expired:
        findings["indicators"].append("Expired certificate")
    
    # Check for suspicious subject fields
    if cert.subject:
        cn = cert.subject.common_name or ""
        org = cert.subject.organization or ""
        
        # Common C2 patterns
        suspicious_patterns = ["localhost", "test", "example", "default"]
        for pattern in suspicious_patterns:
            if pattern in cn.lower() or pattern in org.lower():
                findings["indicators"].append(f"Suspicious pattern in certificate: {pattern}")
    
    if len(findings["indicators"]) >= 2:
        findings["suspicious"] = True
    
    return findings


async def scan_certificate(host: str, port: int = 443, timeout: float = 10.0) -> Optional[Certificate]:
    """Convenience function to scan a host for its certificate"""
    scanner = CertificateScanner(timeout=timeout)
    return await scanner.scan(host, port)
