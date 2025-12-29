"""
ThreatTracer JARM Fingerprinter

Active TLS fingerprinting using JARM technique.
Based on https://github.com/salesforce/jarm
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import socket
import struct
from typing import Optional, Tuple
from datetime import datetime

from threattracer.core.models import JARMFingerprint


logger = logging.getLogger(__name__)


# JARM TLS Client Hello templates
# These are the 10 different probes JARM sends
JARM_PROBES = [
    # (TLS version, ciphers, extensions, description)
    (b"\x03\x01", "ALL", "1.2_FORWARD", "TLS 1.2 forward"),
    (b"\x03\x00", "ALL", "1.2_REVERSE", "TLS 1.2 reverse"),
    (b"\x03\x01", "ALL", "1.2_TOP_HALF", "TLS 1.2 top half"),
    (b"\x03\x01", "ALL", "1.2_BOTTOM_HALF", "TLS 1.2 bottom half"),
    (b"\x03\x01", "ALL", "1.2_MIDDLE_OUT", "TLS 1.2 middle out"),
    (b"\x03\x03", "1.3", "1.3_FORWARD", "TLS 1.3 forward"),
    (b"\x03\x03", "1.3", "1.3_REVERSE", "TLS 1.3 reverse"),
    (b"\x03\x03", "1.3", "1.3_INVALID", "TLS 1.3 invalid"),
    (b"\x03\x03", "1.3", "1.3_MIDDLE_OUT", "TLS 1.3 middle out"),
    (b"\x03\x01", "NO1.3", "1.2_NO_1.3", "TLS 1.2 no 1.3"),
]


# Cipher suites for different probe types
CIPHER_SUITES = {
    "ALL": bytes([
        0x00, 0x16, 0x00, 0x33, 0x00, 0x67, 0xc0, 0x9e, 0xc0, 0xa2, 0x00, 0x9e, 0x00, 0x39,
        0x00, 0x6b, 0xc0, 0x9f, 0xc0, 0xa3, 0x00, 0x9f, 0x00, 0x45, 0x00, 0xbe, 0x00, 0x88,
        0x00, 0xc4, 0x00, 0x9a, 0xc0, 0x08, 0xc0, 0x09, 0xc0, 0x23, 0xc0, 0xac, 0xc0, 0xae,
        0xc0, 0x2b, 0xc0, 0x0a, 0xc0, 0x24, 0xc0, 0xad, 0xc0, 0xaf, 0xc0, 0x2c, 0xc0, 0x72,
        0xc0, 0x73, 0xcc, 0xa9, 0x13, 0x02, 0x13, 0x01, 0xcc, 0x14, 0xcc, 0x13, 0xc0, 0x07,
        0xc0, 0x12, 0xc0, 0x13, 0xc0, 0x27, 0xc0, 0x2f, 0xc0, 0x14, 0xc0, 0x28, 0xc0, 0x30,
        0xc0, 0x60, 0xc0, 0x61, 0xc0, 0x76, 0xc0, 0x77, 0xcc, 0xa8, 0x13, 0x05, 0x13, 0x04,
        0x13, 0x03, 0xcc, 0xaa, 0x00, 0xff,
    ]),
    "1.3": bytes([
        0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0x13, 0x04, 0x13, 0x05, 0x00, 0xff,
    ]),
    "NO1.3": bytes([
        0x00, 0x16, 0x00, 0x33, 0x00, 0x67, 0xc0, 0x9e, 0xc0, 0xa2, 0x00, 0x9e, 0x00, 0x39,
        0x00, 0x6b, 0xc0, 0x9f, 0xc0, 0xa3, 0x00, 0x9f, 0x00, 0x45, 0x00, 0xbe, 0x00, 0x88,
        0x00, 0xc4, 0x00, 0x9a, 0xc0, 0x08, 0xc0, 0x09, 0xc0, 0x23, 0xc0, 0xac, 0xc0, 0xae,
        0xc0, 0x2b, 0xc0, 0x0a, 0xc0, 0x24, 0xc0, 0xad, 0xc0, 0xaf, 0xc0, 0x2c, 0xc0, 0x72,
        0xc0, 0x73, 0xcc, 0xa9, 0xcc, 0x14, 0xcc, 0x13, 0xc0, 0x07, 0xc0, 0x12, 0xc0, 0x13,
        0xc0, 0x27, 0xc0, 0x2f, 0xc0, 0x14, 0xc0, 0x28, 0xc0, 0x30, 0xc0, 0x60, 0xc0, 0x61,
        0xc0, 0x76, 0xc0, 0x77, 0xcc, 0xa8, 0xcc, 0xaa, 0x00, 0xff,
    ]),
}


class JARMScanner:
    """
    JARM fingerprint scanner.
    
    JARM sends 10 specially crafted TLS Client Hello packets
    and analyzes the Server Hello responses to create a
    62-character fingerprint.
    """
    
    def __init__(self, timeout: float = 20.0):
        self.timeout = timeout
    
    async def scan(self, host: str, port: int = 443) -> Optional[JARMFingerprint]:
        """
        Perform JARM scan on a host.
        
        Args:
            host: Target hostname or IP
            port: Target port (default 443)
            
        Returns:
            JARMFingerprint object or None if scan fails
        """
        results = []
        
        for i, (version, cipher_type, ext_type, desc) in enumerate(JARM_PROBES):
            try:
                result = await self._send_probe(host, port, version, cipher_type, ext_type)
                results.append(result)
            except Exception as e:
                logger.debug(f"JARM probe {i} failed for {host}:{port}: {e}")
                results.append("|||")
        
        # Calculate JARM fingerprint
        fingerprint = self._calculate_jarm(results)
        
        if fingerprint == "0" * 62:
            # All probes failed
            return None
        
        return JARMFingerprint(
            fingerprint=fingerprint,
            cipher_hash=fingerprint[:30],
            extension_hash=fingerprint[30:],
            scan_time=datetime.now(),
            port=port,
        )
    
    async def _send_probe(
        self,
        host: str,
        port: int,
        version: bytes,
        cipher_type: str,
        ext_type: str
    ) -> str:
        """Send a single JARM probe and parse the response"""
        
        # Build Client Hello
        client_hello = self._build_client_hello(host, version, cipher_type, ext_type)
        
        # Send probe
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            self._send_packet,
            host,
            port,
            client_hello
        )
        
        if not response:
            return "|||"
        
        # Parse Server Hello
        return self._parse_server_hello(response, ext_type)
    
    def _build_client_hello(
        self,
        host: str,
        version: bytes,
        cipher_type: str,
        ext_type: str
    ) -> bytes:
        """Build a TLS Client Hello packet"""
        
        # This is a simplified implementation
        # Full implementation would match the exact JARM specification
        
        # Record layer
        content_type = b"\x16"  # Handshake
        record_version = b"\x03\x01"  # TLS 1.0
        
        # Handshake header
        handshake_type = b"\x01"  # Client Hello
        
        # Client Hello body
        client_version = version
        random = b"\x00" * 32  # Random bytes
        session_id = b"\x00"  # Empty session ID
        
        # Cipher suites
        ciphers = CIPHER_SUITES.get(cipher_type, CIPHER_SUITES["ALL"])
        cipher_len = struct.pack(">H", len(ciphers))
        
        # Compression methods
        compression = b"\x01\x00"  # NULL compression
        
        # Extensions
        extensions = self._build_extensions(host, ext_type)
        extensions_len = struct.pack(">H", len(extensions))
        
        # Build Client Hello body
        client_hello_body = (
            client_version +
            random +
            session_id +
            cipher_len + ciphers +
            compression +
            extensions_len + extensions
        )
        
        # Handshake layer
        handshake_len = struct.pack(">I", len(client_hello_body))[1:]  # 3 bytes
        handshake = handshake_type + handshake_len + client_hello_body
        
        # Record layer
        record_len = struct.pack(">H", len(handshake))
        record = content_type + record_version + record_len + handshake
        
        return record
    
    def _build_extensions(self, host: str, ext_type: str) -> bytes:
        """Build TLS extensions based on probe type"""
        extensions = b""
        
        # SNI extension
        host_bytes = host.encode()
        sni_data = struct.pack(">H", len(host_bytes) + 3) + b"\x00" + struct.pack(">H", len(host_bytes)) + host_bytes
        extensions += struct.pack(">HH", 0x0000, len(sni_data)) + sni_data
        
        # Supported versions (for TLS 1.3)
        if "1.3" in ext_type:
            supported_versions = b"\x03\x03\x04\x03\x03"  # TLS 1.3, 1.2
            extensions += struct.pack(">HH", 0x002b, len(supported_versions)) + supported_versions
        
        # Signature algorithms
        sig_algs = bytes([
            0x00, 0x10,  # Length
            0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02, 0x03,
            0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01,
        ])
        extensions += struct.pack(">HH", 0x000d, len(sig_algs)) + sig_algs
        
        # Supported groups
        groups = bytes([0x00, 0x04, 0x00, 0x1d, 0x00, 0x17])  # x25519, secp256r1
        extensions += struct.pack(">HH", 0x000a, len(groups)) + groups
        
        return extensions
    
    def _send_packet(self, host: str, port: int, data: bytes) -> Optional[bytes]:
        """Send packet and receive response (synchronous)"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            sock.sendall(data)
            
            # Receive response
            response = b""
            while True:
                try:
                    chunk = sock.recv(1484)
                    if not chunk:
                        break
                    response += chunk
                    # Check if we have complete Server Hello
                    if len(response) >= 5:
                        record_len = struct.unpack(">H", response[3:5])[0]
                        if len(response) >= record_len + 5:
                            break
                except socket.timeout:
                    break
            
            sock.close()
            return response if response else None
            
        except Exception as e:
            logger.debug(f"Socket error for {host}:{port}: {e}")
            return None
    
    def _parse_server_hello(self, response: bytes, ext_type: str) -> str:
        """Parse Server Hello response and extract fingerprint components"""
        try:
            if len(response) < 5:
                return "|||"
            
            # Check for Server Hello (handshake type 0x02)
            if response[0] != 0x16:  # Not handshake
                return "|||"
            
            # Get TLS version from record layer
            record_version = f"{response[1]:x}{response[2]:x}"
            
            # Parse handshake
            if len(response) < 44:
                return "|||"
            
            # Server version (in handshake)
            server_version = f"{response[9]:x}{response[10]:x}"
            
            # Cipher suite (after 32-byte random + session ID)
            session_id_len = response[43]
            cipher_offset = 44 + session_id_len
            
            if len(response) < cipher_offset + 2:
                return "|||"
            
            cipher_suite = f"{response[cipher_offset]:02x}{response[cipher_offset+1]:02x}"
            
            # Build result string
            return f"{cipher_suite}|{server_version}|"
            
        except Exception as e:
            logger.debug(f"Failed to parse Server Hello: {e}")
            return "|||"
    
    def _calculate_jarm(self, results: list[str]) -> str:
        """Calculate final JARM fingerprint from probe results"""
        
        # First 30 characters: fuzzy hash of cipher and version info
        cipher_string = "".join(results)
        
        # Simple hash for cipher portion (real JARM uses custom fuzzy hash)
        cipher_hash = hashlib.sha256(cipher_string.encode()).hexdigest()[:30]
        
        # Last 32 characters: SHA256 of extension data
        extension_string = "".join(r.split("|")[-1] if "|" in r else "" for r in results)
        extension_hash = hashlib.sha256(extension_string.encode()).hexdigest()[:32]
        
        return cipher_hash + extension_hash


# Known JARM signatures for common C2 frameworks
KNOWN_JARM_SIGNATURES = {
    # Cobalt Strike
    "07d14d16d21d21d00042d41d00041de5fb3038e22f33f93c9a4ce6880e8b63": {
        "name": "Cobalt Strike",
        "confidence": "high",
        "notes": "Default Cobalt Strike configuration (Java)"
    },
    "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1": {
        "name": "Metasploit",
        "confidence": "high",
        "notes": "Default Metasploit configuration"
    },
    "2ad2ad0002ad2ad00042d42d000000ad9bf51cc3f5a1e29eecb81d0c7b06eb": {
        "name": "Mythic",
        "confidence": "high",
        "notes": "Mythic C2 framework"
    },
    "2ad2ad16d2ad2ad22c42d42d00042d58c7162162b6a603d3d90a2b76865b53": {
        "name": "Sliver",
        "confidence": "high",
        "notes": "Sliver C2 framework"
    },
    "29d21b20d29d29d21c42d43d00041d44609a5a9a88e797f466e878a82e8365": {
        "name": "Havoc",
        "confidence": "medium",
        "notes": "Havoc C2 framework"
    },
}


def lookup_jarm(fingerprint: str) -> Optional[dict]:
    """Look up a JARM fingerprint in the known signatures database"""
    return KNOWN_JARM_SIGNATURES.get(fingerprint.lower())


async def scan_jarm(host: str, port: int = 443, timeout: float = 20.0) -> Optional[JARMFingerprint]:
    """
    Convenience function to scan a host for JARM fingerprint.
    
    Args:
        host: Target hostname or IP
        port: Target port
        timeout: Connection timeout
        
    Returns:
        JARMFingerprint or None
    """
    scanner = JARMScanner(timeout=timeout)
    return await scanner.scan(host, port)
