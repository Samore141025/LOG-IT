"""Threat Intelligence enrichment module.

Analyzes external IP addresses against reputation data, bogon/private filters,
and threat lists to enrich log events and security findings.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import urllib.request
import json
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# Sample known high-risk IP ranges/indicators for fast offline enrichment
KNOWN_THREAT_INDICATORS: Dict[str, Dict[str, Any]] = {
    "104.192.3.34": {
        "abuse_score": 95,
        "country": "CN",
        "category": "SSH Brute-Force Botnet",
        "isp": "Known Malicious Bulletproof Hosting",
    },
    "103.99.0.122": {
        "abuse_score": 90,
        "country": "HK",
        "category": "Automated Scanner",
        "isp": "Cloud Hosting Gateway",
    },
    "185.220.101.5": {
        "abuse_score": 85,
        "country": "DE",
        "category": "Tor Exit Node",
        "isp": "Tor Anonymizing Relay",
    },
}


class ThreatIntelEnricher:
    """Enriches IP addresses with reputation scores, geolocational data, and threat classifications."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("ABUSEIPDB_API_KEY")
        self._cache: Dict[str, Dict[str, Any]] = {}

    def is_private_or_internal(self, ip_str: str) -> bool:
        """Return True if the IP is localhost, loopback, private RFC 1918, or multicast."""
        try:
            ip = ipaddress.ip_address(ip_str.strip())
            return ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local
        except ValueError:
            return False

    def enrich_ip(self, ip_str: str) -> Dict[str, Any]:
        """Provide detailed threat intelligence for a given IP."""
        clean_ip = ip_str.strip()
        if clean_ip in self._cache:
            return self._cache[clean_ip]

        # Check if internal / private
        if self.is_private_or_internal(clean_ip):
            res = {
                "ip": clean_ip,
                "is_internal": True,
                "reputation_score": 0,
                "threat_level": "CLEAN",
                "category": "Private / Internal Subnet",
                "country": "INTERNAL",
            }
            self._cache[clean_ip] = res
            return res

        # Check offline known indicators first
        if clean_ip in KNOWN_THREAT_INDICATORS:
            info = KNOWN_THREAT_INDICATORS[clean_ip]
            res = {
                "ip": clean_ip,
                "is_internal": False,
                "reputation_score": info["abuse_score"],
                "threat_level": "MALICIOUS" if info["abuse_score"] >= 80 else "SUSPICIOUS",
                "category": info["category"],
                "country": info["country"],
                "isp": info.get("isp", "Unknown ISP"),
            }
            self._cache[clean_ip] = res
            return res

        # Online query if ABUSEIPDB_API_KEY is available
        if self.api_key:
            try:
                url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={clean_ip}&maxAgeInDays=90"
                req = urllib.request.Request(
                    url,
                    headers={
                        "Key": self.api_key,
                        "Accept": "application/json",
                        "User-Agent": "LOG-IT-Sentinel/1.0",
                    },
                )
                with urllib.request.urlopen(req, timeout=3.0) as response:
                    if response.status == 200:
                        raw = json.loads(response.read().decode("utf-8"))
                        data = raw.get("data", {})
                        score = data.get("abuseConfidenceScore", 0)
                        res = {
                            "ip": clean_ip,
                            "is_internal": False,
                            "reputation_score": score,
                            "threat_level": "MALICIOUS" if score >= 80 else "SUSPICIOUS" if score >= 20 else "CLEAN",
                            "category": "AbuseIPDB Verified Threat" if score >= 50 else "Standard External Traffic",
                            "country": data.get("countryCode", "UNKNOWN"),
                            "isp": data.get("isp", "Unknown ISP"),
                        }
                        self._cache[clean_ip] = res
                        return res
            except Exception as e:
                logger.debug(f"Threat intel API check skipped for {clean_ip}: {e}")

        # Default fallback for unknown external IP
        res = {
            "ip": clean_ip,
            "is_internal": False,
            "reputation_score": 10,
            "threat_level": "NEUTRAL",
            "category": "External Host",
            "country": "UNKNOWN",
        }
        self._cache[clean_ip] = res
        return res
