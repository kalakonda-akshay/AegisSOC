"""
AegisSOC Threat Intelligence - Core Types and IOC Classification
Supports IP addresses, domains, URLs, and cryptographic file hashes.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import re
from typing import Any, Dict, List, Optional


# Regex patterns for deterministic IOC type classification
IPV4_PATTERN = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
IPV6_PATTERN = re.compile(r"^(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}$", re.IGNORECASE)
MD5_PATTERN = re.compile(r"^[a-fA-F0-9]{32}$")
SHA1_PATTERN = re.compile(r"^[a-fA-F0-9]{40}$")
SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")
URL_PATTERN = re.compile(r"^(?:https?|ftp)://[^\s/$.?#].[^\s]*$", re.IGNORECASE)
DOMAIN_PATTERN = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")


def detect_ioc_type(indicator: str) -> str:
    """
    Automatically classifies an indicator string into an IOC type:
    'ip', 'domain', 'url', 'hash', or 'unknown'.
    """
    ind = indicator.strip()

    # 1. IP Addresses (IPv4 or IPv6)
    if IPV4_PATTERN.match(ind) or IPV6_PATTERN.match(ind):
        return "ip"

    # 2. Cryptographic File Hashes (MD5, SHA-1, SHA-256)
    if MD5_PATTERN.match(ind) or SHA1_PATTERN.match(ind) or SHA256_PATTERN.match(ind):
        return "hash"

    # 3. URLs
    if URL_PATTERN.match(ind) or ind.startswith(("http://", "https://", "ftp://")):
        return "url"

    # 4. Domains / FQDNs
    if DOMAIN_PATTERN.match(ind):
        return "domain"

    return "unknown"


@dataclass
class ThreatIntelResult:
    """Normalized threat intelligence record returned across all providers."""
    indicator: str
    indicator_type: str
    verdict: str  # 'Clean', 'Suspicious', 'Malicious', 'Unknown'
    reputation_score: int  # 0 to 100
    is_malicious: bool
    threat_types: List[str] = field(default_factory=list)
    asn: Optional[str] = None
    country_code: Optional[str] = None
    organization: Optional[str] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    source_provider: str = "AegisSOC Intelligence Engine"
    cache_hit: bool = False
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
