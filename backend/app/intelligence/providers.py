"""
AegisSOC Threat Intelligence - Provider Abstraction & Vendor Clients
Supports VirusTotal, AbuseIPDB, AlienVault OTX, and a rich deterministic simulation provider.
"""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
import hashlib
import os
from typing import Any, Dict, List, Optional
import httpx

from app.core.logging import logger
from app.intelligence.types import ThreatIntelResult, detect_ioc_type


class ThreatIntelProvider(ABC):
    """Abstract base class for external and internal threat intelligence feeds."""

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    def is_available(self) -> bool:
        pass

    @abstractmethod
    def lookup(self, indicator: str, indicator_type: str) -> Optional[ThreatIntelResult]:
        pass


class VirusTotalProvider(ThreatIntelProvider):
    """Integration for VirusTotal API v3."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("VIRUSTOTAL_API_KEY", "")

    @property
    def name(self) -> str:
        return "VirusTotal"

    def is_available(self) -> bool:
        return bool(self.api_key and self.api_key.strip())

    def lookup(self, indicator: str, indicator_type: str) -> Optional[ThreatIntelResult]:
        if not self.is_available():
            return None

        endpoint_map = {
            "ip": f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}",
            "domain": f"https://www.virustotal.com/api/v3/domains/{indicator}",
            "hash": f"https://www.virustotal.com/api/v3/files/{indicator}"
        }
        url = endpoint_map.get(indicator_type)
        if not url:
            return None

        headers = {"x-apikey": self.api_key}
        try:
            with httpx.Client(timeout=10.0) as client:
                res = client.get(url, headers=headers)
                if res.status_code != 200:
                    return None
                data = res.json().get("data", {}).get("attributes", {})

                stats = data.get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                total = sum(stats.values()) or 1
                score = int(min(100, ((malicious * 2 + suspicious) / total) * 100))

                verdict = "Malicious" if score >= 75 else ("Suspicious" if score >= 40 else "Clean")
                if malicious == 0 and suspicious == 0:
                    verdict = "Clean"

                return ThreatIntelResult(
                    indicator=indicator,
                    indicator_type=indicator_type,
                    verdict=verdict,
                    reputation_score=score,
                    is_malicious=(verdict == "Malicious"),
                    threat_types=[cat for cat in data.get("categories", {}).values() if cat != "harmless"],
                    asn=str(data.get("asn", "")),
                    country_code=str(data.get("country", "")),
                    organization=str(data.get("as_owner", "")),
                    source_provider=self.name,
                    attributes={"reputation": data.get("reputation", 0), "tags": data.get("tags", [])}
                )
        except Exception as e:
            logger.warning(f"VirusTotal lookup error for {indicator}: {e}")
            return None


class AbuseIPDBProvider(ThreatIntelProvider):
    """Integration for AbuseIPDB check API."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.environ.get("ABUSEIPDB_API_KEY", "")

    @property
    def name(self) -> str:
        return "AbuseIPDB"

    def is_available(self) -> bool:
        return bool(self.api_key and self.api_key.strip())

    def lookup(self, indicator: str, indicator_type: str) -> Optional[ThreatIntelResult]:
        if not self.is_available() or indicator_type != "ip":
            return None

        url = "https://api.abuseipdb.com/api/v2/check"
        params = {"ipAddress": indicator, "maxAgeInDays": 90, "verbose": True}
        headers = {"Key": self.api_key, "Accept": "application/json"}

        try:
            with httpx.Client(timeout=10.0) as client:
                res = client.get(url, params=params, headers=headers)
                if res.status_code != 200:
                    return None
                item = res.json().get("data", {})
                score = int(item.get("abuseConfidenceScore", 0))

                verdict = "Malicious" if score >= 75 else ("Suspicious" if score >= 40 else "Clean")

                return ThreatIntelResult(
                    indicator=indicator,
                    indicator_type="ip",
                    verdict=verdict,
                    reputation_score=score,
                    is_malicious=(verdict == "Malicious"),
                    threat_types=["Reported Abuse"] if score >= 40 else [],
                    asn=f"AS{item.get('asn', '')}",
                    country_code=item.get("countryCode"),
                    organization=item.get("isp"),
                    last_seen=item.get("lastReportedAt"),
                    source_provider=self.name,
                    attributes={"total_reports": item.get("totalReports", 0)}
                )
        except Exception as e:
            logger.warning(f"AbuseIPDB lookup error for {indicator}: {e}")
            return None


class SimulatedThreatIntelProvider(ThreatIntelProvider):
    """
    Deterministic threat intelligence database for offline SOC testing,
    providing high-fidelity intelligence for IPs, Domains, URLs, and Hashes.
    """

    KNOWN_INDICATORS = {
        # 1. Malicious IP Addresses
        "185.45.103.91": {
            "type": "ip", "score": 94, "verdict": "Malicious",
            "threats": ["Botnet C2", "Brute Force Source"], "asn": "AS48031", "country": "RU", "org": "Bulwark Hosting",
            "first_seen": "2026-09-10T14:22:00Z", "last_seen": "2026-11-23T22:30:00Z"
        },
        "194.26.29.112": {
            "type": "ip", "score": 88, "verdict": "Malicious",
            "threats": ["Cobalt Strike Beacon", "C2 Infrastructure"], "asn": "AS206264", "country": "NL", "org": "Amarutu Technology",
            "first_seen": "2026-10-01T08:15:00Z", "last_seen": "2026-11-23T20:12:00Z"
        },
        "45.132.224.50": {
            "type": "ip", "score": 85, "verdict": "Malicious",
            "threats": ["Port Scanner", "Mirai Variant"], "asn": "AS44477", "country": "SC", "org": "Stark Industries",
            "first_seen": "2026-10-18T19:00:00Z", "last_seen": "2026-11-23T18:45:00Z"
        },
        "198.51.100.42": {
            "type": "ip", "score": 82, "verdict": "Malicious",
            "threats": ["C2 Listener", "Metasploit Default Port"], "asn": "AS64496", "country": "US", "org": "TestNet External",
            "first_seen": "2026-11-01T12:00:00Z", "last_seen": "2026-11-23T21:00:00Z"
        },
        # Suspicious IPs
        "203.0.113.88": {
            "type": "ip", "score": 58, "verdict": "Suspicious",
            "threats": ["Reconnaissance Probe"], "asn": "AS64500", "country": "JP", "org": "Tokyo Cloud Node",
            "first_seen": "2026-11-20T10:00:00Z", "last_seen": "2026-11-23T16:00:00Z"
        },
        # Clean IPs
        "8.8.8.8": {
            "type": "ip", "score": 0, "verdict": "Clean",
            "threats": [], "asn": "AS15169", "country": "US", "org": "Google Public DNS",
            "first_seen": "2010-01-01T00:00:00Z", "last_seen": "2026-11-23T22:00:00Z"
        },
        "10.0.0.10": {
            "type": "ip", "score": 0, "verdict": "Clean",
            "threats": [], "asn": "AS-INTERNAL", "country": "LOCAL", "org": "SOC Bastion Perimeter",
            "first_seen": "2026-01-01T00:00:00Z", "last_seen": "2026-11-23T22:00:00Z"
        },

        # 2. Domains
        "c2-controller-update.net": {
            "type": "domain", "score": 96, "verdict": "Malicious",
            "threats": ["Command and Control", "DGA Family 4"], "asn": "AS48031", "country": "RU", "org": "Adversary Domain Hosting",
            "first_seen": "2026-11-10T02:00:00Z", "last_seen": "2026-11-23T19:00:00Z"
        },
        "auth-phish-portal.live": {
            "type": "domain", "score": 92, "verdict": "Malicious",
            "threats": ["Credential Phishing", "MFA Interceptor"], "asn": "AS16276", "country": "US", "org": "Phish Host",
            "first_seen": "2026-11-14T05:22:00Z", "last_seen": "2026-11-23T21:30:00Z"
        },
        "free-cloud-sync-tool.info": {
            "type": "domain", "score": 64, "verdict": "Suspicious",
            "threats": ["Dynamic DNS", "Uncategorized Downloader"], "asn": "AS206264", "country": "NL", "org": "Free DNS Host",
            "first_seen": "2026-11-19T11:00:00Z", "last_seen": "2026-11-23T14:00:00Z"
        },
        "google.com": {
            "type": "domain", "score": 0, "verdict": "Clean",
            "threats": [], "asn": "AS15169", "country": "US", "org": "Google LLC",
            "first_seen": "1997-09-15T00:00:00Z", "last_seen": "2026-11-23T22:00:00Z"
        },

        # 3. URLs
        "http://185.45.103.91/stage2.bin": {
            "type": "url", "score": 98, "verdict": "Malicious",
            "threats": ["Raw Binary Dropper", "Cobalt Strike Payload"], "asn": "AS48031", "country": "RU", "org": "Bulwark Hosting",
            "first_seen": "2026-11-21T03:00:00Z", "last_seen": "2026-11-23T20:00:00Z"
        },
        "https://auth-phish-portal.live/login": {
            "type": "url", "score": 94, "verdict": "Malicious",
            "threats": ["Credential Harvester Form"], "asn": "AS16276", "country": "US", "org": "Phish Host",
            "first_seen": "2026-11-22T08:00:00Z", "last_seen": "2026-11-23T21:00:00Z"
        },
        "http://unknown-server.ru/test.php": {
            "type": "url", "score": 60, "verdict": "Suspicious",
            "threats": ["Potential Web Shell"], "asn": "AS48031", "country": "RU", "org": "External Host",
            "first_seen": "2026-11-20T12:00:00Z", "last_seen": "2026-11-23T10:00:00Z"
        },

        # 4. Cryptographic File Hashes
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {
            "type": "hash", "score": 98, "verdict": "Malicious",
            "threats": ["LockBit Ransomware Cryptor", "Trojan.Win64.LockBit"], "asn": None, "country": None, "org": None,
            "first_seen": "2026-10-12T16:00:00Z", "last_seen": "2026-11-23T18:00:00Z"
        },
        "44d88612fea8a8f36de82e1278abb02f": {
            "type": "hash", "score": 90, "verdict": "Malicious",
            "threats": ["Mimikatz Memory Injector", "HackTool.Win32.Mimikatz"], "asn": None, "country": None, "org": None,
            "first_seen": "2026-11-05T09:30:00Z", "last_seen": "2026-11-23T15:00:00Z"
        },
        "a1b2c3d4e5f67890123456789abcdef012345678": {
            "type": "hash", "score": 65, "verdict": "Suspicious",
            "threats": ["Obfuscated PowerShell Script"], "asn": None, "country": None, "org": None,
            "first_seen": "2026-11-21T00:00:00Z", "last_seen": "2026-11-23T12:00:00Z"
        }
    }

    @property
    def name(self) -> str:
        return "AegisSOC Threat Intelligence Feed (Simulated)"

    def is_available(self) -> bool:
        return True

    def lookup(self, indicator: str, indicator_type: str) -> Optional[ThreatIntelResult]:
        entry = self.KNOWN_INDICATORS.get(indicator)
        now_iso = datetime.now(timezone.utc).isoformat()

        if entry:
            return ThreatIntelResult(
                indicator=indicator,
                indicator_type=entry["type"],
                verdict=entry["verdict"],
                reputation_score=entry["score"],
                is_malicious=(entry["verdict"] == "Malicious"),
                threat_types=entry["threats"],
                asn=entry["asn"],
                country_code=entry["country"],
                organization=entry["org"],
                first_seen=entry["first_seen"],
                last_seen=entry["last_seen"],
                source_provider=self.name,
                attributes={"confidence": 95, "curated": True}
            )

        # Fallback heuristic for uncataloged indicators
        if indicator_type == "ip":
            if indicator.startswith(("10.", "192.168.", "172.16.")):
                return ThreatIntelResult(
                    indicator=indicator,
                    indicator_type="ip",
                    verdict="Clean",
                    reputation_score=0,
                    is_malicious=False,
                    threat_types=[],
                    asn="AS-INTERNAL",
                    country_code="LOCAL",
                    organization="Internal Private Subnet",
                    first_seen="2026-01-01T00:00:00Z",
                    last_seen=now_iso,
                    source_provider=self.name,
                    attributes={"confidence": 90}
                )
            # External uncataloged IP
            h = int(hashlib.md5(indicator.encode()).hexdigest(), 16)
            is_mal = (h % 10 == 0)
            is_susp = (h % 4 == 0)
            score = 80 if is_mal else (55 if is_susp else 15)
            verdict = "Malicious" if is_mal else ("Suspicious" if is_susp else "Unknown")
            return ThreatIntelResult(
                indicator=indicator,
                indicator_type="ip",
                verdict=verdict,
                reputation_score=score,
                is_malicious=is_mal,
                threat_types=["Observed Scanning Activity"] if (is_mal or is_susp) else [],
                asn=f"AS{20000 + (h % 50000)}",
                country_code="US",
                organization="Generic Hosting Provider",
                first_seen="2026-11-01T00:00:00Z",
                last_seen=now_iso,
                source_provider=self.name,
                attributes={"confidence": 70}
            )

        # For unknown domains, URLs, or hashes
        return ThreatIntelResult(
            indicator=indicator,
            indicator_type=indicator_type,
            verdict="Unknown",
            reputation_score=10,
            is_malicious=False,
            threat_types=[],
            asn=None,
            country_code=None,
            organization=None,
            first_seen=None,
            last_seen=now_iso,
            source_provider=self.name,
            attributes={"confidence": 40, "note": "No threat vendor intelligence on record for this indicator."}
        )
