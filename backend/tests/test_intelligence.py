"""
Comprehensive Unit & Integration Tests for AegisSOC Threat Intelligence Engine
Verifies IOC detection, multi-provider enrichment, reputation scoring, verdict distinction,
cache management, and query telemetry.
"""

import pytest
from httpx import AsyncClient

from app.intelligence.types import detect_ioc_type


class TestIOCTypeClassification:
    def test_detect_ioc_types(self):
        """Verifies deterministic classification of IPs, Domains, URLs, and Hashes."""
        # IP addresses
        assert detect_ioc_type("192.168.1.1") == "ip"
        assert detect_ioc_type("185.45.103.91") == "ip"
        assert detect_ioc_type("2001:0db8:85a3:0000:0000:8a2e:0370:7334") == "ip"

        # Cryptographic file hashes
        assert detect_ioc_type("44d88612fea8a8f36de82e1278abb02f") == "hash"  # MD5 (32 hex)
        assert detect_ioc_type("a1b2c3d4e5f67890123456789abcdef012345678") == "hash"  # SHA-1 (40 hex)
        assert detect_ioc_type("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == "hash"  # SHA-256 (64 hex)

        # URLs
        assert detect_ioc_type("http://185.45.103.91/stage2.bin") == "url"
        assert detect_ioc_type("https://auth-phish-portal.live/login") == "url"

        # Domains
        assert detect_ioc_type("c2-controller-update.net") == "domain"
        assert detect_ioc_type("auth-phish-portal.live") == "domain"
        assert detect_ioc_type("google.com") == "domain"


class TestThreatIntelEndpoints:
    @pytest.mark.asyncio
    async def test_intelligence_lookup(self, client: AsyncClient):
        """Verifies IP lookup with malicious verdict and ASN/Geo attribution."""
        payload = {"indicator": "185.45.103.91", "indicator_type": "ip"}
        response = await client.post("/api/intelligence/lookup", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["indicator"] == "185.45.103.91"
        assert data["reputation_score"] >= 75
        assert data["is_malicious"] is True
        assert data["verdict"] == "Malicious"
        assert data["asn"] == "AS48031"
        assert "Botnet C2" in data["threat_types"]

    @pytest.mark.asyncio
    async def test_intelligence_ip_direct(self, client: AsyncClient):
        """Verifies clean internal IP lookup."""
        response = await client.get("/api/intelligence/ip/10.0.0.1")
        assert response.status_code == 200
        data = response.json()
        assert data["indicator"] == "10.0.0.1"
        assert data["verdict"] == "Clean"
        assert data["reputation_score"] == 0

    @pytest.mark.asyncio
    async def test_intelligence_domain_lookup(self, client: AsyncClient):
        """Verifies domain lookup for malicious and suspicious indicators."""
        # Malicious C2 domain
        res_mal = await client.get("/api/intelligence/domain/c2-controller-update.net")
        assert res_mal.status_code == 200
        d_mal = res_mal.json()
        assert d_mal["verdict"] == "Malicious"
        assert d_mal["indicator_type"] == "domain"

        # Suspicious domain
        res_susp = await client.get("/api/intelligence/domain/free-cloud-sync-tool.info")
        assert res_susp.status_code == 200
        d_susp = res_susp.json()
        assert d_susp["verdict"] == "Suspicious"
        assert 40 <= d_susp["reputation_score"] < 75

    @pytest.mark.asyncio
    async def test_intelligence_hash_lookup(self, client: AsyncClient):
        """Verifies file hash lookup with malware family attribution."""
        # Known ransomware hash
        h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        res = await client.get(f"/api/intelligence/hash/{h}")
        assert res.status_code == 200
        data = res.json()
        assert data["verdict"] == "Malicious"
        assert data["reputation_score"] >= 90
        assert any("LockBit" in t for t in data["threat_types"])

        # Unknown hash
        unknown_h = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        res_unk = await client.get(f"/api/intelligence/hash/{unknown_h}")
        assert res_unk.status_code == 200
        d_unk = res_unk.json()
        assert d_unk["verdict"] == "Unknown"

    @pytest.mark.asyncio
    async def test_intelligence_cache_and_history(self, client: AsyncClient):
        """Verifies caching behavior, cache hits, and query telemetry history."""
        ind = "194.26.29.112"

        # First query (populates cache)
        res1 = await client.post("/api/intelligence/lookup", json={"indicator": ind})
        assert res1.status_code == 200
        assert res1.json()["cache_hit"] is False

        # Second query (served from cache)
        res2 = await client.post("/api/intelligence/lookup", json={"indicator": ind})
        assert res2.status_code == 200
        assert res2.json()["cache_hit"] is True

        # Query history
        hist_res = await client.get("/api/intelligence/history?limit=10")
        assert hist_res.status_code == 200
        history = hist_res.json()
        assert len(history) >= 2
        assert any(item["indicator"] == ind for item in history)

        # Clear cache
        clear_res = await client.post(f"/api/intelligence/cache/clear?indicator={ind}")
        assert clear_res.status_code == 200
        assert clear_res.json()["entries_removed"] >= 1
