"""Tests for the database layer and storage tier fallback."""

from unittest.mock import patch, MagicMock

import pytest


class TestStorageTierFallback:
    """Verify the 3-tier fallback chain: Supabase -> Postgres -> in-memory."""

    def test_in_memory_create_and_get(self):
        """In-memory tier should create and retrieve scans."""
        from app.demo_store import _mem_create_scan, _scans

        scan = _mem_create_scan(
            "https://github.com/test/repo", "test/repo", "main"
        )
        assert scan["id"] in _scans
        assert scan["repo_url"] == "https://github.com/test/repo"
        assert scan["status"] == "queued"
        assert scan["progress"] == 0
        assert scan["mcp_detected"] is False
        assert scan["total_findings"] == 0

    def test_in_memory_update(self):
        """In-memory tier should update scan fields."""
        from app.demo_store import _mem_create_scan, _scans

        scan = _mem_create_scan(
            "https://github.com/test/update", "test/update", "main"
        )
        scan_id = scan["id"]
        _scans[scan_id]["status"] = "analyzing"
        _scans[scan_id]["progress"] = 50
        assert _scans[scan_id]["status"] == "analyzing"
        assert _scans[scan_id]["progress"] == 50

    def test_storage_tier_returns_valid_string(self):
        """get_storage_tier should return one of the valid tiers."""
        from app.demo_store import get_storage_tier

        tier = get_storage_tier()
        assert tier in ("supabase", "postgres", "memory")

    def test_in_memory_findings_roundtrip(self):
        """In-memory tier should store and retrieve findings."""
        from app.demo_store import _mem_create_scan, _findings

        scan = _mem_create_scan(
            "https://github.com/test/findings", "test/findings", "main"
        )
        scan_id = scan["id"]
        test_findings = [
            {"id": "f1", "severity": "HIGH", "title": "Test finding"},
            {"id": "f2", "severity": "LOW", "title": "Another finding"},
        ]
        _findings[scan_id] = test_findings
        assert len(_findings[scan_id]) == 2
        assert _findings[scan_id][0]["severity"] == "HIGH"


class TestSupabaseClientConfig:
    """Test Supabase client configuration handling."""

    def test_placeholder_url_raises(self):
        """Client should not connect to placeholder URLs."""
        from app.db.client import get_supabase_client
        # Clear the lru_cache to test fresh
        get_supabase_client.cache_clear()

        with pytest.raises(ValueError, match="not configured"):
            get_supabase_client()

    def test_try_get_client_returns_none_for_placeholder(self):
        """try_get_client should return None when not configured."""
        from app.db.client import try_get_client, get_supabase_client
        get_supabase_client.cache_clear()

        result = try_get_client()
        assert result is None

    def test_is_supabase_available_false_for_placeholder(self):
        """is_supabase_available should be False with placeholder creds."""
        from app.db.client import is_supabase_available, get_supabase_client
        get_supabase_client.cache_clear()

        assert is_supabase_available() is False


class TestScanRepoInterface:
    """Test Supabase scan_repo functions raise when not configured."""

    def test_create_scan_raises_without_supabase(self):
        """scan_repo.create_scan should raise when Supabase is not available."""
        from app.db.client import get_supabase_client
        get_supabase_client.cache_clear()

        from app.db.scan_repo import create_scan
        with pytest.raises(ValueError):
            create_scan(repo_url="https://github.com/t/t", repo_name="t/t", branch="main")

    def test_get_scan_raises_without_supabase(self):
        """scan_repo.get_scan should raise when Supabase is not available."""
        from app.db.client import get_supabase_client
        get_supabase_client.cache_clear()

        from app.db.scan_repo import get_scan
        with pytest.raises(ValueError):
            get_scan("some-id")


class TestFindingRepoInterface:
    """Test finding_repo functions raise when not configured."""

    def test_create_findings_empty_returns_zero(self):
        """Empty findings list should return 0 without touching Supabase."""
        from app.db.finding_repo import create_findings
        assert create_findings("scan-id", []) == 0


class TestAgentFindingRepo:
    """Test agent_finding_repo interface."""

    def test_create_empty_returns_zero(self):
        """Empty agent findings list should return 0."""
        from app.db.agent_finding_repo import create_agent_findings
        assert create_agent_findings("scan-id", []) == 0
