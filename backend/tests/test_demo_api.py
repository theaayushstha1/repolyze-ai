"""Tests for the demo API endpoints."""

from fastapi.testclient import TestClient

from demo import app


client = TestClient(app)


class TestHealthEndpoint:
    def test_health_returns_200(self):
        res = client.get("/api/health")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "healthy"
        assert data["service"] == "repolyze-ai-backend"
        assert data["storage"] in ("supabase", "postgres", "memory")
        assert data["tasks"] in ("celery", "asyncio")


class TestA2AEndpoints:
    def test_agent_card_discovery(self):
        res = client.get("/.well-known/agent.json")
        assert res.status_code == 200
        data = res.json()
        assert "name" in data
        assert data["name"] == "RepolyzeAI Orchestrator"

    def test_list_agents(self):
        res = client.get("/api/a2a/agents")
        assert res.status_code == 200
        agents = res.json()
        assert len(agents) >= 1


class TestScanEndpoints:
    def test_create_scan_invalid_url(self):
        res = client.post("/api/scans", json={"repo_url": "not-a-url"})
        assert res.status_code == 400

    def test_create_scan_valid_url(self):
        res = client.post("/api/scans",
                          json={"repo_url": "https://github.com/octocat/Hello-World"})
        assert res.status_code == 201
        data = res.json()
        assert "id" in data
        assert data["repo_url"] == "https://github.com/octocat/Hello-World"
        assert data["status"] == "queued"

    def test_get_scan_not_found(self):
        res = client.get("/api/scans/nonexistent-id")
        assert res.status_code == 404

    def test_get_findings_not_found(self):
        res = client.get("/api/scans/nonexistent-id/findings")
        assert res.status_code == 404


class TestDashboard:
    def test_dashboard_returns_list(self):
        res = client.get("/api/dashboard/scans")
        assert res.status_code == 200
        assert isinstance(res.json(), list)
