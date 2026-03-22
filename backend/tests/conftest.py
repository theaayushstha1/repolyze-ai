"""Shared pytest fixtures for the RepolyzeAI test suite."""

from collections.abc import AsyncIterator, Iterator
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient


@pytest.fixture(scope="session")
def _mock_supabase() -> Iterator[MagicMock]:
    """Patch the Supabase client for the entire test session."""
    mock_client = MagicMock()
    with patch("app.db.client.create_client", return_value=mock_client):
        yield mock_client


@pytest.fixture()
def client(_mock_supabase: MagicMock) -> TestClient:
    """Provide a FastAPI TestClient with mocked external dependencies."""
    from app.main import app

    return TestClient(app)


@pytest.fixture()
def supabase_mock(_mock_supabase: MagicMock) -> MagicMock:
    """Expose the mocked Supabase client for per-test assertions."""
    _mock_supabase.reset_mock()
    return _mock_supabase
