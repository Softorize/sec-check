"""Shared fixtures for sec-check tests."""

import pytest
from unittest.mock import patch, MagicMock
from urllib.error import HTTPError


@pytest.fixture
def mock_http_post():
    """Patch _http_post_json to return controlled data."""
    with patch("sec_check.checkers._http_post_json") as m:
        yield m


@pytest.fixture
def mock_fetch_with_status():
    """Patch _fetch_with_status to return controlled FetchResult."""
    with patch("sec_check.checkers._fetch_with_status") as m:
        yield m


@pytest.fixture
def no_network(mock_http_post, mock_fetch_with_status):
    """Block all network access — all HTTP helpers return None/error."""
    from sec_check.checkers import FetchResult
    mock_http_post.return_value = None
    mock_fetch_with_status.return_value = FetchResult(data=None, status_code=None, error="blocked by test")
    return {
        "post": mock_http_post,
        "fetch": mock_fetch_with_status,
    }


@pytest.fixture
def pypi_metadata_factory():
    """Factory for creating PyPI metadata dicts."""
    def _make(
        name="test-pkg",
        version="1.0.0",
        description="A test package",
        home_page="https://github.com/test/test-pkg",
        author_email="dev@example.com",
        releases=None,
        requires_dist=None,
        urls=None,
    ):
        if releases is None:
            releases = {
                "1.0.0": [{
                    "upload_time_iso_8601": "2023-01-01T00:00:00Z",
                    "packagetype": "sdist",
                    "size": 50000,
                }]
            }
        return {
            "info": {
                "name": name,
                "version": version,
                "description": description,
                "home_page": home_page,
                "project_url": None,
                "project_urls": {"Homepage": home_page} if home_page else None,
                "author_email": author_email,
                "requires_dist": requires_dist or [],
            },
            "releases": releases,
            "urls": urls or releases.get(version, []),
        }
    return _make


@pytest.fixture
def npm_metadata_factory():
    """Factory for creating npm metadata dicts."""
    def _make(
        name="test-pkg",
        created="2023-01-01T00:00:00Z",
        modified="2023-06-01T00:00:00Z",
        maintainers=None,
        scripts=None,
    ):
        data = {
            "name": name,
            "dist-tags": {"latest": "1.0.0"},
            "time": {
                "created": created,
                "modified": modified,
            },
            "maintainers": maintainers or [{"name": "author1"}, {"name": "author2"}],
            "versions": {
                "1.0.0": {
                    "scripts": scripts or {},
                }
            },
        }
        return data
    return _make
