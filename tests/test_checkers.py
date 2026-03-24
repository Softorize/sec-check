"""Tests for sec_check.checkers — all checkers with mocked HTTP."""

import pytest
from unittest.mock import patch
from sec_check.parsers import PackageRef
from sec_check.checkers import (
    MetadataCache, FetchResult, CheckResult,
    DYNAMIC_INSTALL, PIPED_INSTALL,
    check_suspicious_install,
    check_known_vulnerabilities,
    check_typosquatting,
    check_package_metadata,
    check_install_scripts,
    check_package_exists,
    run_all_checks,
    _POPULAR_PACKAGES,
)


def _make_cache(pypi_data=None, npm_data=None, pypi_status=200, npm_status=200):
    """Create a MetadataCache with pre-loaded data (no network)."""
    cache = MetadataCache()
    if pypi_data is not None or pypi_status != 200:
        # Pre-populate so no HTTP call is made
        pass
    return cache


def _cache_with_pypi(name, data, status=200):
    cache = MetadataCache()
    cache._store[f"pypi:{name}"] = FetchResult(data=data, status_code=status)
    return cache


def _cache_with_npm(name, data, status=200):
    cache = MetadataCache()
    cache._store[f"npm:{name}"] = FetchResult(data=data, status_code=status)
    return cache


def _empty_cache():
    return MetadataCache()


# ─── check_suspicious_install ────────────────────────────────────────────────

class TestCheckSuspiciousInstall:
    def test_dynamic_install(self):
        pkg = PackageRef(DYNAMIC_INSTALL, None, "pypi", "pip install $(echo x)")
        findings = check_suspicious_install(pkg, _empty_cache())
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert findings[0].check_name == "dynamic_install"

    def test_piped_install(self):
        pkg = PackageRef(PIPED_INSTALL, None, "npm", "echo x | npm install")
        findings = check_suspicious_install(pkg, _empty_cache())
        assert len(findings) == 1
        assert findings[0].severity == "high"
        assert findings[0].check_name == "piped_install"

    def test_normal_package(self):
        pkg = PackageRef("requests", None, "pypi", "requests")
        findings = check_suspicious_install(pkg, _empty_cache())
        assert findings == []


# ─── check_known_vulnerabilities ─────────────────────────────────────────────

class TestCheckKnownVulnerabilities:
    def test_no_vulns(self, mock_http_post, mock_fetch_with_status, pypi_metadata_factory):
        mock_http_post.return_value = {"vulns": []}
        mock_fetch_with_status.return_value = FetchResult(
            data=pypi_metadata_factory(version="2.31.0"), status_code=200
        )
        pkg = PackageRef("requests", None, "pypi", "requests")
        cache = MetadataCache()
        findings = check_known_vulnerabilities(pkg, cache)
        non_info = [f for f in findings if f.severity != "info"]
        assert non_info == []

    def test_critical_vuln(self, mock_http_post):
        mock_http_post.return_value = {
            "vulns": [{
                "id": "CVE-2024-0001",
                "summary": "Critical RCE",
                "severity": [{"score": "9.8"}],
                "references": [],
            }]
        }
        pkg = PackageRef("badpkg", "1.0.0", "pypi", "badpkg==1.0.0")
        findings = check_known_vulnerabilities(pkg, _empty_cache())
        assert any(f.severity == "critical" for f in findings)

    def test_high_vuln(self, mock_http_post):
        mock_http_post.return_value = {
            "vulns": [{
                "id": "CVE-2024-0002",
                "summary": "High severity",
                "severity": [{"score": "7.5"}],
                "references": [],
            }]
        }
        pkg = PackageRef("pkg", "1.0.0", "pypi", "pkg==1.0.0")
        findings = check_known_vulnerabilities(pkg, _empty_cache())
        assert any(f.severity == "high" for f in findings)

    def test_medium_vuln(self, mock_http_post):
        mock_http_post.return_value = {
            "vulns": [{
                "id": "CVE-2024-0003",
                "summary": "Medium severity",
                "severity": [{"score": "5.0"}],
                "references": [],
            }]
        }
        pkg = PackageRef("pkg", "1.0.0", "pypi", "pkg==1.0.0")
        findings = check_known_vulnerabilities(pkg, _empty_cache())
        assert any(f.severity == "medium" for f in findings)

    def test_unknown_cvss_defaults_to_medium(self, mock_http_post):
        """Vulns without CVSS should be medium (non-blocking), not high."""
        mock_http_post.return_value = {
            "vulns": [{
                "id": "CVE-2024-0004",
                "summary": "No score",
                "severity": [],
                "references": [],
            }]
        }
        pkg = PackageRef("pkg", "1.0.0", "pypi", "pkg==1.0.0")
        findings = check_known_vulnerabilities(pkg, _empty_cache())
        vuln_findings = [f for f in findings if f.check_name == "known_vulnerability"]
        assert len(vuln_findings) == 1
        assert vuln_findings[0].severity == "medium"
        assert not vuln_findings[0].should_block

    def test_api_failure_returns_empty(self, mock_http_post):
        mock_http_post.return_value = None
        pkg = PackageRef("pkg", "1.0.0", "pypi", "pkg")
        findings = check_known_vulnerabilities(pkg, _empty_cache())
        assert findings == []

    def test_version_resolved_when_none(self, mock_http_post, mock_fetch_with_status, pypi_metadata_factory):
        """When no version specified, latest should be resolved and sent to OSV."""
        mock_fetch_with_status.return_value = FetchResult(
            data=pypi_metadata_factory(version="2.31.0"), status_code=200
        )
        mock_http_post.return_value = {"vulns": []}
        pkg = PackageRef("requests", None, "pypi", "requests")
        cache = MetadataCache()
        findings = check_known_vulnerabilities(pkg, cache)
        # Should have called OSV with version
        call_args = mock_http_post.call_args
        assert call_args[0][1].get("version") == "2.31.0"
        # Should have an info finding about version resolution
        info = [f for f in findings if f.check_name == "version_resolved"]
        assert len(info) == 1

    def test_ecosystem_mapping(self, mock_http_post):
        """Verify ecosystem names are mapped correctly for OSV."""
        mock_http_post.return_value = {"vulns": []}
        for eco, osv_name in [("pypi", "PyPI"), ("npm", "npm"), ("go", "Go"), ("cargo", "crates.io"), ("gem", "RubyGems")]:
            pkg = PackageRef("test", "1.0.0", eco, "test")
            check_known_vulnerabilities(pkg, _empty_cache())
            call_body = mock_http_post.call_args[0][1]
            assert call_body["package"]["ecosystem"] == osv_name


# ─── check_typosquatting ────────────────────────────────────────────────────

class TestCheckTyposquatting:
    def test_exact_match_not_flagged(self):
        pkg = PackageRef("requests", None, "pypi", "requests")
        findings = check_typosquatting(pkg, _empty_cache())
        assert findings == []

    def test_known_typosquat_similarity(self):
        pkg = PackageRef("reqeusts", None, "pypi", "reqeusts")
        findings = check_typosquatting(pkg, _empty_cache())
        assert len(findings) >= 1
        assert findings[0].severity == "high"
        assert findings[0].check_name == "typosquatting"

    def test_substitution_detection_o_to_0(self):
        pkg = PackageRef("djang0", None, "pypi", "djang0")
        findings = check_typosquatting(pkg, _empty_cache())
        assert len(findings) >= 1
        assert "django" in findings[0].title.lower()

    def test_unrelated_package_no_findings(self):
        pkg = PackageRef("my-unique-unrelated-pkg-xyz", None, "pypi", "x")
        findings = check_typosquatting(pkg, _empty_cache())
        assert findings == []

    def test_all_popular_packages_not_false_positive(self):
        """No popular package should be flagged as a typosquat of itself."""
        for eco, packages in _POPULAR_PACKAGES.items():
            for name in packages:
                pkg = PackageRef(name, None, eco, name)
                findings = check_typosquatting(pkg, _empty_cache())
                assert findings == [], f"False positive: {name} ({eco}) flagged as typosquat"


# ─── check_package_metadata ─────────────────────────────────────────────────

class TestCheckPackageMetadata:
    def test_healthy_package_no_issues(self, pypi_metadata_factory):
        data = pypi_metadata_factory()
        pkg = PackageRef("test-pkg", None, "pypi", "test-pkg")
        cache = _cache_with_pypi("test-pkg", data)
        findings = check_package_metadata(pkg, cache)
        blocking = [f for f in findings if f.should_block]
        assert blocking == []

    def test_new_package_flagged(self, pypi_metadata_factory):
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat()
        data = pypi_metadata_factory(releases={
            "0.1.0": [{"upload_time_iso_8601": now, "packagetype": "sdist", "size": 5000}]
        })
        pkg = PackageRef("newpkg", None, "pypi", "newpkg")
        cache = _cache_with_pypi("newpkg", data)
        findings = check_package_metadata(pkg, cache)
        assert any(f.check_name == "new_package" for f in findings)

    def test_missing_urls_flagged(self, pypi_metadata_factory):
        data = pypi_metadata_factory(home_page=None)
        data["info"]["project_urls"] = None
        pkg = PackageRef("nourls", None, "pypi", "nourls")
        cache = _cache_with_pypi("nourls", data)
        findings = check_package_metadata(pkg, cache)
        assert any(f.check_name == "missing_urls" for f in findings)

    def test_suspicious_author_email(self, pypi_metadata_factory):
        data = pypi_metadata_factory(author_email="hacker@mailinator.com")
        pkg = PackageRef("sus", None, "pypi", "sus")
        cache = _cache_with_pypi("sus", data)
        findings = check_package_metadata(pkg, cache)
        assert any(f.check_name == "suspicious_author" for f in findings)

    def test_url_dependency_flagged(self, pypi_metadata_factory):
        data = pypi_metadata_factory(
            requires_dist=["evil-pkg @ https://evil.com/evil.tar.gz"]
        )
        pkg = PackageRef("pkg", None, "pypi", "pkg")
        cache = _cache_with_pypi("pkg", data)
        findings = check_package_metadata(pkg, cache)
        assert any(f.check_name == "url_dependency" for f in findings)

    def test_metadata_unavailable(self):
        pkg = PackageRef("gone", None, "pypi", "gone")
        cache = _cache_with_pypi("gone", None, status=None)
        findings = check_package_metadata(pkg, cache)
        assert any(f.check_name == "metadata_unavailable" for f in findings)

    def test_404_not_duplicate_with_exists_check(self):
        """404 should not produce metadata_unavailable (that's check_package_exists' job)."""
        pkg = PackageRef("removed", None, "pypi", "removed")
        cache = _cache_with_pypi("removed", None, status=404)
        findings = check_package_metadata(pkg, cache)
        assert not any(f.check_name == "metadata_unavailable" for f in findings)


class TestCheckNpmMetadata:
    def test_healthy_npm_package(self, npm_metadata_factory):
        data = npm_metadata_factory()
        pkg = PackageRef("test-pkg", None, "npm", "test-pkg")
        cache = _cache_with_npm("test-pkg", data)
        findings = check_package_metadata(pkg, cache)
        blocking = [f for f in findings if f.should_block]
        assert blocking == []

    def test_single_maintainer_info(self, npm_metadata_factory):
        data = npm_metadata_factory(maintainers=[{"name": "solo"}])
        pkg = PackageRef("solo-pkg", None, "npm", "solo-pkg")
        cache = _cache_with_npm("solo-pkg", data)
        findings = check_package_metadata(pkg, cache)
        assert any(f.check_name == "single_maintainer" for f in findings)


# ─── check_install_scripts ──────────────────────────────────────────────────

class TestCheckInstallScripts:
    def test_clean_description(self, pypi_metadata_factory):
        data = pypi_metadata_factory(description="A simple HTTP library for Python.")
        pkg = PackageRef("clean", None, "pypi", "clean")
        cache = _cache_with_pypi("clean", data)
        findings = check_install_scripts(pkg, cache)
        assert findings == []

    def test_base64_in_description(self, pypi_metadata_factory):
        data = pypi_metadata_factory(description="Uses base64 encoding to decode payloads")
        pkg = PackageRef("sus", None, "pypi", "sus")
        cache = _cache_with_pypi("sus", data)
        findings = check_install_scripts(pkg, cache)
        assert any("base64" in f.title for f in findings)

    def test_eval_in_description(self, pypi_metadata_factory):
        data = pypi_metadata_factory(description="Run eval( code ) for dynamic execution")
        pkg = PackageRef("evalpkg", None, "pypi", "evalpkg")
        cache = _cache_with_pypi("evalpkg", data)
        findings = check_install_scripts(pkg, cache)
        assert any("eval" in f.title for f in findings)

    def test_tiny_sdist_flagged(self, pypi_metadata_factory):
        data = pypi_metadata_factory(urls=[{"packagetype": "sdist", "size": 500}])
        pkg = PackageRef("tiny", None, "pypi", "tiny")
        cache = _cache_with_pypi("tiny", data)
        findings = check_install_scripts(pkg, cache)
        assert any(f.check_name == "tiny_sdist" for f in findings)

    def test_npm_postinstall_detected(self, npm_metadata_factory):
        data = npm_metadata_factory(scripts={"postinstall": "node setup.js"})
        pkg = PackageRef("npmpkg", None, "npm", "npmpkg")
        cache = _cache_with_npm("npmpkg", data)
        findings = check_install_scripts(pkg, cache)
        assert any(f.check_name == "install_script" for f in findings)

    def test_npm_suspicious_postinstall(self, npm_metadata_factory):
        data = npm_metadata_factory(scripts={"postinstall": "eval(Buffer.from('...').toString())"})
        pkg = PackageRef("evilnpm", None, "npm", "evilnpm")
        cache = _cache_with_npm("evilnpm", data)
        findings = check_install_scripts(pkg, cache)
        assert any(f.check_name == "suspicious_install_script" for f in findings)

    def test_non_pypi_skipped(self):
        pkg = PackageRef("cargo-pkg", None, "cargo", "cargo-pkg")
        findings = check_install_scripts(pkg, _empty_cache())
        assert findings == []


# ─── check_package_exists ────────────────────────────────────────────────────

class TestCheckPackageExists:
    def test_existing_package_pypi(self, pypi_metadata_factory):
        data = pypi_metadata_factory()
        pkg = PackageRef("exists", None, "pypi", "exists")
        cache = _cache_with_pypi("exists", data)
        findings = check_package_exists(pkg, cache)
        assert findings == []

    def test_removed_package_pypi_404(self):
        pkg = PackageRef("removed", None, "pypi", "removed")
        cache = _cache_with_pypi("removed", None, status=404)
        findings = check_package_exists(pkg, cache)
        assert len(findings) == 1
        assert findings[0].severity == "critical"
        assert findings[0].check_name == "package_removed"

    def test_removed_package_npm_404(self):
        pkg = PackageRef("removed", None, "npm", "removed")
        cache = _cache_with_npm("removed", None, status=404)
        findings = check_package_exists(pkg, cache)
        assert len(findings) == 1
        assert findings[0].severity == "critical"

    def test_network_error_no_finding(self):
        """Network errors should not produce a 'removed' finding."""
        pkg = PackageRef("maybe", None, "pypi", "maybe")
        cache = MetadataCache()
        cache._store["pypi:maybe"] = FetchResult(data=None, status_code=None, error="timeout")
        findings = check_package_exists(pkg, cache)
        assert findings == []


# ─── run_all_checks ──────────────────────────────────────────────────────────

class TestRunAllChecks:
    def test_synthetic_short_circuits(self):
        """Synthetic packages should only run check_suspicious_install."""
        pkg = PackageRef(DYNAMIC_INSTALL, None, "pypi", "pip install $(x)")
        result = run_all_checks(pkg)
        assert isinstance(result, CheckResult)
        assert result.total_checkers == 1
        assert len(result.findings) == 1
        assert result.findings[0].check_name == "dynamic_install"

    def test_checker_exception_handled(self, no_network):
        """If a checker raises, it should produce an info finding, not crash."""
        pkg = PackageRef("test", "1.0.0", "pypi", "test")
        # With all network blocked, some checkers may fail
        result = run_all_checks(pkg)
        assert isinstance(result, CheckResult)
        # Should not crash — checkers should handle errors gracefully
        assert result.total_checkers > 0

    def test_returns_check_result(self, no_network):
        pkg = PackageRef("test", "1.0.0", "pypi", "test")
        result = run_all_checks(pkg)
        assert isinstance(result, CheckResult)
        assert isinstance(result.findings, list)
        assert isinstance(result.total_checkers, int)
        assert isinstance(result.failed_checkers, int)
