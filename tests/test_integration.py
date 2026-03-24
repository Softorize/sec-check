"""
Integration tests that hit live APIs.
Run with: pytest -m integration
Skipped by default in normal test runs.
"""

import pytest
from sec_check.parsers import PackageRef
from sec_check.checkers import run_all_checks


pytestmark = pytest.mark.integration


class TestLiveAPIs:
    def test_requests_package_not_blocked(self):
        """requests is a popular, safe package — should NOT produce blocking findings."""
        pkg = PackageRef("requests", None, "pypi", "requests")
        result = run_all_checks(pkg)
        blocking = [f for f in result.findings if f.should_block]
        assert len(blocking) == 0, (
            f"Safe package 'requests' was blocked with {len(blocking)} findings: "
            f"{[f.title for f in blocking]}"
        )

    def test_flask_not_blocked(self):
        """flask should not be blocked."""
        pkg = PackageRef("flask", None, "pypi", "flask")
        result = run_all_checks(pkg)
        blocking = [f for f in result.findings if f.should_block]
        assert len(blocking) == 0, f"flask blocked: {[f.title for f in blocking]}"

    def test_typosquat_reqeusts_detected(self):
        """reqeusts (misspelling) should be flagged."""
        pkg = PackageRef("reqeusts", None, "pypi", "reqeusts")
        result = run_all_checks(pkg)
        typo = [f for f in result.findings if f.check_name == "typosquatting"]
        assert len(typo) > 0

    def test_nonexistent_package_flagged(self):
        """A truly nonexistent package should be flagged as removed/missing."""
        pkg = PackageRef("this-package-definitely-does-not-exist-xyz123", None, "pypi",
                         "this-package-definitely-does-not-exist-xyz123")
        result = run_all_checks(pkg)
        removed = [f for f in result.findings if f.check_name == "package_removed"]
        assert len(removed) > 0

    def test_express_npm_not_blocked(self):
        """express (npm) should not be blocked."""
        pkg = PackageRef("express", None, "npm", "express")
        result = run_all_checks(pkg)
        blocking = [f for f in result.findings if f.should_block]
        assert len(blocking) == 0, f"express blocked: {[f.title for f in blocking]}"
