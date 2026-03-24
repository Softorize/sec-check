"""Tests for sec_check.hook — full stdin-to-exit-code pipeline."""

import json
import pytest
from io import StringIO
from unittest.mock import patch, MagicMock

from sec_check.checkers import Finding, CheckResult


def _run_hook(tool_name, command):
    """Feed JSON to hook's main(), return (exit_code, stderr_output)."""
    from sec_check.hook import main

    hook_input = json.dumps({
        "tool_name": tool_name,
        "tool_input": {"command": command},
    })
    with patch("sys.stdin", StringIO(hook_input)), \
         patch("sys.stderr", new_callable=StringIO) as mock_stderr:
        try:
            main()
            return 0, mock_stderr.getvalue()
        except SystemExit as e:
            return e.code, mock_stderr.getvalue()


def _run_hook_raw(raw_input):
    """Feed raw string to hook's main()."""
    from sec_check.hook import main

    with patch("sys.stdin", StringIO(raw_input)), \
         patch("sys.stderr", new_callable=StringIO) as mock_stderr:
        try:
            main()
            return 0, mock_stderr.getvalue()
        except SystemExit as e:
            return e.code, mock_stderr.getvalue()


class TestHookRouting:
    """Test that the hook correctly routes based on tool_name and command."""

    def test_non_bash_tool_allowed(self):
        code, _ = _run_hook("Read", "/some/file")
        assert code == 0

    def test_non_install_command_allowed(self):
        code, _ = _run_hook("Bash", "ls -la")
        assert code == 0

    def test_empty_command_allowed(self):
        code, _ = _run_hook("Bash", "")
        assert code == 0

    def test_invalid_json_allowed(self):
        code, stderr = _run_hook_raw("not valid json {{{")
        assert code == 0
        assert "WARNING" in stderr


class TestHookDecisions:
    """Test blocking vs allowing based on check results."""

    @patch("sec_check.hook.run_all_checks")
    def test_safe_install_allowed(self, mock_checks):
        mock_checks.return_value = CheckResult(
            findings=[], total_checkers=6, failed_checkers=0,
        )
        code, stderr = _run_hook("Bash", "pip install requests")
        assert code == 0
        assert "passed all checks" in stderr

    @patch("sec_check.hook.run_all_checks")
    def test_blocking_finding_exits_2(self, mock_checks):
        mock_checks.return_value = CheckResult(
            findings=[Finding(
                severity="critical",
                check_name="package_removed",
                title="Package removed",
                detail="Gone",
                package="evil",
                ecosystem="pypi",
            )],
            total_checkers=6, failed_checkers=0,
        )
        code, stderr = _run_hook("Bash", "pip install evil")
        assert code == 2
        assert "BLOCKED" in stderr

    @patch("sec_check.hook.run_all_checks")
    def test_warning_only_exits_0(self, mock_checks):
        mock_checks.return_value = CheckResult(
            findings=[Finding(
                severity="medium",
                check_name="new_package",
                title="New package",
                detail="Created recently",
                package="newpkg",
                ecosystem="pypi",
            )],
            total_checkers=6, failed_checkers=0,
        )
        code, stderr = _run_hook("Bash", "pip install newpkg")
        assert code == 0
        assert "ALLOWED with warnings" in stderr


class TestHookFailOpen:
    """Test that all-checkers-fail blocks instead of silently allowing."""

    @patch("sec_check.hook.run_all_checks")
    def test_all_checkers_failed_blocks(self, mock_checks):
        mock_checks.return_value = CheckResult(
            findings=[],
            total_checkers=6,
            failed_checkers=6,
            checker_errors=["checker1: timeout", "checker2: timeout"],
        )
        code, stderr = _run_hook("Bash", "pip install something")
        assert code == 2
        assert "all security checkers failed" in stderr.lower()

    @patch("sec_check.hook.run_all_checks")
    def test_all_futures_failed_blocks(self, mock_checks):
        mock_checks.side_effect = RuntimeError("catastrophic failure")
        code, stderr = _run_hook("Bash", "pip install something")
        assert code == 2
        assert "could not run any security checks" in stderr.lower()
