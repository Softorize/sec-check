#!/usr/bin/env python3
"""
sec-check: Claude Code PreToolUse hook.

Reads the tool invocation from stdin (JSON), checks if it's a package install
command, runs security checks, and either allows (exit 0) or blocks (exit 2)
with a detailed explanation on stderr.

Usage in .claude/settings.json:
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "python3 -m sec_check.hook"
          }
        ]
      }
    ]
  }
}
"""

import json
import sys
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

# Add parent directory to path so the module can be found
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sec_check.parsers import parse_command
from sec_check.checkers import run_all_checks, Finding


# ─── Severity colors for terminal output ─────────────────────────────────────

_SEVERITY_ICONS = {
    "critical": "\u2718 CRITICAL",
    "high":     "\u2718 HIGH",
    "medium":   "\u26a0 MEDIUM",
    "low":      "\u2139 LOW",
    "info":     "\u2139 INFO",
}


def format_report(findings: list[Finding], packages: list) -> str:
    """Format findings into a readable report for stderr."""
    lines = []
    lines.append("")
    lines.append("=" * 60)
    lines.append("  SEC-CHECK: Dependency Security Report")
    lines.append("=" * 60)
    lines.append("")

    blocking = [f for f in findings if f.should_block]
    warnings = [f for f in findings if not f.should_block and f.severity != "info"]
    infos = [f for f in findings if f.severity == "info"]

    if blocking:
        lines.append(f"  BLOCKING: {len(blocking)} critical/high issue(s) found.")
        lines.append(f"  This install has been BLOCKED to protect your system.")
        lines.append("")

    for f in findings:
        if f.severity == "info":
            continue
        icon = _SEVERITY_ICONS.get(f.severity, f.severity.upper())
        lines.append(f"  [{icon}] {f.title}")
        lines.append(f"    Package: {f.package} ({f.ecosystem})")
        lines.append(f"    Check:   {f.check_name}")
        for detail_line in f.detail.split("\n"):
            lines.append(f"    {detail_line}")
        if f.references:
            lines.append(f"    References:")
            for ref in f.references:
                lines.append(f"      - {ref}")
        lines.append("")

    if infos:
        lines.append("  --- Informational ---")
        for f in infos:
            lines.append(f"  [\u2139 INFO] {f.title}: {f.detail.split(chr(10))[0]}")
        lines.append("")

    lines.append("=" * 60)

    if blocking:
        lines.append("  ACTION: Install BLOCKED. To override, run the install")
        lines.append("  command manually outside of the agent, after reviewing")
        lines.append("  the findings above.")
    elif warnings:
        lines.append("  ACTION: Install ALLOWED with warnings. Review above.")
    else:
        lines.append("  All checks passed. Install allowed.")

    lines.append("=" * 60)
    lines.append("")

    return "\n".join(lines)


def main():
    # Read hook input from stdin
    try:
        raw = sys.stdin.read()
        hook_input = json.loads(raw)
    except (json.JSONDecodeError, Exception) as e:
        # Can't parse input — allow (don't break the agent)
        sys.exit(0)

    tool_name = hook_input.get("tool_name", "")
    tool_input = hook_input.get("tool_input", {})

    # Only care about Bash tool
    if tool_name != "Bash":
        sys.exit(0)

    command = tool_input.get("command", "")
    if not command:
        sys.exit(0)

    # Parse for install commands
    packages = parse_command(command)
    if not packages:
        # Not an install command — allow
        sys.exit(0)

    # Run checks in parallel across packages
    all_findings: list[Finding] = []

    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = {pool.submit(run_all_checks, pkg): pkg for pkg in packages}
        for future in as_completed(futures):
            try:
                all_findings.extend(future.result())
            except Exception:
                pass

    if not all_findings:
        # All clear
        pkg_names = ", ".join(p.name for p in packages)
        sys.stderr.write(f"sec-check: \u2714 {pkg_names} passed all checks.\n")
        sys.exit(0)

    # Sort by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    all_findings.sort(key=lambda f: severity_order.get(f.severity, 5))

    report = format_report(all_findings, packages)

    # Decide: block or warn
    has_blocking = any(f.should_block for f in all_findings)

    if has_blocking:
        sys.stderr.write(report)
        sys.exit(2)  # Exit 2 = block in Claude Code hooks
    else:
        sys.stderr.write(report)
        sys.exit(0)  # Allow but show warnings


if __name__ == "__main__":
    main()
