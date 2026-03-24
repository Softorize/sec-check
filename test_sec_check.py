#!/usr/bin/env python3
"""
Test suite for sec-check.
Tests parsing, typosquatting detection, and live API checks.
"""

import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sec_check.parsers import parse_command, PackageRef
from sec_check.checkers import (
    check_typosquatting,
    check_known_vulnerabilities,
    check_package_metadata,
    check_package_exists,
    run_all_checks,
)


def test_parsers():
    print("=" * 50)
    print("TEST: Command Parsing")
    print("=" * 50)

    cases = [
        ("pip install requests", [("requests", None, "pypi")]),
        ("pip install litellm==1.82.7", [("litellm", "1.82.7", "pypi")]),
        ("pip3 install flask django>=4.0", [("flask", None, "pypi"), ("django", "4.0", "pypi")]),
        ("pip install -r requirements.txt", []),
        ("npm install express", [("express", None, "npm")]),
        ("npm i lodash@4.17.21 axios", [("lodash", "4.17.21", "npm"), ("axios", None, "npm")]),
        ("yarn add react@18", [("react", "18", "npm")]),
        ("go get github.com/gin-gonic/gin@v1.9.1", [("github.com/gin-gonic/gin", "v1.9.1", "go")]),
        ("cargo install ripgrep", [("ripgrep", None, "cargo")]),
        ("gem install rails", [("rails", None, "gem")]),
        ("echo hello", []),
        ("ls -la", []),
        ("pip install requests && npm install express", [("requests", None, "pypi"), ("express", None, "npm")]),
        ("python3 -m pip install --break-system-packages boto3", [("boto3", None, "pypi")]),
    ]

    passed = 0
    for cmd, expected in cases:
        pkgs = parse_command(cmd)
        actual = [(p.name, p.version, p.ecosystem) for p in pkgs]
        ok = actual == expected
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] {cmd!r}")
        if not ok:
            print(f"         Expected: {expected}")
            print(f"         Got:      {actual}")
        else:
            passed += 1

    print(f"\n  {passed}/{len(cases)} passed\n")
    return passed == len(cases)


def test_typosquatting():
    print("=" * 50)
    print("TEST: Typosquatting Detection")
    print("=" * 50)

    # Should detect
    typosquats = [
        PackageRef("reqeusts", None, "pypi", "reqeusts"),      # common misspelling
        PackageRef("req-uests", None, "pypi", "req-uests"),    # inserted hyphen
        PackageRef("requ3sts", None, "pypi", "requ3sts"),      # letter swap
        PackageRef("litelm", None, "pypi", "litelm"),          # missing letter
        PackageRef("djang0", None, "pypi", "djang0"),          # o -> 0
        PackageRef("expresss", None, "npm", "expresss"),       # extra letter
    ]

    # Should NOT detect
    safe = [
        PackageRef("requests", None, "pypi", "requests"),       # exact match
        PackageRef("flask", None, "pypi", "flask"),
        PackageRef("my-unique-pkg-12345", None, "pypi", "x"),   # nothing close
    ]

    print("\n  --- Should detect as typosquat ---")
    detected = 0
    for pkg in typosquats:
        findings = check_typosquatting(pkg)
        if findings:
            detected += 1
            print(f"  [PASS] '{pkg.name}' → {findings[0].title}")
        else:
            print(f"  [MISS] '{pkg.name}' → no findings (may be expected for subtle typos)")

    print(f"\n  --- Should NOT detect ---")
    false_positives = 0
    for pkg in safe:
        findings = check_typosquatting(pkg)
        if findings:
            false_positives += 1
            print(f"  [FALSE POS] '{pkg.name}' → {findings[0].title}")
        else:
            print(f"  [PASS] '{pkg.name}' → correctly allowed")

    print(f"\n  Detected {detected}/{len(typosquats)} typosquats, {false_positives} false positives\n")


def test_live_checks():
    print("=" * 50)
    print("TEST: Live API Checks")
    print("=" * 50)

    # Test a well-known safe package
    print("\n  --- Safe package: requests ---")
    pkg = PackageRef("requests", None, "pypi", "requests")
    findings = run_all_checks(pkg)
    blocking = [f for f in findings if f.should_block]
    print(f"  Findings: {len(findings)} total, {len(blocking)} blocking")
    for f in findings:
        print(f"    [{f.severity.upper()}] {f.title}")

    # Test litellm (may be quarantined/removed)
    print("\n  --- Potentially compromised: litellm ---")
    pkg = PackageRef("litellm", None, "pypi", "litellm")
    findings = run_all_checks(pkg)
    blocking = [f for f in findings if f.should_block]
    print(f"  Findings: {len(findings)} total, {len(blocking)} blocking")
    for f in findings:
        print(f"    [{f.severity.upper()}] {f.title}")

    # Test a likely-nonexistent typosquat
    print("\n  --- Fake typosquat: reqeusts ---")
    pkg = PackageRef("reqeusts", None, "pypi", "reqeusts")
    findings = run_all_checks(pkg)
    blocking = [f for f in findings if f.should_block]
    print(f"  Findings: {len(findings)} total, {len(blocking)} blocking")
    for f in findings:
        print(f"    [{f.severity.upper()}] {f.title}")


def test_hook_simulation():
    print("=" * 50)
    print("TEST: Hook Simulation (stdin → decision)")
    print("=" * 50)

    # Simulate what Claude Code sends
    test_cases = [
        {
            "desc": "pip install requests (safe)",
            "input": {"tool_name": "Bash", "tool_input": {"command": "pip install requests"}},
        },
        {
            "desc": "npm install expresss (typosquat)",
            "input": {"tool_name": "Bash", "tool_input": {"command": "npm install expresss"}},
        },
        {
            "desc": "ls -la (not an install)",
            "input": {"tool_name": "Bash", "tool_input": {"command": "ls -la"}},
        },
    ]

    for case in test_cases:
        print(f"\n  --- {case['desc']} ---")
        inp = case["input"]
        cmd = inp["tool_input"]["command"]
        pkgs = parse_command(cmd)
        if not pkgs:
            print(f"  → Not an install command, would ALLOW")
            continue

        all_findings = []
        for pkg in pkgs:
            all_findings.extend(run_all_checks(pkg))

        blocking = [f for f in all_findings if f.should_block]
        if blocking:
            print(f"  → Would BLOCK ({len(blocking)} critical/high findings)")
            for f in blocking:
                print(f"    [{f.severity.upper()}] {f.title}")
        elif all_findings:
            print(f"  → Would ALLOW with {len(all_findings)} warnings")
        else:
            print(f"  → Would ALLOW (all clear)")


if __name__ == "__main__":
    print("\n  sec-check test suite\n")

    test_parsers()
    test_typosquatting()
    test_live_checks()
    test_hook_simulation()

    print("\n  Done.\n")
