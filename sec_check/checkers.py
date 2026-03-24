"""
Security checkers for packages.
Each checker returns a list of Finding objects.
"""

import json
import urllib.request
import urllib.error
import re
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional
from difflib import SequenceMatcher

from .parsers import PackageRef


# ─── Data structures ─────────────────────────────────────────────────────────

@dataclass
class Finding:
    """A single security finding about a package."""
    severity: str          # "critical", "high", "medium", "low", "info"
    check_name: str        # e.g. "known_vulnerability", "typosquatting"
    title: str             # short summary
    detail: str            # full explanation
    package: str
    ecosystem: str
    references: list[str] = field(default_factory=list)

    @property
    def should_block(self) -> bool:
        return self.severity in ("critical", "high")


@dataclass
class FetchResult:
    """Result of an HTTP fetch, distinguishing success/404/error."""
    data: Optional[dict] = None
    status_code: Optional[int] = None  # 200=success, 404=not found, None=error
    error: Optional[str] = None


@dataclass
class CheckResult:
    """Aggregated result from run_all_checks."""
    findings: list[Finding]
    total_checkers: int
    failed_checkers: int
    checker_errors: list[str] = field(default_factory=list)


# ─── Metadata Cache ──────────────────────────────────────────────────────────

class MetadataCache:
    """In-memory cache for registry metadata within a single check run."""

    def __init__(self, disk_cache=None):
        self._store: dict[str, FetchResult] = {}
        self._disk = disk_cache  # Optional DiskCache instance

    def get_pypi(self, name: str) -> FetchResult:
        key = f"pypi:{name}"
        if key in self._store:
            return self._store[key]

        # Check disk cache
        if self._disk:
            cached = self._disk.get(key)
            if cached is not None:
                result = FetchResult(data=cached, status_code=200)
                self._store[key] = result
                return result

        result = _fetch_with_status(f"https://pypi.org/pypi/{name}/json")
        self._store[key] = result

        if self._disk and result.data:
            self._disk.set(key, result.data)

        return result

    def get_npm(self, name: str) -> FetchResult:
        key = f"npm:{name}"
        if key in self._store:
            return self._store[key]

        if self._disk:
            cached = self._disk.get(key)
            if cached is not None:
                result = FetchResult(data=cached, status_code=200)
                self._store[key] = result
                return result

        result = _fetch_with_status(f"https://registry.npmjs.org/{name}")
        self._store[key] = result

        if self._disk and result.data:
            self._disk.set(key, result.data)

        return result


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _http_get_json(url: str, timeout: int = 10) -> Optional[dict]:
    """Fetch JSON from a URL. Returns None on any failure."""
    try:
        ctx = ssl.create_default_context()
        req = urllib.request.Request(url, headers={"User-Agent": "sec-check/1.0"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return json.loads(resp.read())
    except Exception:
        return None


def _http_post_json(url: str, body: dict, timeout: int = 10) -> Optional[dict]:
    """POST JSON to a URL. Returns None on any failure."""
    try:
        ctx = ssl.create_default_context()
        data = json.dumps(body).encode()
        req = urllib.request.Request(
            url, data=data,
            headers={"User-Agent": "sec-check/1.0", "Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return json.loads(resp.read())
    except Exception:
        return None


def _fetch_with_status(url: str, timeout: int = 10) -> FetchResult:
    """Fetch JSON from a URL, returning status code for error differentiation."""
    try:
        ctx = ssl.create_default_context()
        req = urllib.request.Request(url, headers={"User-Agent": "sec-check/1.0"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = json.loads(resp.read())
            return FetchResult(data=data, status_code=200)
    except urllib.error.HTTPError as e:
        return FetchResult(data=None, status_code=e.code, error=str(e))
    except Exception as e:
        return FetchResult(data=None, status_code=None, error=str(e))


# ─── Version resolution ─────────────────────────────────────────────────────

def _resolve_latest_version(pkg: PackageRef, cache: MetadataCache) -> Optional[str]:
    """Resolve the latest version of a package from registry metadata."""
    if pkg.ecosystem == "pypi":
        result = cache.get_pypi(pkg.name)
        if result.data:
            return result.data.get("info", {}).get("version")
    elif pkg.ecosystem == "npm":
        result = cache.get_npm(pkg.name)
        if result.data:
            return result.data.get("dist-tags", {}).get("latest")
    return None


# ─── 0. Suspicious Install Check ────────────────────────────────────────────

def check_suspicious_install(pkg: PackageRef, cache: MetadataCache) -> list[Finding]:
    """Flag installs where we can't determine the package name."""
    if pkg.name == "__DYNAMIC_INSTALL__":
        return [Finding(
            severity="high",
            check_name="dynamic_install",
            title="Install command uses dynamic/computed package name",
            detail=(
                f"The install command uses shell substitution ($() or backticks) "
                f"to compute the package name dynamically: {pkg.raw}\n\n"
                f"sec-check cannot verify the safety of dynamically-computed package names. "
                f"This pattern is suspicious and commonly used in supply-chain attacks."
            ),
            package="<dynamic>",
            ecosystem=pkg.ecosystem,
        )]
    if pkg.name == "__PIPED_INSTALL__":
        return [Finding(
            severity="high",
            check_name="piped_install",
            title="Package install receives input via pipe",
            detail=(
                f"The install command receives package names from a pipe: {pkg.raw}\n\n"
                f"sec-check cannot verify packages passed through pipes. "
                f"Review the full command carefully before allowing."
            ),
            package="<piped>",
            ecosystem=pkg.ecosystem,
        )]
    return []


# ─── 1. Known Vulnerability Check (OSV.dev) ─────────────────────────────────

_OSV_ECOSYSTEM_MAP = {
    "pypi": "PyPI",
    "npm": "npm",
    "go": "Go",
    "cargo": "crates.io",
    "gem": "RubyGems",
}


def check_known_vulnerabilities(pkg: PackageRef, cache: MetadataCache) -> list[Finding]:
    """Query OSV.dev for known vulnerabilities."""
    findings = []
    osv_eco = _OSV_ECOSYSTEM_MAP.get(pkg.ecosystem)
    if not osv_eco:
        return findings

    body: dict = {"package": {"name": pkg.name, "ecosystem": osv_eco}}

    version_to_check = pkg.version
    resolved_version = None

    if not version_to_check:
        # Resolve latest version from registry to avoid returning all historical CVEs
        resolved_version = _resolve_latest_version(pkg, cache)
        if resolved_version:
            version_to_check = resolved_version
            findings.append(Finding(
                severity="info",
                check_name="version_resolved",
                title=f"No version specified; checked against latest ({resolved_version})",
                detail=f"No version was specified in the install command. Checking against the latest version ({resolved_version}) from the registry.",
                package=pkg.name,
                ecosystem=pkg.ecosystem,
            ))

    if version_to_check:
        body["version"] = version_to_check

    data = _http_post_json("https://api.osv.dev/v1/query", body)
    if not data or "vulns" not in data:
        return findings

    for vuln in data["vulns"]:
        vuln_id = vuln.get("id", "unknown")
        summary = vuln.get("summary", "No summary available.")
        severity_list = vuln.get("severity", [])
        cvss_score = None
        for s in severity_list:
            if "score" in s:
                try:
                    cvss_score = float(s["score"])
                except (ValueError, TypeError):
                    pass

        if cvss_score and cvss_score >= 9.0:
            sev = "critical"
        elif cvss_score and cvss_score >= 7.0:
            sev = "high"
        elif cvss_score and cvss_score >= 4.0:
            sev = "medium"
        elif cvss_score is not None:
            sev = "low"
        else:
            # No CVSS score available — default to medium (non-blocking)
            # to avoid false-positive blocking of popular packages
            sev = "medium"

        refs = [r.get("url", "") for r in vuln.get("references", []) if r.get("url")]

        findings.append(Finding(
            severity=sev,
            check_name="known_vulnerability",
            title=f"Known vulnerability: {vuln_id}",
            detail=f"{summary}\n\nVuln ID: {vuln_id}" + (f"\nCVSS: {cvss_score}" if cvss_score else ""),
            package=pkg.name,
            ecosystem=pkg.ecosystem,
            references=refs[:3],
        ))

    return findings


# ─── 2. Typosquatting Detection ──────────────────────────────────────────────

# Top packages per ecosystem (curated — extend as needed)
_POPULAR_PACKAGES = {
    "pypi": [
        "requests", "flask", "django", "numpy", "pandas", "scipy", "boto3",
        "tensorflow", "torch", "pytest", "setuptools", "pip", "wheel",
        "cryptography", "pillow", "sqlalchemy", "celery", "redis", "httpx",
        "fastapi", "uvicorn", "pydantic", "litellm", "openai", "anthropic",
        "langchain", "transformers", "scikit-learn", "matplotlib", "aiohttp",
        "beautifulsoup4", "selenium", "scrapy", "paramiko", "fabric",
        "black", "ruff", "mypy", "rich", "click", "typer", "httptools",
        "starlette", "gunicorn", "psycopg2", "pymongo", "elasticsearch",
        "aws-cdk-lib", "google-cloud-storage", "azure-storage-blob",
    ],
    "npm": [
        "express", "react", "vue", "angular", "next", "axios", "lodash",
        "moment", "dayjs", "webpack", "vite", "typescript", "eslint",
        "prettier", "jest", "mocha", "chalk", "commander", "inquirer",
        "dotenv", "cors", "jsonwebtoken", "bcrypt", "mongoose", "prisma",
        "sequelize", "socket.io", "nodemon", "pm2", "fastify", "openai",
        "langchain", "@anthropic-ai/sdk", "zod", "trpc", "tailwindcss",
    ],
    "go": [
        "github.com/gin-gonic/gin", "github.com/gorilla/mux",
        "github.com/go-chi/chi", "github.com/stretchr/testify",
    ],
    "cargo": [
        "serde", "tokio", "reqwest", "clap", "rand", "hyper", "actix-web",
        "axum", "diesel", "sqlx", "tracing",
    ],
    "gem": [
        "rails", "sinatra", "rspec", "puma", "sidekiq", "devise", "nokogiri",
        "httparty", "faraday", "redis",
    ],
}

# Common typosquatting tricks
_TYPO_SUBSTITUTIONS = {
    "-": ["_", "", "."],
    "_": ["-", "", "."],
    "l": ["1", "i"],
    "1": ["l", "i"],
    "0": ["o"],
    "o": ["0"],
    "rn": ["m"],
    "m": ["rn"],
}


def _similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a.lower(), b.lower()).ratio()


def check_typosquatting(pkg: PackageRef, cache: MetadataCache) -> list[Finding]:
    """Check if the package name looks like a typosquat of a popular package."""
    findings = []
    popular = _POPULAR_PACKAGES.get(pkg.ecosystem, [])
    name_lower = pkg.name.lower()

    for legit in popular:
        legit_lower = legit.lower()
        if name_lower == legit_lower:
            continue  # exact match — it's the real one

        sim = _similarity(name_lower, legit_lower)

        # Very high similarity (but not exact)
        if sim >= 0.85:
            findings.append(Finding(
                severity="high",
                check_name="typosquatting",
                title=f"Possible typosquat of '{legit}'",
                detail=(
                    f"Package '{pkg.name}' has {sim:.0%} similarity to the popular "
                    f"package '{legit}'. This could be a typosquatting attack.\n\n"
                    f"Did you mean: {legit}?"
                ),
                package=pkg.name,
                ecosystem=pkg.ecosystem,
            ))
            break

        # Check common substitution tricks
        for char, replacements in _TYPO_SUBSTITUTIONS.items():
            if char in legit_lower:
                for repl in replacements:
                    variant = legit_lower.replace(char, repl)
                    if name_lower == variant and name_lower != legit_lower:
                        findings.append(Finding(
                            severity="high",
                            check_name="typosquatting",
                            title=f"Likely typosquat of '{legit}'",
                            detail=(
                                f"Package '{pkg.name}' matches a known typosquatting "
                                f"pattern ('{char}' -> '{repl}') of popular package "
                                f"'{legit}'.\n\nDid you mean: {legit}?"
                            ),
                            package=pkg.name,
                            ecosystem=pkg.ecosystem,
                        ))
                        break

    return findings


# ─── 3. Package Metadata Analysis ───────────────────────────────────────────

def check_package_metadata(pkg: PackageRef, cache: MetadataCache) -> list[Finding]:
    """
    Analyze package registry metadata for red flags:
    - Very new package with few downloads
    - Recent maintainer change
    - Suspiciously recent version of an old package
    - Missing or suspicious project URLs
    """
    findings = []

    if pkg.ecosystem == "pypi":
        findings.extend(_check_pypi_metadata(pkg, cache))
    elif pkg.ecosystem == "npm":
        findings.extend(_check_npm_metadata(pkg, cache))

    return findings


def _check_pypi_metadata(pkg: PackageRef, cache: MetadataCache) -> list[Finding]:
    findings = []
    result = cache.get_pypi(pkg.name)

    if not result.data:
        if result.status_code != 404:  # 404 is handled by check_package_exists
            findings.append(Finding(
                severity="medium",
                check_name="metadata_unavailable",
                title=f"Cannot fetch metadata for '{pkg.name}'",
                detail="Could not retrieve package metadata from PyPI. The package may not exist, may have been removed, or PyPI may be unreachable.",
                package=pkg.name,
                ecosystem="pypi",
            ))
        return findings

    data = result.data
    info = data.get("info", {})
    releases = data.get("releases", {})

    # Check 1: Package age — very new packages are riskier
    all_upload_times = []
    for ver, files in releases.items():
        for f in files:
            if f.get("upload_time_iso_8601"):
                try:
                    t = datetime.fromisoformat(f["upload_time_iso_8601"].replace("Z", "+00:00"))
                    all_upload_times.append(t)
                except (ValueError, TypeError):
                    pass

    if all_upload_times:
        first_upload = min(all_upload_times)
        latest_upload = max(all_upload_times)
        now = datetime.now(timezone.utc)
        age = now - first_upload

        if age < timedelta(days=7):
            findings.append(Finding(
                severity="medium",
                check_name="new_package",
                title=f"Very new package (created {age.days}d ago)",
                detail=(
                    f"'{pkg.name}' was first published {age.days} days ago "
                    f"({first_upload.strftime('%Y-%m-%d')}). New packages carry "
                    f"higher supply-chain risk."
                ),
                package=pkg.name,
                ecosystem="pypi",
            ))

        # Check for suspiciously rapid new version on old package
        if age > timedelta(days=365) and (now - latest_upload) < timedelta(hours=48):
            findings.append(Finding(
                severity="high",
                check_name="suspicious_new_version",
                title="Very recent version on established package",
                detail=(
                    f"'{pkg.name}' has existed for {age.days} days but its latest "
                    f"release was uploaded within the last 48 hours "
                    f"({latest_upload.strftime('%Y-%m-%d %H:%M UTC')}). "
                    f"This pattern matches supply-chain compromises like the litellm "
                    f"incident where attackers push malicious versions of trusted packages."
                ),
                package=pkg.name,
                ecosystem="pypi",
            ))

    # Check 2: Missing project URLs / description
    if not info.get("home_page") and not info.get("project_url") and not info.get("project_urls"):
        findings.append(Finding(
            severity="low",
            check_name="missing_urls",
            title="No project homepage or repository URL",
            detail=f"'{pkg.name}' has no homepage or repository link. Legitimate packages typically link to their source code.",
            package=pkg.name,
            ecosystem="pypi",
        ))

    # Check 3: Very few releases can indicate a placeholder / attack package
    if len(releases) <= 1 and all_upload_times:
        age = datetime.now(timezone.utc) - min(all_upload_times)
        if age < timedelta(days=30):
            findings.append(Finding(
                severity="medium",
                check_name="single_release",
                title="Single-release package",
                detail=f"'{pkg.name}' has only {len(releases)} release(s) and was created recently. This could indicate a malicious placeholder package.",
                package=pkg.name,
                ecosystem="pypi",
            ))

    # Check 4: Author email looks suspicious
    author_email = info.get("author_email", "") or ""
    if author_email and any(x in author_email.lower() for x in ["temp", "disposable", "guerrilla", "yopmail", "mailinator"]):
        findings.append(Finding(
            severity="medium",
            check_name="suspicious_author",
            title="Suspicious author email",
            detail=f"The author email '{author_email}' uses a disposable email service, which is unusual for legitimate packages.",
            package=pkg.name,
            ecosystem="pypi",
        ))

    # Check 5: URL-based dependencies in requires_dist (supply-chain vector)
    requires_dist = info.get("requires_dist") or []
    for req in requires_dist:
        if isinstance(req, str) and "@" in req and ("http://" in req or "https://" in req):
            findings.append(Finding(
                severity="high",
                check_name="url_dependency",
                title=f"URL-based dependency: {req[:80]}",
                detail=(
                    f"'{pkg.name}' has a dependency that points to a URL: {req}\n\n"
                    f"URL-based dependencies can be used to inject malicious packages "
                    f"from arbitrary sources."
                ),
                package=pkg.name,
                ecosystem="pypi",
            ))

    return findings


def _check_npm_metadata(pkg: PackageRef, cache: MetadataCache) -> list[Finding]:
    findings = []
    result = cache.get_npm(pkg.name)

    if not result.data:
        if result.status_code != 404:
            findings.append(Finding(
                severity="medium",
                check_name="metadata_unavailable",
                title=f"Cannot fetch metadata for '{pkg.name}'",
                detail="Could not retrieve package metadata from npm registry.",
                package=pkg.name,
                ecosystem="npm",
            ))
        return findings

    data = result.data
    time_data = data.get("time", {})
    created_str = time_data.get("created")
    modified_str = time_data.get("modified")

    if created_str:
        try:
            created = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
            now = datetime.now(timezone.utc)
            age = now - created

            if age < timedelta(days=7):
                findings.append(Finding(
                    severity="medium",
                    check_name="new_package",
                    title=f"Very new package (created {age.days}d ago)",
                    detail=f"'{pkg.name}' was first published {age.days} days ago on npm.",
                    package=pkg.name,
                    ecosystem="npm",
                ))

            if modified_str and age > timedelta(days=365):
                modified = datetime.fromisoformat(modified_str.replace("Z", "+00:00"))
                if (now - modified) < timedelta(hours=48):
                    findings.append(Finding(
                        severity="high",
                        check_name="suspicious_new_version",
                        title="Very recent version on established package",
                        detail=(
                            f"'{pkg.name}' has existed for {age.days} days but was "
                            f"modified within the last 48 hours. This is a red flag for "
                            f"supply-chain attacks."
                        ),
                        package=pkg.name,
                        ecosystem="npm",
                    ))
        except (ValueError, TypeError):
            pass

    # Check maintainer count — single maintainer on popular package is risky
    maintainers = data.get("maintainers", [])
    if len(maintainers) == 1:
        findings.append(Finding(
            severity="info",
            check_name="single_maintainer",
            title="Single maintainer",
            detail=f"'{pkg.name}' has only one npm maintainer. Compromising a single account could lead to a supply-chain attack.",
            package=pkg.name,
            ecosystem="npm",
        ))

    return findings


# ─── 4. Install Script / Post-install Analysis ──────────────────────────────

_SUSPICIOUS_PATTERNS = [
    (re.compile(r'base64', re.IGNORECASE), "base64 encoding (potential payload obfuscation)"),
    (re.compile(r'eval\s*\('), "eval() usage (dynamic code execution)"),
    (re.compile(r'exec\s*\('), "exec() usage (dynamic code execution)"),
    (re.compile(r'subprocess|os\.system|os\.popen'), "shell command execution"),
    (re.compile(r'socket\.connect|urllib\.request|requests\.(?:get|post)|httpx|aiohttp'), "network call in setup"),
    (re.compile(r'\.ssh|\.aws|\.kube|\.env|credentials', re.IGNORECASE), "credential file access"),
    (re.compile(r'keyring|getpass'), "credential/keyring access"),
    (re.compile(r'\\x[0-9a-f]{2}|\\u[0-9a-f]{4}', re.IGNORECASE), "hex/unicode escape sequences (obfuscation)"),
    (re.compile(r'compile\s*\(\s*["\']'), "dynamic compilation"),
    (re.compile(r'__import__\s*\('), "dynamic import (anti-analysis technique)"),
    (re.compile(r'\.pth\b'), ".pth file creation (persistence mechanism — used in litellm attack)"),
]


def check_install_scripts(pkg: PackageRef, cache: MetadataCache) -> list[Finding]:
    """
    Check for suspicious patterns in package metadata and install scripts.
    - PyPI: scan description, check sdist size
    - npm: scan preinstall/postinstall scripts
    """
    findings = []

    if pkg.ecosystem == "pypi":
        result = cache.get_pypi(pkg.name)
        if not result.data:
            return findings

        data = result.data
        description = data.get("info", {}).get("description", "") or ""

        # Scan description for suspicious patterns
        for pattern, desc in _SUSPICIOUS_PATTERNS:
            if pattern.search(description):
                findings.append(Finding(
                    severity="medium",
                    check_name="suspicious_description",
                    title=f"Suspicious pattern in description: {desc}",
                    detail=f"The package description contains '{desc}'. While not always malicious, this is unusual for package descriptions.",
                    package=pkg.name,
                    ecosystem="pypi",
                ))

        # Check for suspiciously small sdist
        urls = data.get("urls", [])
        sdists = [u for u in urls if u.get("packagetype") == "sdist"]
        if sdists:
            size = sdists[0].get("size", 0)
            if 0 < size < 1000:
                findings.append(Finding(
                    severity="medium",
                    check_name="tiny_sdist",
                    title=f"Suspiciously small source distribution ({size} bytes)",
                    detail=(
                        f"'{pkg.name}' has an sdist of only {size} bytes. "
                        f"Legitimate packages are typically larger. Very small packages "
                        f"may be malicious placeholders."
                    ),
                    package=pkg.name,
                    ecosystem="pypi",
                ))

    elif pkg.ecosystem == "npm":
        result = cache.get_npm(pkg.name)
        if not result.data:
            return findings

        data = result.data
        latest_tag = data.get("dist-tags", {}).get("latest")
        if latest_tag:
            latest_data = data.get("versions", {}).get(latest_tag, {})
            scripts = latest_data.get("scripts", {})
            for hook_name in ("preinstall", "install", "postinstall"):
                if hook_name in scripts:
                    script_content = scripts[hook_name]
                    findings.append(Finding(
                        severity="medium",
                        check_name="install_script",
                        title=f"npm {hook_name} script detected",
                        detail=f"'{pkg.name}' has a '{hook_name}' script: {str(script_content)[:200]}",
                        package=pkg.name,
                        ecosystem="npm",
                    ))
                    # Also scan script content against suspicious patterns
                    for pattern, desc in _SUSPICIOUS_PATTERNS:
                        if isinstance(script_content, str) and pattern.search(script_content):
                            findings.append(Finding(
                                severity="high",
                                check_name="suspicious_install_script",
                                title=f"Suspicious pattern in npm {hook_name}: {desc}",
                                detail=(
                                    f"The '{hook_name}' script contains '{desc}'. "
                                    f"This is a common supply-chain attack vector."
                                ),
                                package=pkg.name,
                                ecosystem="npm",
                            ))

    return findings


# ─── 5. Quarantine / Removal Check ──────────────────────────────────────────

def check_package_exists(pkg: PackageRef, cache: MetadataCache) -> list[Finding]:
    """Check if the package has been removed or quarantined."""
    findings = []

    if pkg.ecosystem == "pypi":
        result = cache.get_pypi(pkg.name)
        if result.status_code == 404:
            findings.append(Finding(
                severity="critical",
                check_name="package_removed",
                title=f"Package '{pkg.name}' not found on PyPI",
                detail=(
                    f"'{pkg.name}' returned 404 on PyPI. The package may have been "
                    f"removed or quarantined due to a security incident. "
                    f"DO NOT install this package."
                ),
                package=pkg.name,
                ecosystem="pypi",
            ))

    elif pkg.ecosystem == "npm":
        result = cache.get_npm(pkg.name)
        if result.status_code == 404:
            findings.append(Finding(
                severity="critical",
                check_name="package_removed",
                title=f"Package '{pkg.name}' not found on npm",
                detail=f"'{pkg.name}' returned 404 on npm. It may have been removed due to a security incident.",
                package=pkg.name,
                ecosystem="npm",
            ))

    return findings


# ─── Master runner ───────────────────────────────────────────────────────────

ALL_CHECKERS = [
    check_suspicious_install,
    check_package_exists,
    check_known_vulnerabilities,
    check_typosquatting,
    check_package_metadata,
    check_install_scripts,
]


def run_all_checks(pkg: PackageRef, disk_cache=None) -> CheckResult:
    """Run all security checks on a single package."""
    cache = MetadataCache(disk_cache=disk_cache)
    findings = []
    failed = 0
    errors = []

    # Short-circuit for synthetic package names (dynamic/piped installs)
    if pkg.name.startswith("__") and pkg.name.endswith("__"):
        try:
            findings.extend(check_suspicious_install(pkg, cache))
        except Exception as e:
            failed += 1
            errors.append(f"check_suspicious_install: {e}")
        return CheckResult(
            findings=findings,
            total_checkers=1,
            failed_checkers=failed,
            checker_errors=errors,
        )

    for checker in ALL_CHECKERS:
        try:
            findings.extend(checker(pkg, cache))
        except Exception as e:
            failed += 1
            errors.append(f"{checker.__name__}: {e}")
            findings.append(Finding(
                severity="info",
                check_name="checker_error",
                title=f"Check '{checker.__name__}' failed",
                detail=f"Error running {checker.__name__}: {e}",
                package=pkg.name,
                ecosystem=pkg.ecosystem,
            ))

    return CheckResult(
        findings=findings,
        total_checkers=len(ALL_CHECKERS),
        failed_checkers=failed,
        checker_errors=errors,
    )
