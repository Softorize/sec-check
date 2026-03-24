"""
Package manager command parsers.
Extracts package names (and optionally versions) from install commands
across pip, npm, go, cargo, gem, and more.
"""

import re
from dataclasses import dataclass
from typing import Optional


@dataclass
class PackageRef:
    """A parsed reference to a package someone is trying to install."""
    name: str
    version: Optional[str]  # None means "latest" / unspecified
    ecosystem: str           # "pypi", "npm", "go", "cargo", "gem"
    raw: str                 # original command fragment


# ── pip / pip3 / python -m pip ───────────────────────────────────────────────
_PIP_SKIP = {
    "-r", "--requirement", "-c", "--constraint", "-e", "--editable",
    "-f", "--find-links", "-i", "--index-url", "--extra-index-url",
    "--no-index", "--prefix", "--root", "--target", "-t",
    "--break-system-packages", "--user", "--upgrade", "-U",
    "--force-reinstall", "--no-deps", "--pre", "--no-cache-dir",
    "--quiet", "-q", "--verbose", "-v", "--dry-run",
}

_PIP_FLAGS_WITH_ARG = {
    "-r", "--requirement", "-c", "--constraint", "-e", "--editable",
    "-f", "--find-links", "-i", "--index-url", "--extra-index-url",
    "--prefix", "--root", "--target", "-t",
}


def parse_pip(tokens: list[str]) -> list[PackageRef]:
    """Parse pip install tokens into PackageRef list."""
    packages = []
    skip_next = False
    for tok in tokens:
        if skip_next:
            skip_next = False
            continue
        if tok in _PIP_FLAGS_WITH_ARG:
            skip_next = True
            continue
        if tok.startswith("-"):
            continue
        # e.g. "litellm==1.82.7", "requests>=2.28", "flask"
        match = re.match(r'^([A-Za-z0-9_][A-Za-z0-9._-]*)\s*(?:[=<>!~]+\s*(.+))?$', tok)
        if match:
            name, ver = match.group(1), match.group(2)
            packages.append(PackageRef(name=name, version=ver, ecosystem="pypi", raw=tok))
    return packages


# ── npm / yarn / pnpm ────────────────────────────────────────────────────────
_NPM_SKIP_FLAGS = {
    "--save", "--save-dev", "--save-exact", "-S", "-D", "-E",
    "--global", "-g", "--legacy-peer-deps", "--force",
    "--no-save", "--production", "--ignore-scripts",
}

_NPM_FLAGS_WITH_ARG = {
    "--registry", "--prefix",
}


def parse_npm(tokens: list[str]) -> list[PackageRef]:
    """Parse npm/yarn/pnpm install/add tokens into PackageRef list."""
    packages = []
    skip_next = False
    for tok in tokens:
        if skip_next:
            skip_next = False
            continue
        if tok in _NPM_FLAGS_WITH_ARG:
            skip_next = True
            continue
        if tok.startswith("-"):
            continue
        # e.g. "express@4.18.2", "@types/node", "lodash"
        match = re.match(r'^(@?[A-Za-z0-9_][A-Za-z0-9._/-]*)(?:@(.+))?$', tok)
        if match:
            name, ver = match.group(1), match.group(2)
            packages.append(PackageRef(name=name, version=ver, ecosystem="npm", raw=tok))
    return packages


# ── go get ───────────────────────────────────────────────────────────────────
def parse_go(tokens: list[str]) -> list[PackageRef]:
    packages = []
    for tok in tokens:
        if tok.startswith("-"):
            continue
        # e.g. "github.com/gin-gonic/gin@v1.9.1"
        match = re.match(r'^([A-Za-z0-9._/-]+?)(?:@(.+))?$', tok)
        if match:
            packages.append(PackageRef(
                name=match.group(1), version=match.group(2),
                ecosystem="go", raw=tok,
            ))
    return packages


# ── cargo install ────────────────────────────────────────────────────────────
def parse_cargo(tokens: list[str]) -> list[PackageRef]:
    packages = []
    skip_next = False
    for tok in tokens:
        if skip_next:
            skip_next = False
            continue
        if tok in {"--version", "--vers", "--git", "--branch", "--tag", "--rev", "--path"}:
            skip_next = True
            continue
        if tok.startswith("-"):
            continue
        packages.append(PackageRef(name=tok, version=None, ecosystem="cargo", raw=tok))
    return packages


# ── gem install ──────────────────────────────────────────────────────────────
def parse_gem(tokens: list[str]) -> list[PackageRef]:
    packages = []
    skip_next = False
    for tok in tokens:
        if skip_next:
            skip_next = False
            continue
        if tok in {"-v", "--version", "-i", "--install-dir", "--bindir"}:
            skip_next = True
            continue
        if tok.startswith("-"):
            continue
        packages.append(PackageRef(name=tok, version=None, ecosystem="gem", raw=tok))
    return packages


# ── Master dispatcher ────────────────────────────────────────────────────────

# Patterns: (regex matching the command prefix, parser function)
_INSTALL_PATTERNS: list[tuple[re.Pattern, callable]] = [
    # pip install ..., pip3 install ..., python -m pip install ...
    (re.compile(
        r'^(?:pip3?|python3?\s+-m\s+pip)\s+install\s+(.+)$', re.IGNORECASE
    ), parse_pip),
    # npm install ..., npm i ..., npm add ...
    (re.compile(
        r'^(?:npm|npx|yarn|pnpm)\s+(?:install|add|i)\s+(.+)$', re.IGNORECASE
    ), parse_npm),
    # go install ..., go get ...
    (re.compile(
        r'^go\s+(?:install|get)\s+(.+)$', re.IGNORECASE
    ), parse_go),
    # cargo install ...
    (re.compile(
        r'^cargo\s+install\s+(.+)$', re.IGNORECASE
    ), parse_cargo),
    # gem install ...
    (re.compile(
        r'^gem\s+install\s+(.+)$', re.IGNORECASE
    ), parse_gem),
]


def parse_command(command: str) -> list[PackageRef]:
    """
    Given a raw shell command string, detect if it's a package install
    and return all PackageRef objects found.  Returns [] if it's not
    an install command.
    """
    command = command.strip()
    # Handle command chaining (&&, ;, ||)
    # We check each sub-command independently
    all_packages = []
    for sub in re.split(r'\s*(?:&&|\|\||;)\s*', command):
        sub = sub.strip()
        for pattern, parser in _INSTALL_PATTERNS:
            m = pattern.match(sub)
            if m:
                tokens = m.group(1).split()
                all_packages.extend(parser(tokens))
                break
    return all_packages
