"""
Package manager command parsers.
Extracts package names (and optionally versions) from install commands
across pip, npm, go, cargo, gem, uv, pipx, and more.
"""

import os
import re
import shlex
from dataclasses import dataclass
from typing import Optional

# Synthetic package names for installs we can't inspect
DYNAMIC_INSTALL = "__DYNAMIC_INSTALL__"
PIPED_INSTALL = "__PIPED_INSTALL__"


@dataclass
class PackageRef:
    """A parsed reference to a package someone is trying to install."""
    name: str
    version: Optional[str]  # None means "latest" / unspecified
    ecosystem: str           # "pypi", "npm", "go", "cargo", "gem"
    raw: str                 # original command fragment


# ── Quote-aware command chain splitting ─────────────────────────────────────

def _split_command_chains(command: str) -> list[tuple[str, Optional[str]]]:
    """
    Split a command string on &&, ||, ;, and | while respecting quotes.
    Returns list of (sub_command, operator) tuples.
    The operator is what follows the sub_command (None for the last one).
    """
    chains: list[tuple[str, Optional[str]]] = []
    current: list[str] = []
    in_single = False
    in_double = False
    i = 0
    chars = command

    while i < len(chars):
        c = chars[i]

        # Track quote state
        if c == "'" and not in_double:
            in_single = not in_single
            current.append(c)
            i += 1
            continue
        if c == '"' and not in_single:
            in_double = not in_double
            current.append(c)
            i += 1
            continue

        # Only split when outside quotes
        if not in_single and not in_double:
            # Check for && or ||
            if i + 1 < len(chars):
                two = chars[i:i+2]
                if two == "&&" or two == "||":
                    chains.append(("".join(current).strip(), two))
                    current = []
                    i += 2
                    continue
            # Check for ; or |
            if c == ";":
                chains.append(("".join(current).strip(), ";"))
                current = []
                i += 1
                continue
            if c == "|":
                chains.append(("".join(current).strip(), "|"))
                current = []
                i += 1
                continue

        current.append(c)
        i += 1

    # Last segment
    final = "".join(current).strip()
    if final:
        chains.append((final, None))

    return chains


# ── Command normalization ───────────────────────────────────────────────────

_WRAPPER_COMMANDS = {"sudo", "env", "nice", "nohup", "command", "builtin", "exec", "time"}

_SUDO_FLAGS = {
    "-A", "-b", "-E", "-e", "-H", "-h", "-K", "-k", "-n", "-P", "-S", "-s",
    "--preserve-env", "--login", "--non-interactive", "--stdin",
}
_SUDO_FLAGS_WITH_ARG = {"-u", "-g", "-C", "-D", "-p", "-r", "-t", "--user", "--group"}


def _normalize_sub_command(sub: str) -> str:
    """
    Strip prefixes that defeat ^-anchored regex matching:
    - Environment variable assignments (VAR=value)
    - Wrapper commands (sudo, env, nice, etc.)
    - Full paths (/usr/bin/pip -> pip)
    """
    try:
        tokens = shlex.split(sub)
    except ValueError:
        tokens = sub.split()

    if not tokens:
        return ""

    i = 0

    # Strip leading VAR=value assignments
    while i < len(tokens) and re.match(r'^[A-Za-z_]\w*=', tokens[i]):
        i += 1

    # Strip wrapper commands
    while i < len(tokens) and tokens[i] in _WRAPPER_COMMANDS:
        wrapper = tokens[i]
        i += 1

        if wrapper == "sudo":
            # Skip sudo flags
            while i < len(tokens):
                if tokens[i] in _SUDO_FLAGS:
                    i += 1
                elif tokens[i] in _SUDO_FLAGS_WITH_ARG:
                    i += 2  # skip flag + its argument
                elif tokens[i].startswith("-"):
                    i += 1  # skip unknown sudo flag
                else:
                    break
        elif wrapper == "env":
            # env can have VAR=value before the command
            while i < len(tokens) and re.match(r'^[A-Za-z_]\w*=', tokens[i]):
                i += 1
        elif wrapper == "nice":
            # nice -n N
            if i < len(tokens) and tokens[i] == "-n":
                i += 2

    if i >= len(tokens):
        return ""

    # Handle xargs — everything after xargs is the actual command
    if tokens[i] == "xargs":
        i += 1
        # Skip xargs flags
        while i < len(tokens) and tokens[i].startswith("-"):
            if tokens[i] in ("-I", "-L", "-n", "-P", "-s"):
                i += 2  # flag with argument
            else:
                i += 1
        if i >= len(tokens):
            return ""

    # Apply basename to the command itself (strips /usr/bin/pip -> pip)
    tokens[i] = os.path.basename(tokens[i])

    # Rejoin remaining tokens
    return " ".join(tokens[i:])


# ── Argument tokenization ──────────────────────────────────────────────────

def _tokenize_args(args_str: str) -> list[str]:
    """Tokenize arguments using shlex (handles quoted args). Fallback to split."""
    try:
        return shlex.split(args_str)
    except ValueError:
        return args_str.split()


# ── Command substitution detection ─────────────────────────────────────────

def _has_command_substitution(s: str) -> bool:
    """Check if a string contains shell command substitution."""
    return "$(" in s or "`" in s


# ── pip / pip3 / python -m pip ───────────────────────────────────────────────

_PIP_SKIP = {
    "-r", "--requirement", "-c", "--constraint", "-e", "--editable",
    "-f", "--find-links", "-i", "--index-url", "--extra-index-url",
    "--no-index", "--prefix", "--root", "--target", "-t",
    "--break-system-packages", "--user", "--upgrade", "-U",
    "--force-reinstall", "--no-deps", "--pre", "--no-cache-dir",
    "--quiet", "-q", "--verbose", "-v", "--dry-run",
    "--system", "--python", "--force",
    "--include-deps", "--suffix",
}

_PIP_FLAGS_WITH_ARG = {
    "-r", "--requirement", "-c", "--constraint", "-e", "--editable",
    "-f", "--find-links", "-i", "--index-url", "--extra-index-url",
    "--prefix", "--root", "--target", "-t",
    "--python", "--suffix",
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
        # Skip local paths and URLs
        if tok in (".", "..") or tok.startswith("./") or tok.startswith("/") or tok.startswith("git+") or "://" in tok:
            continue
        # e.g. "litellm==1.82.7", "requests>=2.28", "flask", "requests[security]"
        match = re.match(r'^([A-Za-z0-9_][A-Za-z0-9._-]*)(?:\[[\w,.-]+\])?\s*(?:[=<>!~]+\s*(.+))?$', tok)
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

# Patterns: (regex matching the command prefix, parser function, ecosystem)
_INSTALL_PATTERNS: list[tuple[re.Pattern, callable, str]] = [
    # uv pip install ...
    (re.compile(
        r'^uv\s+pip\s+install\s+(.+)$', re.IGNORECASE
    ), parse_pip, "pypi"),
    # uv add ...
    (re.compile(
        r'^uv\s+add\s+(.+)$', re.IGNORECASE
    ), parse_pip, "pypi"),
    # pipx install/run ...
    (re.compile(
        r'^pipx\s+(?:install|run)\s+(.+)$', re.IGNORECASE
    ), parse_pip, "pypi"),
    # pip install ..., pip3 install ..., python -m pip install ...
    (re.compile(
        r'^(?:pip3?|python3?\s+-m\s+pip)\s+install\s+(.+)$', re.IGNORECASE
    ), parse_pip, "pypi"),
    # npm install ..., npm i ..., npm add ...
    (re.compile(
        r'^(?:npm|npx|yarn|pnpm)\s+(?:install|add|i)\s+(.+)$', re.IGNORECASE
    ), parse_npm, "npm"),
    # bun install/add ...
    (re.compile(
        r'^(?:bun|bunx)\s+(?:install|add|i)\s+(.+)$', re.IGNORECASE
    ), parse_npm, "npm"),
    # go install ..., go get ...
    (re.compile(
        r'^go\s+(?:install|get)\s+(.+)$', re.IGNORECASE
    ), parse_go, "go"),
    # cargo install ...
    (re.compile(
        r'^cargo\s+install\s+(.+)$', re.IGNORECASE
    ), parse_cargo, "cargo"),
    # gem install ...
    (re.compile(
        r'^gem\s+install\s+(.+)$', re.IGNORECASE
    ), parse_gem, "gem"),
]


def parse_command(command: str) -> list[PackageRef]:
    """
    Given a raw shell command string, detect if it's a package install
    and return all PackageRef objects found.  Returns [] if it's not
    an install command.
    """
    command = command.strip()
    if not command:
        return []

    all_packages = []
    chains = _split_command_chains(command)

    for idx, (sub, operator) in enumerate(chains):
        sub = sub.strip()
        if not sub:
            continue

        # Normalize: strip sudo, env vars, full paths
        normalized = _normalize_sub_command(sub)
        if not normalized:
            continue

        # Check for command substitution in the arguments
        if _has_command_substitution(normalized):
            # See if the base command is an install command
            cleaned = re.sub(r'\$\([^)]*\)', 'UNKNOWN_PKG', normalized)
            cleaned = re.sub(r'`[^`]*`', 'UNKNOWN_PKG', cleaned)
            for pattern, parser, ecosystem in _INSTALL_PATTERNS:
                m = pattern.match(cleaned)
                if m:
                    all_packages.append(PackageRef(
                        name=DYNAMIC_INSTALL,
                        version=None,
                        ecosystem=ecosystem,
                        raw=sub,
                    ))
                    break
            continue

        # Normal regex matching
        for pattern, parser, ecosystem in _INSTALL_PATTERNS:
            m = pattern.match(normalized)
            if m:
                tokens = _tokenize_args(m.group(1))
                all_packages.extend(parser(tokens))
                break

    # Handle pipe constructs: check if the right side of a pipe is an install command
    for idx, (sub, operator) in enumerate(chains):
        if operator == "|" and idx + 1 < len(chains):
            next_sub = chains[idx + 1][0].strip()
            next_normalized = _normalize_sub_command(next_sub)
            if not next_normalized:
                continue
            # Check if the piped-into command is an install command
            for pattern, parser, ecosystem in _INSTALL_PATTERNS:
                # Try matching even if the install command has no explicit package args
                # (they'd come from the pipe)
                if pattern.match(next_normalized) or _is_install_base(next_normalized, ecosystem):
                    all_packages.append(PackageRef(
                        name=PIPED_INSTALL,
                        version=None,
                        ecosystem=ecosystem,
                        raw=f"{sub} | {next_sub}",
                    ))
                    break

    return all_packages


# ── Pipe install detection helper ────────────────────────────────────────────

_INSTALL_KEYWORDS = {
    "pip": "pypi", "pip3": "pypi",
    "npm": "npm", "npx": "npm", "yarn": "npm", "pnpm": "npm",
    "bun": "npm", "bunx": "npm",
    "go": "go",
    "cargo": "cargo",
    "gem": "gem",
    "uv": "pypi",
    "pipx": "pypi",
}

_INSTALL_SUBCOMMANDS = {"install", "add", "i", "get"}


def _is_install_base(normalized: str, ecosystem: str) -> bool:
    """Check if a normalized command looks like a package install (even without args)."""
    tokens = normalized.split()
    if len(tokens) < 2:
        return False
    cmd = tokens[0].lower()
    if cmd not in _INSTALL_KEYWORDS:
        return False
    if _INSTALL_KEYWORDS[cmd] != ecosystem:
        return False
    subcmd = tokens[1].lower()
    # Special case: uv pip install
    if cmd == "uv" and len(tokens) >= 3 and subcmd == "pip" and tokens[2].lower() == "install":
        return True
    return subcmd in _INSTALL_SUBCOMMANDS
