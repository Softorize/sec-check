#!/usr/bin/env bash
#
# sec-check installer
# Installs the sec-check hook into Claude Code's settings.
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SEC_CHECK_DIR="$SCRIPT_DIR/sec_check"

echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║   sec-check installer                    ║"
echo "  ║   Dependency security gate for AI agents ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""

# 1. Verify Python 3.8+
if ! command -v python3 &>/dev/null; then
    echo "ERROR: python3 is required but not found."
    exit 1
fi

PYTHON_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "  [✓] Python $PYTHON_VER found"

# 2. Verify jq (optional but helpful)
if command -v jq &>/dev/null; then
    HAS_JQ=true
    echo "  [✓] jq found"
else
    HAS_JQ=false
    echo "  [!] jq not found — will use Python for JSON manipulation"
fi

# 3. Determine settings file location
# Support both project-level and user-level settings
echo ""
echo "  Where do you want to install the hook?"
echo "    1) Current project (.claude/settings.json) — recommended"
echo "    2) User-level (~/.claude/settings.json) — applies to all projects"
echo ""
read -rp "  Choice [1/2]: " CHOICE

case "${CHOICE:-1}" in
    2)
        SETTINGS_DIR="$HOME/.claude"
        SCOPE="user-level"
        ;;
    *)
        SETTINGS_DIR=".claude"
        SCOPE="project-level"
        ;;
esac

SETTINGS_FILE="$SETTINGS_DIR/settings.json"

echo ""
echo "  Installing to $SCOPE: $SETTINGS_FILE"

# 4. Create settings directory if needed
mkdir -p "$SETTINGS_DIR"

# 5. Build the hook command
HOOK_CMD="python3 -m sec_check.hook"

# 6. Read existing settings or start fresh
if [ -f "$SETTINGS_FILE" ]; then
    EXISTING=$(cat "$SETTINGS_FILE")
else
    EXISTING="{}"
fi

# 7. Merge hook config using Python (works everywhere)
# NOTE: Using quoted heredoc ('PYEOF') to prevent shell injection.
# Variables are passed via environment, not string interpolation.
SETTINGS_FILE="$SETTINGS_FILE" \
HOOK_CMD="$HOOK_CMD" \
SEC_CHECK_DIR="$SEC_CHECK_DIR" \
python3 << 'PYEOF'
import json
import os
import sys

settings_file = os.environ["SETTINGS_FILE"]
hook_cmd = os.environ["HOOK_CMD"]
sec_check_dir = os.environ["SEC_CHECK_DIR"]

try:
    with open(settings_file, 'r') as f:
        settings = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    settings = {}

# Ensure hooks structure exists
if "hooks" not in settings:
    settings["hooks"] = {}
if "PreToolUse" not in settings["hooks"]:
    settings["hooks"]["PreToolUse"] = []

# Check if sec-check hook already exists
pre_tool_hooks = settings["hooks"]["PreToolUse"]
already_installed = False
for entry in pre_tool_hooks:
    if entry.get("matcher") == "Bash":
        for h in entry.get("hooks", []):
            if "sec_check" in h.get("command", ""):
                already_installed = True
                break

if already_installed:
    print("  [!] sec-check hook is already installed. Skipping.")
    sys.exit(0)

# We need PYTHONPATH so the module can be found
full_cmd = f"PYTHONPATH={sec_check_dir}/.. python3 -m sec_check.hook"

# Add the hook
new_hook_entry = {
    "matcher": "Bash",
    "hooks": [
        {
            "type": "command",
            "command": full_cmd
        }
    ]
}

# Check if there's already a Bash matcher we should add to
bash_matcher_found = False
for entry in pre_tool_hooks:
    if entry.get("matcher") == "Bash":
        entry["hooks"].append({
            "type": "command",
            "command": full_cmd
        })
        bash_matcher_found = True
        break

if not bash_matcher_found:
    pre_tool_hooks.append(new_hook_entry)

with open(settings_file, 'w') as f:
    json.dump(settings, f, indent=2)

print(f"  [✓] Hook configuration written to {settings_file}")
PYEOF

echo ""
echo "  ╔══════════════════════════════════════════╗"
echo "  ║   Installation complete!                 ║"
echo "  ╚══════════════════════════════════════════╝"
echo ""
echo "  sec-check will now automatically intercept package"
echo "  installs (pip, npm, go, cargo, gem) in Claude Code"
echo "  and block suspicious packages."
echo ""
echo "  Checks performed:"
echo "    • Known vulnerabilities (OSV.dev)"
echo "    • Typosquatting detection"
echo "    • Package metadata analysis"
echo "    • Suspicious version detection"
echo "    • Package removal/quarantine detection"
echo ""
echo "  To test: ask Claude Code to 'pip install requests'"
echo "  To uninstall: remove the sec-check entry from $SETTINGS_FILE"
echo ""
