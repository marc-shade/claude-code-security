#!/bin/bash
set -euo pipefail

# Claude Code Security - One-command installer
# Usage: bash setup.sh [--tier 1|2|3|4] [--dry-run]

TIER="${1:---tier}"
TIER_NUM="2"
DRY_RUN=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --tier)
            TIER_NUM="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        *)
            shift
            ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLAUDE_HOME="${CLAUDE_CODE_SECURITY_HOME:-$HOME/.claude}"
HOOKS_DIR="$CLAUDE_HOME/hooks"
SETTINGS_FILE="$CLAUDE_HOME/settings.json"

echo "============================================"
echo "  Claude Code Security - Setup (Tier $TIER_NUM)"
echo "============================================"
echo ""
echo "  Source:    $SCRIPT_DIR"
echo "  Target:    $CLAUDE_HOME"
echo "  Tier:      $TIER_NUM"
echo "  Dry Run:   $DRY_RUN"
echo ""

if [ "$DRY_RUN" = true ]; then
    echo "[DRY RUN] Would perform the following:"
    echo ""
fi

# Step 1: Install Python package
echo "Step 1: Installing Python package..."
if [ "$DRY_RUN" = true ]; then
    if [ "$TIER_NUM" -ge 4 ]; then
        echo "  pip install -e '$SCRIPT_DIR[all]'"
    elif [ "$TIER_NUM" -ge 3 ]; then
        echo "  pip install -e '$SCRIPT_DIR[watcher]'"
    else
        echo "  pip install -e '$SCRIPT_DIR'"
    fi
else
    if [ "$TIER_NUM" -ge 4 ]; then
        pip install -e "$SCRIPT_DIR[all]"
    elif [ "$TIER_NUM" -ge 3 ]; then
        pip install -e "$SCRIPT_DIR[watcher]"
    else
        pip install -e "$SCRIPT_DIR"
    fi
fi
echo "  Done."
echo ""

# Step 2: Create directories
echo "Step 2: Creating directories..."
DIRS=("$HOOKS_DIR" "$CLAUDE_HOME/audit_logs" "$CLAUDE_HOME/.vault")
for dir in "${DIRS[@]}"; do
    if [ "$DRY_RUN" = true ]; then
        echo "  mkdir -p $dir"
    else
        mkdir -p "$dir"
    fi
done
echo "  Done."
echo ""

# Step 3: Copy hook scripts
echo "Step 3: Installing hook scripts..."
HOOK_FILES=(session_start.py pre_tool_use.py post_tool_use.py security_orchestrator.py)
for hook in "${HOOK_FILES[@]}"; do
    if [ "$DRY_RUN" = true ]; then
        echo "  cp $SCRIPT_DIR/hooks/$hook -> $HOOKS_DIR/$hook"
    else
        cp "$SCRIPT_DIR/hooks/$hook" "$HOOKS_DIR/$hook"
        chmod +x "$HOOKS_DIR/$hook"
    fi
done
echo "  Done."
echo ""

# Step 4: Merge settings
echo "Step 4: Configuring settings (Tier $TIER_NUM)..."
TEMPLATE="$SCRIPT_DIR/templates/settings-tier${TIER_NUM}.json"
if [ ! -f "$TEMPLATE" ]; then
    echo "  ERROR: Template not found: $TEMPLATE"
    exit 1
fi

if [ "$DRY_RUN" = true ]; then
    echo "  Would merge $TEMPLATE into $SETTINGS_FILE"
    echo "  Template contents:"
    cat "$TEMPLATE" | sed 's/^/    /'
else
    if [ -f "$SETTINGS_FILE" ]; then
        echo "  Existing settings found. Merging hooks..."
        # Use Python to merge JSON safely
        python3 -c "
import json, sys
existing = json.loads(open('$SETTINGS_FILE').read()) if open('$SETTINGS_FILE').read().strip() else {}
template = json.loads(open('$TEMPLATE').read())
existing.setdefault('hooks', {}).update(template.get('hooks', {}))
with open('$SETTINGS_FILE', 'w') as f:
    json.dump(existing, f, indent=2)
print('  Hooks merged successfully.')
"
    else
        cp "$TEMPLATE" "$SETTINGS_FILE"
        echo "  Settings created from template."
    fi
fi
echo "  Done."
echo ""

# Step 5: Sign all files
echo "Step 5: Signing monitored files..."
if [ "$DRY_RUN" = true ]; then
    echo "  python3 -c 'from claude_code_security.file_integrity import quick_sign_all; print(quick_sign_all())'"
else
    python3 -c "
from claude_code_security.file_integrity import quick_sign_all
signed, errors = quick_sign_all()
print(f'  Signed {signed} files ({errors} errors)')
"
fi
echo "  Done."
echo ""

# Step 6: Verify
echo "Step 6: Verifying installation..."
if [ "$DRY_RUN" = true ]; then
    echo "  Would run verification checks"
else
    python3 -c "
from claude_code_security.file_integrity import quick_verify
report = quick_verify()
print(f'  File integrity: {report.summary()}')
"
    echo "  Hook scripts installed:"
    for hook in "${HOOK_FILES[@]}"; do
        if [ -f "$HOOKS_DIR/$hook" ]; then
            echo "    [OK] $hook"
        else
            echo "    [MISSING] $hook"
        fi
    done
fi
echo ""

echo "============================================"
echo "  Setup complete! Tier $TIER_NUM active."
echo ""
echo "  Next: Restart Claude Code to activate hooks."
echo "============================================"
