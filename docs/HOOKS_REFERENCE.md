# Hooks Reference

## How Claude Code Hooks Work

Claude Code supports hooks that execute shell commands at specific lifecycle events. Hooks are configured in `~/.claude/settings.json`.

### Hook Events

| Event | When | Stdin | Can Block |
|-------|------|-------|-----------|
| `SessionStart` | Claude Code session starts | (none) | No |
| `PreToolUse` | Before a tool executes | Tool invocation JSON | Yes (exit 2) |
| `PostToolUse` | After a tool executes | Tool result JSON | No |

### Exit Codes

| Code | Meaning | Effect |
|------|---------|--------|
| 0 | Success/Allow | Proceed normally |
| 1 | Error | Proceed, but log the error |
| 2 | Block | **Reject the tool execution** (PreToolUse only) |

### Stdin Format

**PreToolUse**:
```json
{
  "tool_name": "Bash",
  "tool_input": {
    "command": "ls -la"
  }
}
```

**PostToolUse**:
```json
{
  "tool_name": "Bash",
  "tool_input": {
    "command": "ls -la"
  },
  "tool_output": "total 42\n..."
}
```

### Stdout (PreToolUse only)

When exiting with code 2, any stdout is shown to the user as the rejection reason:

```
BLOCKED: Dangerous command pattern detected: 'rm -rf /'
```

### Settings Format

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": ".*",
        "hooks": [
          {
            "type": "command",
            "command": "python3 ~/.claude/hooks/pre_tool_use.py"
          }
        ]
      }
    ]
  }
}
```

The `matcher` field is a regex matched against the tool name. Use `".*"` to match all tools, or specific patterns like `"Bash|Write|Edit"`.

## Provided Hook Scripts

### session_start.py
- Runs file integrity verification
- Reports verified/unsigned/tampered/missing counts
- Exits 2 if tampered files detected

### pre_tool_use.py
- Blocks dangerous Bash commands (rm -rf /, mkfs, fork bombs)
- Runs security gate on Write/Edit/Bash content
- Checks approval tokens for monitored file modifications

### post_tool_use.py
- Captures self-modification diffs for Write/Edit on monitored paths
- Appends to hash-chained tamper-proof audit log

### security_orchestrator.py
- Combines all pre-tool checks into a single hook
- Runs: dangerous commands, injection, file integrity
- Use instead of pre_tool_use.py for the full check suite

## Custom Hooks

Create your own hook at `~/.claude/hooks/my_hook.py`:

```python
#!/usr/bin/env python3
import json, sys

data = json.loads(sys.stdin.read())
tool_name = data.get("tool_name", "")

if tool_name == "Bash" and "sudo" in data.get("tool_input", {}).get("command", ""):
    print("BLOCKED: sudo commands not allowed")
    sys.exit(2)

sys.exit(0)
```

Add to settings:
```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [{"type": "command", "command": "python3 ~/.claude/hooks/my_hook.py"}]
      }
    ]
  }
}
```
