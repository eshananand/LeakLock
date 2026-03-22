#!/usr/bin/env node

/**
 * LeakLock - Installer
 *
 * Adds LeakLock as both a PreToolUse and UserPromptSubmit hook
 * in the user's Claude Code settings (~/.claude/settings.json).
 */

const fs = require("fs");
const path = require("path");

const CLAUDE_SETTINGS_DIR = path.join(
  process.env.HOME || process.env.USERPROFILE || "",
  ".claude"
);
const SETTINGS_FILE = path.join(CLAUDE_SETTINGS_DIR, "settings.json");
const HOOK_COMMAND = `node ${path.resolve(__dirname, "hook.js")}`;

// All hook events that LeakLock registers
const HOOK_EVENTS = ["PreToolUse", "UserPromptSubmit", "PostToolUse"];

function isLeakLockHook(entry) {
  return (
    entry.hooks &&
    entry.hooks.some((h) => h.command && h.command.includes("leaklock"))
  );
}

function install() {
  console.log("[LeakLock] Installing Claude Code hooks...\n");

  // Load existing settings or start fresh
  let settings = {};
  if (fs.existsSync(SETTINGS_FILE)) {
    try {
      settings = JSON.parse(fs.readFileSync(SETTINGS_FILE, "utf8"));
    } catch {
      console.log("[LeakLock] Warning: could not parse existing settings.json, creating new one.");
    }
  } else {
    if (!fs.existsSync(CLAUDE_SETTINGS_DIR)) {
      fs.mkdirSync(CLAUDE_SETTINGS_DIR, { recursive: true });
    }
  }

  if (!settings.hooks) settings.hooks = {};

  let installed = 0;

  for (const event of HOOK_EVENTS) {
    if (!settings.hooks[event]) settings.hooks[event] = [];

    // Check if already installed for this event
    const alreadyInstalled = settings.hooks[event].some(isLeakLockHook);
    if (alreadyInstalled) {
      console.log(`[LeakLock] ${event} hook already installed — skipping.`);
      continue;
    }

    // Add the hook
    // matcher: "" means match all (tools for PreToolUse, all prompts for UserPromptSubmit)
    settings.hooks[event].push({
      matcher: "",
      hooks: [
        {
          type: "command",
          command: HOOK_COMMAND,
        },
      ],
    });
    installed++;
    console.log(`[LeakLock] ${event} hook added.`);
  }

  if (installed === 0) {
    console.log("\n[LeakLock] All hooks were already installed.");
    console.log(`[LeakLock] Settings file: ${SETTINGS_FILE}`);
    return;
  }

  fs.writeFileSync(SETTINGS_FILE, JSON.stringify(settings, null, 2) + "\n");

  console.log(`\n[LeakLock] ${installed} hook(s) installed successfully!`);
  console.log(`[LeakLock] Settings file: ${SETTINGS_FILE}`);
  console.log(`[LeakLock] Hook command:  ${HOOK_COMMAND}`);
  console.log("");
  console.log("[LeakLock] What's protected:");
  console.log("  - UserPromptSubmit: Blocks messages containing sensitive data BEFORE Claude sees them");
  console.log("  - PreToolUse:       Redacts sensitive data in tool inputs (Write, Bash, Edit, etc.)");
  console.log("  - PostToolUse:      Redacts sensitive data in tool responses (MCP servers like Grafana, Slack, etc.)");
  console.log("");
  console.log("[LeakLock] Configuration (optional):");
  console.log("  Create a .leaklock.json in your project root to customize:");
  console.log('    { "action": "redact|block|warn", "minSeverity": "low|medium|high|critical" }');
  console.log("");
  console.log("[LeakLock] Logs are written to: ~/.leaklock/detections.jsonl");
}

function uninstall() {
  console.log("[LeakLock] Removing Claude Code hooks...\n");

  if (!fs.existsSync(SETTINGS_FILE)) {
    console.log("[LeakLock] No settings file found. Nothing to remove.");
    return;
  }

  let settings;
  try {
    settings = JSON.parse(fs.readFileSync(SETTINGS_FILE, "utf8"));
  } catch {
    console.log("[LeakLock] Could not parse settings.json.");
    return;
  }

  if (!settings.hooks) {
    console.log("[LeakLock] No hooks found. Nothing to remove.");
    return;
  }

  let totalRemoved = 0;

  for (const event of HOOK_EVENTS) {
    if (!settings.hooks[event]) continue;

    const before = settings.hooks[event].length;
    settings.hooks[event] = settings.hooks[event].filter(
      (entry) => !isLeakLockHook(entry)
    );
    const removed = before - settings.hooks[event].length;
    if (removed > 0) {
      console.log(`[LeakLock] Removed ${removed} ${event} hook(s).`);
      totalRemoved += removed;
    }
  }

  if (totalRemoved === 0) {
    console.log("[LeakLock] No LeakLock hooks were found in settings.");
    return;
  }

  fs.writeFileSync(SETTINGS_FILE, JSON.stringify(settings, null, 2) + "\n");
  console.log(`\n[LeakLock] Removed ${totalRemoved} hook(s) total. Settings updated.`);
}

// CLI
const action = process.argv[2];
if (action === "uninstall" || action === "--uninstall") {
  uninstall();
} else {
  install();
}
