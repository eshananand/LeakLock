#!/usr/bin/env node

/**
 * LeakLock - Installer
 *
 * Adds LeakLock as a Claude Code PreToolUse hook in the user's
 * Claude Code settings (~/.claude/settings.json).
 */

const fs = require("fs");
const path = require("path");

const CLAUDE_SETTINGS_DIR = path.join(
  process.env.HOME || process.env.USERPROFILE || "",
  ".claude"
);
const SETTINGS_FILE = path.join(CLAUDE_SETTINGS_DIR, "settings.json");
const HOOK_COMMAND = `node ${path.resolve(__dirname, "hook.js")}`;

function install() {
  console.log("[LeakLock] Installing Claude Code hook...\n");

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

  // Ensure hooks structure exists
  if (!settings.hooks) settings.hooks = {};
  if (!settings.hooks.PreToolUse) settings.hooks.PreToolUse = [];

  // Check if already installed
  const alreadyInstalled = settings.hooks.PreToolUse.some(
    (hook) => hook.command && hook.command.includes("leaklock")
  );

  if (alreadyInstalled) {
    console.log("[LeakLock] Hook is already installed in Claude Code settings.");
    console.log(`[LeakLock] Settings file: ${SETTINGS_FILE}`);
    return;
  }

  // Add the hook
  settings.hooks.PreToolUse.push({
    type: "command",
    command: HOOK_COMMAND,
    description: "LeakLock: Scans for and redacts sensitive data (PII, API keys, secrets) before sending to Claude",
  });

  fs.writeFileSync(SETTINGS_FILE, JSON.stringify(settings, null, 2) + "\n");

  console.log("[LeakLock] Hook installed successfully!");
  console.log(`[LeakLock] Settings file: ${SETTINGS_FILE}`);
  console.log(`[LeakLock] Hook command:  ${HOOK_COMMAND}`);
  console.log("");
  console.log("[LeakLock] Configuration (optional):");
  console.log("  Create a .leaklock.json in your project root to customize:");
  console.log('    { "action": "redact|block|warn", "minSeverity": "low|medium|high|critical" }');
  console.log("");
  console.log("[LeakLock] Logs are written to: ~/.leaklock/detections.jsonl");
}

function uninstall() {
  console.log("[LeakLock] Removing Claude Code hook...\n");

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

  if (!settings.hooks || !settings.hooks.PreToolUse) {
    console.log("[LeakLock] No PreToolUse hooks found. Nothing to remove.");
    return;
  }

  const before = settings.hooks.PreToolUse.length;
  settings.hooks.PreToolUse = settings.hooks.PreToolUse.filter(
    (hook) => !hook.command || !hook.command.includes("leaklock")
  );
  const removed = before - settings.hooks.PreToolUse.length;

  if (removed === 0) {
    console.log("[LeakLock] Hook was not found in settings.");
    return;
  }

  fs.writeFileSync(SETTINGS_FILE, JSON.stringify(settings, null, 2) + "\n");
  console.log(`[LeakLock] Removed ${removed} hook(s). Settings updated.`);
}

// CLI
const action = process.argv[2];
if (action === "uninstall" || action === "--uninstall") {
  uninstall();
} else {
  install();
}
