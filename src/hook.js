#!/usr/bin/env node

/**
 * LeakLock - Claude Code Hook Entry Point
 *
 * This script is invoked by Claude Code as a "PreToolUse" hook.
 * It reads the tool input from stdin (JSON), scans all string fields
 * for sensitive data, redacts them, and writes the modified input
 * back to stdout so Claude Code uses the sanitized version.
 *
 * Hook protocol (Claude Code):
 *   stdin  → { tool_name, tool_input }
 *   stdout → JSON with optional "decision" and modified "tool_input"
 *
 * Decisions: "approve" (continue with changes), "block" (abort tool call)
 */

const { redact } = require("./redactor");
const { createLogger } = require("./logger");
const { loadConfig, severitiesAtOrAbove } = require("./config");

async function main() {
  // Read stdin
  const chunks = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk);
  }
  const raw = Buffer.concat(chunks).toString("utf8");

  let hookInput;
  try {
    hookInput = JSON.parse(raw);
  } catch {
    // Not valid JSON — nothing we can do
    process.exit(0);
  }

  const toolName = hookInput.tool_name || "unknown";
  const toolInput = hookInput.tool_input || {};

  const config = loadConfig();
  const logger = createLogger({
    logDir: config.logDir,
    silent: config.silent,
  });

  const detectOptions = {
    categories: config.categories,
    severities: severitiesAtOrAbove(config.minSeverity),
    extraPatterns: config.extraPatterns,
  };

  // Deep-scan all string values in tool_input
  let totalFindings = [];
  let combinedSummary = {};
  const redactedInput = deepRedact(toolInput, detectOptions, (result) => {
    totalFindings = totalFindings.concat(result.findings);
    // Merge summaries
    for (const [cat, types] of Object.entries(result.summary)) {
      if (!combinedSummary[cat]) combinedSummary[cat] = {};
      for (const [name, count] of Object.entries(types)) {
        combinedSummary[cat][name] = (combinedSummary[cat][name] || 0) + count;
      }
    }
  });

  if (totalFindings.length === 0) {
    // No sensitive data — let the tool call proceed unchanged
    process.exit(0);
  }

  const combinedResult = {
    redacted: "",
    findings: totalFindings,
    summary: combinedSummary,
  };

  // Log and notify
  logger.log(combinedResult, { toolName });

  // Decide action
  if (config.action === "block") {
    // Block the tool call entirely
    const output = {
      decision: "block",
      reason:
        `LeakLock blocked this tool call because it contained ` +
        `${totalFindings.length} piece(s) of sensitive data ` +
        `(${Object.keys(combinedSummary).join(", ")}).`,
    };
    process.stdout.write(JSON.stringify(output));
  } else if (config.action === "warn") {
    // Warn but allow through unchanged
    process.exit(0);
  } else {
    // Default: "redact" — approve with modified input
    const output = {
      decision: "approve",
      tool_input: redactedInput,
    };
    process.stdout.write(JSON.stringify(output));
  }
}

/**
 * Recursively walk an object/array and redact all string values.
 *
 * @param {*}        value
 * @param {Object}   options  - detect() options
 * @param {Function} onResult - callback with each redact() result
 * @returns {*} The value with strings redacted
 */
function deepRedact(value, options, onResult) {
  if (typeof value === "string") {
    const result = redact(value, options);
    if (result.findings.length > 0) {
      onResult(result);
      return result.redacted;
    }
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => deepRedact(item, options, onResult));
  }
  if (value && typeof value === "object") {
    const out = {};
    for (const [key, val] of Object.entries(value)) {
      out[key] = deepRedact(val, options, onResult);
    }
    return out;
  }
  return value;
}

main().catch((err) => {
  process.stderr.write(`[LeakLock] Hook error: ${err.message}\n`);
  process.exit(0); // Don't block on errors
});
