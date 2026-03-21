#!/usr/bin/env node

/**
 * LeakLock - CLI Tool
 *
 * Standalone CLI for scanning files or stdin for sensitive data.
 *
 * Usage:
 *   leaklock scan <file>        Scan a file and report findings
 *   leaklock scan --stdin       Scan stdin
 *   leaklock redact <file>      Redact a file and print sanitized output
 *   leaklock log                Show recent detection log entries
 *   leaklock install            Install Claude Code hook
 *   leaklock uninstall          Remove Claude Code hook
 */

const fs = require("fs");
const { detect } = require("./detector");
const { redact } = require("./redactor");
const { createLogger } = require("./logger");
const { loadConfig, severitiesAtOrAbove } = require("./config");

const args = process.argv.slice(2);
const command = args[0];

function printUsage() {
  console.log(`
LeakLock - Sensitive Data Detection & Redaction

Usage:
  leaklock scan <file>        Scan a file and report findings
  leaklock scan --stdin       Scan text from stdin
  leaklock redact <file>      Print redacted version of a file
  leaklock log [--tail N]     Show recent detection log entries
  leaklock install            Install as Claude Code hook
  leaklock uninstall          Remove Claude Code hook

Options:
  --severity <level>          Minimum severity: low, medium, high, critical
  --category <cat>            Filter: pii, secret, financial, credential
  --json                      Output findings as JSON
`);
}

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function main() {
  if (!command || command === "--help" || command === "-h") {
    printUsage();
    process.exit(0);
  }

  const config = loadConfig();
  const opts = {
    categories: config.categories,
    severities: severitiesAtOrAbove(config.minSeverity),
    extraPatterns: config.extraPatterns,
  };

  // Override from CLI flags
  const sevIdx = args.indexOf("--severity");
  if (sevIdx !== -1 && args[sevIdx + 1]) {
    opts.severities = severitiesAtOrAbove(args[sevIdx + 1]);
  }
  const catIdx = args.indexOf("--category");
  if (catIdx !== -1 && args[catIdx + 1]) {
    opts.categories = [args[catIdx + 1]];
  }
  const jsonOutput = args.includes("--json");

  if (command === "scan") {
    const target = args[1];
    let text;

    if (target === "--stdin") {
      text = await readStdin();
    } else if (target && fs.existsSync(target)) {
      text = fs.readFileSync(target, "utf8");
    } else {
      console.error("Error: provide a file path or --stdin");
      process.exit(1);
    }

    const findings = detect(text, opts);

    if (jsonOutput) {
      console.log(
        JSON.stringify(
          findings.map((f) => ({
            name: f.name,
            category: f.category,
            severity: f.severity,
            matched: f.matched,
          })),
          null,
          2
        )
      );
    } else if (findings.length === 0) {
      console.log("No sensitive data detected.");
    } else {
      console.log(`Found ${findings.length} sensitive item(s):\n`);
      for (const f of findings) {
        console.log(
          `  [${f.severity.toUpperCase()}] ${f.name} — ${f.matched}`
        );
      }
    }
    process.exit(findings.length > 0 ? 1 : 0);
  }

  if (command === "redact") {
    const target = args[1];
    let text;

    if (target === "--stdin") {
      text = await readStdin();
    } else if (target && fs.existsSync(target)) {
      text = fs.readFileSync(target, "utf8");
    } else {
      console.error("Error: provide a file path or --stdin");
      process.exit(1);
    }

    const result = redact(text, opts);
    process.stdout.write(result.redacted);

    if (result.findings.length > 0) {
      const logger = createLogger({ logDir: config.logDir, silent: true });
      logger.notify(result);
    }
  }

  if (command === "log") {
    const logger = createLogger({ logDir: config.logDir, silent: true });
    const logPath = logger.getLogPath();

    if (!fs.existsSync(logPath)) {
      console.log("No detection logs found yet.");
      process.exit(0);
    }

    const lines = fs.readFileSync(logPath, "utf8").trim().split("\n");
    const tailIdx = args.indexOf("--tail");
    const count = tailIdx !== -1 ? parseInt(args[tailIdx + 1], 10) || 10 : 10;
    const recent = lines.slice(-count);

    for (const line of recent) {
      try {
        const entry = JSON.parse(line);
        console.log(
          `[${entry.timestamp}] ${entry.totalFindings} finding(s) — ` +
            `tool: ${entry.meta.toolName || "unknown"}`
        );
        for (const f of entry.findings) {
          console.log(
            `    [${f.severity}] ${f.name}: ${f.matched}`
          );
        }
        console.log("");
      } catch {
        // skip malformed lines
      }
    }
  }

  if (command === "install") {
    require("./install");
  }

  if (command === "uninstall") {
    process.argv[2] = "uninstall";
    require("./install");
  }
}

main().catch((err) => {
  console.error(`Error: ${err.message}`);
  process.exit(1);
});
