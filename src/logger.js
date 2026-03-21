/**
 * LeakLock - Logging & Notification System
 *
 * Logs all detections to a file and notifies the user via stderr.
 * Logs are written as JSON-lines for easy parsing/auditing.
 */

const fs = require("fs");
const path = require("path");

const DEFAULT_LOG_DIR = path.join(
  process.env.HOME || process.env.USERPROFILE || "/tmp",
  ".leaklock"
);
const DEFAULT_LOG_FILE = "detections.jsonl";

/**
 * Create a logger instance.
 *
 * @param {Object} [options]
 * @param {string} [options.logDir]  - Directory for log files
 * @param {boolean} [options.silent] - Suppress stderr notifications
 */
function createLogger(options = {}) {
  const logDir = options.logDir || DEFAULT_LOG_DIR;
  const silent = options.silent || false;
  const logPath = path.join(logDir, DEFAULT_LOG_FILE);

  // Ensure log directory exists
  if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir, { recursive: true });
  }

  return {
    /**
     * Log a redaction event.
     *
     * @param {Object}   result          - Output from redactor.redact()
     * @param {string}   result.redacted
     * @param {Object[]} result.findings
     * @param {Object}   result.summary
     * @param {Object}   [meta]          - Extra context (tool name, file, etc.)
     */
    log(result, meta = {}) {
      if (result.findings.length === 0) return;

      const entry = {
        timestamp: new Date().toISOString(),
        totalFindings: result.findings.length,
        summary: result.summary,
        findings: result.findings.map((f) => ({
          name: f.name,
          category: f.category,
          severity: f.severity,
          matched: f.matched, // already truncated
        })),
        meta,
      };

      // Append to JSONL log file
      try {
        fs.appendFileSync(logPath, JSON.stringify(entry) + "\n");
      } catch (err) {
        process.stderr.write(
          `[LeakLock] Warning: could not write to log file: ${err.message}\n`
        );
      }

      // Notify user on stderr (Claude Code shows stderr to the user)
      if (!silent) {
        this.notify(result);
      }
    },

    /**
     * Print a user-facing notification about what was detected.
     */
    notify(result) {
      const lines = [];
      lines.push("");
      lines.push("╔══════════════════════════════════════════════════════════╗");
      lines.push("║           ⚠  LeakLock: Sensitive Data Detected  ⚠      ║");
      lines.push("╠══════════════════════════════════════════════════════════╣");

      // Group by category
      for (const [category, types] of Object.entries(result.summary)) {
        const label = category.toUpperCase();
        lines.push(`║  Category: ${label.padEnd(44)}║`);
        for (const [name, count] of Object.entries(types)) {
          const detail = `    ${name}: ${count} occurrence(s)`;
          lines.push(`║  ${detail.padEnd(54)}║`);
        }
      }

      // Severity breakdown
      const severityCounts = {};
      for (const f of result.findings) {
        severityCounts[f.severity] = (severityCounts[f.severity] || 0) + 1;
      }
      lines.push("╠══════════════════════════════════════════════════════════╣");
      const sevLine = Object.entries(severityCounts)
        .map(([s, c]) => `${s}:${c}`)
        .join("  ");
      lines.push(`║  Severity: ${sevLine.padEnd(44)}║`);
      lines.push("║                                                        ║");
      lines.push("║  All sensitive data has been REDACTED before sending.   ║");
      lines.push("╚══════════════════════════════════════════════════════════╝");
      lines.push("");

      process.stderr.write(lines.join("\n") + "\n");
    },

    /** Return path to the log file. */
    getLogPath() {
      return logPath;
    },
  };
}

module.exports = { createLogger };
