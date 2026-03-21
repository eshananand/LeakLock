/**
 * LeakLock - Configuration Loader
 *
 * Reads optional .leaklock.json from the project root for custom rules,
 * severity filters, and behaviour settings.
 */

const fs = require("fs");
const path = require("path");

const CONFIG_FILENAME = ".leaklock.json";

const DEFAULTS = {
  // Which categories to scan: "pii", "secret", "financial", "credential"
  categories: null, // null = all
  // Minimum severity to act on: "low" | "medium" | "high" | "critical"
  minSeverity: "low",
  // Action when sensitive data is found: "redact" | "block" | "warn"
  action: "redact",
  // Log directory (null = ~/.leaklock)
  logDir: null,
  // Suppress stderr notifications
  silent: false,
  // Extra regex patterns (same shape as patterns.js entries)
  extraPatterns: [],
  // Paths/globs to exclude from scanning
  excludePaths: ["node_modules", ".git", "*.lock"],
};

/**
 * Load configuration from .leaklock.json in the given directory,
 * merged with defaults.
 *
 * @param {string} [dir] - Directory to search for config file
 * @returns {Object} Merged configuration
 */
function loadConfig(dir) {
  const searchDir = dir || process.cwd();
  const configPath = path.join(searchDir, CONFIG_FILENAME);
  let userConfig = {};

  if (fs.existsSync(configPath)) {
    try {
      const raw = fs.readFileSync(configPath, "utf8");
      userConfig = JSON.parse(raw);
    } catch (err) {
      process.stderr.write(
        `[LeakLock] Warning: could not parse ${configPath}: ${err.message}\n`
      );
    }
  }

  // Compile any user-supplied regex strings into RegExp objects
  if (userConfig.extraPatterns) {
    userConfig.extraPatterns = userConfig.extraPatterns.map((p) => ({
      ...p,
      regex: new RegExp(p.regex, p.flags || "gi"),
    }));
  }

  return { ...DEFAULTS, ...userConfig };
}

/**
 * Map minSeverity to a list of severities at or above that level.
 */
function severitiesAtOrAbove(minSeverity) {
  const levels = ["low", "medium", "high", "critical"];
  const idx = levels.indexOf(minSeverity);
  if (idx === -1) return levels;
  return levels.slice(idx);
}

module.exports = { loadConfig, severitiesAtOrAbove, DEFAULTS };
