/**
 * LeakLock - Main API
 *
 * Public API for programmatic use.
 */

const { detect, hasSensitiveData } = require("./detector");
const { redact } = require("./redactor");
const { createLogger } = require("./logger");
const { loadConfig, severitiesAtOrAbove, DEFAULTS } = require("./config");
const { PATTERNS } = require("./patterns");

module.exports = {
  detect,
  hasSensitiveData,
  redact,
  createLogger,
  loadConfig,
  severitiesAtOrAbove,
  PATTERNS,
  DEFAULTS,
};
