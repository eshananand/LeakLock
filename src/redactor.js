/**
 * LeakLock - Redaction Module
 *
 * Takes text + findings from the detector and produces sanitized output.
 */

const { detect } = require("./detector");

/**
 * Redact all sensitive data found in text.
 *
 * @param {string} text     - Original text
 * @param {Object} [options] - Same options as detect()
 * @returns {{ redacted: string, findings: Finding[], summary: Object }}
 */
function redact(text, options = {}) {
  if (!text || typeof text !== "string") {
    return { redacted: text, findings: [], summary: {} };
  }

  const findings = detect(text, options);
  if (findings.length === 0) {
    return { redacted: text, findings: [], summary: {} };
  }

  // Build redacted string by replacing matches back-to-front
  // (so indices stay valid as we modify the string)
  let redacted = text;
  const applied = [];

  // Process in reverse order of position to preserve indices
  for (let i = findings.length - 1; i >= 0; i--) {
    const f = findings[i];
    const before = redacted.slice(0, f.startIndex);
    const after = redacted.slice(f.startIndex + f.length);
    redacted = before + f.redactWith + after;
    applied.push(f);
  }

  // Build summary by category and severity
  const summary = {};
  for (const f of findings) {
    if (!summary[f.category]) summary[f.category] = {};
    if (!summary[f.category][f.name]) summary[f.category][f.name] = 0;
    summary[f.category][f.name]++;
  }

  return { redacted, findings, summary };
}

module.exports = { redact };
