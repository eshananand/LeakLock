/**
 * LeakLock - Detection Engine
 *
 * Scans text for sensitive data using the pattern library.
 * Returns structured findings with location, category, and severity.
 */

const { PATTERNS } = require("./patterns");

/**
 * @typedef {Object} Finding
 * @property {string}  name       - Pattern name that matched
 * @property {string}  category   - "pii" | "secret" | "financial" | "credential"
 * @property {string}  severity   - "critical" | "high" | "medium" | "low"
 * @property {string}  matched    - The matched text (truncated for safety)
 * @property {number}  startIndex - Position in the input string
 * @property {string}  redactWith - The replacement token
 */

/**
 * Scan text and return all findings.
 *
 * @param {string}   text              - The text to scan
 * @param {Object}   [options]
 * @param {string[]} [options.categories]  - Filter to these categories only
 * @param {string[]} [options.severities]  - Filter to these severities only
 * @param {Object[]} [options.extraPatterns] - Additional patterns to include
 * @returns {Finding[]}
 */
function detect(text, options = {}) {
  if (!text || typeof text !== "string") return [];

  const { categories, severities, extraPatterns = [] } = options;
  const allPatterns = [...PATTERNS, ...extraPatterns];
  const findings = [];

  for (const pattern of allPatterns) {
    if (categories && !categories.includes(pattern.category)) continue;
    if (severities && !severities.includes(pattern.severity)) continue;

    // Reset regex state for global patterns
    const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
    let match;

    while ((match = regex.exec(text)) !== null) {
      const raw = match[0];
      findings.push({
        name: pattern.name,
        category: pattern.category,
        severity: pattern.severity,
        matched: truncate(raw, 12),
        startIndex: match.index,
        length: raw.length,
        redactWith: pattern.redactWith,
        _fullMatch: raw,           // internal: used by redactor
        _patternRegex: regex,      // internal: used by redactor
      });
    }
  }

  // Sort by position in the string
  findings.sort((a, b) => a.startIndex - b.startIndex);
  return findings;
}

/**
 * Quick boolean check — is there any sensitive data?
 */
function hasSensitiveData(text, options = {}) {
  return detect(text, options).length > 0;
}

/**
 * Truncate a matched string for safe display:
 * show first N chars, mask the rest.
 */
function truncate(str, visibleChars = 6) {
  if (str.length <= visibleChars + 4) return str.replace(/./g, "*");
  return str.slice(0, visibleChars) + "****";
}

module.exports = { detect, hasSensitiveData };
