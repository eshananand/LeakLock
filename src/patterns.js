/**
 * LeakLock - Sensitive Data Detection Patterns
 *
 * Each pattern has:
 *   - name:        Human-readable label
 *   - category:    "pii" | "secret" | "financial" | "credential"
 *   - severity:    "critical" | "high" | "medium" | "low"
 *   - regex:       RegExp to match
 *   - redactWith:  Replacement string (use $1, $2 for capture groups)
 */

const PATTERNS = [
  // ── API Keys & Tokens ─────────────────────────────────────────────
  {
    name: "AWS Access Key",
    category: "secret",
    severity: "critical",
    regex: /\b(AKIA[0-9A-Z]{16})\b/g,
    redactWith: "[REDACTED_AWS_KEY]",
  },
  {
    name: "AWS Secret Key",
    category: "secret",
    severity: "critical",
    regex: /(?:aws_secret_access_key|aws_secret)\s*[=:]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi,
    redactWith: "[REDACTED_AWS_SECRET]",
  },
  {
    name: "GitHub Token",
    category: "secret",
    severity: "critical",
    regex: /\b(ghp_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9_]{22,})\b/g,
    redactWith: "[REDACTED_GITHUB_TOKEN]",
  },
  {
    name: "GitLab Token",
    category: "secret",
    severity: "critical",
    regex: /\b(glpat-[A-Za-z0-9\-_]{20,})\b/g,
    redactWith: "[REDACTED_GITLAB_TOKEN]",
  },
  {
    name: "Slack Token",
    category: "secret",
    severity: "critical",
    regex: /\b(xox[baprs]-[0-9A-Za-z\-]{10,})\b/g,
    redactWith: "[REDACTED_SLACK_TOKEN]",
  },
  {
    name: "Stripe Key",
    category: "secret",
    severity: "critical",
    regex: /\b(sk_live_[0-9a-zA-Z]{24,}|pk_live_[0-9a-zA-Z]{24,})\b/g,
    redactWith: "[REDACTED_STRIPE_KEY]",
  },
  {
    name: "OpenAI API Key",
    category: "secret",
    severity: "critical",
    regex: /\b(sk-[A-Za-z0-9]{32,})\b/g,
    redactWith: "[REDACTED_OPENAI_KEY]",
  },
  {
    name: "Anthropic API Key",
    category: "secret",
    severity: "critical",
    regex: /\b(sk-ant-[A-Za-z0-9\-]{32,})\b/g,
    redactWith: "[REDACTED_ANTHROPIC_KEY]",
  },
  {
    name: "Google API Key",
    category: "secret",
    severity: "critical",
    regex: /\b(AIza[0-9A-Za-z\-_]{35})\b/g,
    redactWith: "[REDACTED_GOOGLE_API_KEY]",
  },
  {
    name: "Generic API Key Assignment",
    category: "secret",
    severity: "high",
    regex: /(?:api[_-]?key|apikey|api[_-]?secret|api[_-]?token)\s*[=:]\s*['"]([A-Za-z0-9\-_./+=]{16,})['"]?/gi,
    redactWith: "[REDACTED_API_KEY]",
  },
  {
    name: "Bearer Token",
    category: "secret",
    severity: "high",
    regex: /Bearer\s+([A-Za-z0-9\-_\.]{20,})/g,
    redactWith: "Bearer [REDACTED_TOKEN]",
  },
  {
    name: "Private Key Block",
    category: "secret",
    severity: "critical",
    regex: /-----BEGIN\s+(RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END\s+(RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
    redactWith: "[REDACTED_PRIVATE_KEY]",
  },
  {
    name: "JWT Token",
    category: "secret",
    severity: "high",
    regex: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_\-+/=]{10,}\b/g,
    redactWith: "[REDACTED_JWT]",
  },

  // ── Database Connection Strings ────────────────────────────────────
  {
    name: "Database Connection String",
    category: "credential",
    severity: "critical",
    regex: /(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp|mssql):\/\/[^\s'"<>{}|\\^`]{8,}/gi,
    redactWith: "[REDACTED_DB_CONNECTION]",
  },

  // ── Passwords ──────────────────────────────────────────────────────
  {
    name: "Password Assignment",
    category: "credential",
    severity: "critical",
    regex: /(?:password|passwd|pwd)\s*[=:]\s*['"]([^'"]{4,})['"]?/gi,
    redactWith: "[REDACTED_PASSWORD]",
  },

  // ── Personal Identifiable Information (PII) ───────────────────────
  {
    name: "Email Address",
    category: "pii",
    severity: "medium",
    regex: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g,
    redactWith: "[REDACTED_EMAIL]",
  },
  {
    name: "US Phone Number",
    category: "pii",
    severity: "medium",
    regex: /\b(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
    redactWith: "[REDACTED_PHONE]",
  },
  {
    name: "US Social Security Number",
    category: "pii",
    severity: "critical",
    regex: /\b\d{3}-\d{2}-\d{4}\b/g,
    redactWith: "[REDACTED_SSN]",
  },
  {
    name: "IP Address (IPv4)",
    category: "pii",
    severity: "low",
    regex: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
    redactWith: "[REDACTED_IP]",
  },

  // ── Financial ──────────────────────────────────────────────────────
  {
    name: "Credit Card Number",
    category: "financial",
    severity: "critical",
    regex: /\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{3,4}\b/g,
    redactWith: "[REDACTED_CREDIT_CARD]",
  },
  {
    name: "IBAN",
    category: "financial",
    severity: "high",
    regex: /\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16}\b/g,
    redactWith: "[REDACTED_IBAN]",
  },
];

module.exports = { PATTERNS };
