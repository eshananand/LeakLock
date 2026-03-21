const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { detect, hasSensitiveData } = require("../src/detector");

describe("detector", () => {
  // ── API Keys ──────────────────────────────────────────────────────
  describe("API key detection", () => {
    it("detects AWS access keys", () => {
      const text = "my key is AKIAIOSFODNN7EXAMPLE";
      const findings = detect(text);
      assert.equal(findings.length, 1);
      assert.equal(findings[0].name, "AWS Access Key");
      assert.equal(findings[0].severity, "critical");
    });

    it("detects GitHub tokens (ghp_)", () => {
      const text = "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
      const findings = detect(text);
      assert.ok(findings.some((f) => f.name === "GitHub Token"));
    });

    it("detects Slack tokens", () => {
      const text = "SLACK_TOKEN=xoxb-1234567890-abcdefghijklmn";
      const findings = detect(text);
      assert.ok(findings.some((f) => f.name === "Slack Token"));
    });

    it("detects OpenAI API keys", () => {
      const text = 'api_key = "sk-abcdefghijklmnopqrstuvwxyz0123456789"';
      const findings = detect(text);
      assert.ok(findings.some((f) => f.name === "OpenAI API Key"));
    });

    it("detects generic api_key assignments", () => {
      const text = 'api_key = "mySecretKeyValue123456"';
      const findings = detect(text);
      assert.ok(findings.some((f) => f.name === "Generic API Key Assignment"));
    });

    it("detects Bearer tokens", () => {
      const text =
        "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.something.here";
      const findings = detect(text);
      assert.ok(findings.some((f) => f.name === "Bearer Token" || f.name === "JWT Token"));
    });

    it("detects private key blocks", () => {
      const text = `
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn...
-----END RSA PRIVATE KEY-----`;
      const findings = detect(text);
      assert.ok(findings.some((f) => f.name === "Private Key Block"));
    });
  });

  // ── PII ───────────────────────────────────────────────────────────
  describe("PII detection", () => {
    it("detects email addresses", () => {
      const text = "contact me at john.doe@example.com please";
      const findings = detect(text);
      assert.ok(findings.some((f) => f.name === "Email Address"));
    });

    it("detects US phone numbers", () => {
      const text = "call me at (555) 123-4567";
      const findings = detect(text);
      assert.ok(findings.some((f) => f.name === "US Phone Number"));
    });

    it("detects SSNs", () => {
      const text = "SSN: 123-45-6789";
      const findings = detect(text);
      assert.ok(findings.some((f) => f.name === "US Social Security Number"));
    });

    it("detects IP addresses", () => {
      const text = "server is at 192.168.1.100";
      const findings = detect(text);
      assert.ok(findings.some((f) => f.name === "IP Address (IPv4)"));
    });
  });

  // ── Financial ─────────────────────────────────────────────────────
  describe("financial data detection", () => {
    it("detects credit card numbers", () => {
      const text = "card: 4111-1111-1111-1111";
      const findings = detect(text);
      assert.ok(findings.some((f) => f.name === "Credit Card Number"));
    });
  });

  // ── Credentials ───────────────────────────────────────────────────
  describe("credential detection", () => {
    it("detects database connection strings", () => {
      const text =
        'db = "postgresql://admin:password123@db.example.com:5432/mydb"';
      const findings = detect(text);
      assert.ok(
        findings.some((f) => f.name === "Database Connection String")
      );
    });

    it("detects password assignments", () => {
      const text = 'password = "SuperSecret123!"';
      const findings = detect(text);
      assert.ok(findings.some((f) => f.name === "Password Assignment"));
    });
  });

  // ── Filtering ─────────────────────────────────────────────────────
  describe("filtering", () => {
    it("filters by category", () => {
      const text = "email: a@b.com key: AKIAIOSFODNN7EXAMPLE";
      const findings = detect(text, { categories: ["pii"] });
      assert.ok(findings.every((f) => f.category === "pii"));
    });

    it("filters by severity", () => {
      const text = "email: a@b.com SSN: 123-45-6789";
      const findings = detect(text, { severities: ["critical"] });
      assert.ok(findings.every((f) => f.severity === "critical"));
    });
  });

  // ── Edge cases ────────────────────────────────────────────────────
  describe("edge cases", () => {
    it("returns empty for clean text", () => {
      const findings = detect("Hello, this is a normal message.");
      assert.equal(findings.length, 0);
    });

    it("handles null/undefined input", () => {
      assert.deepEqual(detect(null), []);
      assert.deepEqual(detect(undefined), []);
      assert.deepEqual(detect(""), []);
    });

    it("hasSensitiveData returns correct boolean", () => {
      assert.equal(hasSensitiveData("clean text"), false);
      assert.equal(hasSensitiveData("email: a@b.com"), true);
    });
  });
});
