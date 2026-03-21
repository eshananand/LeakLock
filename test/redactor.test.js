const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { redact } = require("../src/redactor");

describe("redactor", () => {
  it("redacts AWS keys in text", () => {
    const text = "key: AKIAIOSFODNN7EXAMPLE";
    const result = redact(text);
    assert.ok(!result.redacted.includes("AKIAIOSFODNN7EXAMPLE"));
    assert.ok(result.redacted.includes("[REDACTED_AWS_KEY]"));
    assert.equal(result.findings.length, 1);
  });

  it("redacts emails", () => {
    const text = "send to john@example.com";
    const result = redact(text);
    assert.ok(!result.redacted.includes("john@example.com"));
    assert.ok(result.redacted.includes("[REDACTED_EMAIL]"));
  });

  it("redacts multiple items in same text", () => {
    const text =
      "email: user@test.com, SSN: 123-45-6789, key: AKIAIOSFODNN7EXAMPLE";
    const result = redact(text);
    assert.ok(!result.redacted.includes("user@test.com"));
    assert.ok(!result.redacted.includes("123-45-6789"));
    assert.ok(!result.redacted.includes("AKIAIOSFODNN7EXAMPLE"));
    assert.ok(result.findings.length >= 3);
  });

  it("returns original text when nothing found", () => {
    const text = "Nothing sensitive here.";
    const result = redact(text);
    assert.equal(result.redacted, text);
    assert.equal(result.findings.length, 0);
  });

  it("handles null input gracefully", () => {
    const result = redact(null);
    assert.equal(result.redacted, null);
    assert.equal(result.findings.length, 0);
  });

  it("provides a summary grouped by category", () => {
    const text = "email: a@b.com SSN: 123-45-6789 key: AKIAIOSFODNN7EXAMPLE";
    const result = redact(text);
    assert.ok(result.summary.pii);
    assert.ok(result.summary.secret);
  });

  it("redacts password assignments", () => {
    const text = 'password = "MyS3cretP@ss!"';
    const result = redact(text);
    assert.ok(result.redacted.includes("[REDACTED_PASSWORD]"));
    assert.ok(!result.redacted.includes("MyS3cretP@ss!"));
  });

  it("redacts database connection strings", () => {
    const text = "mongodb://admin:pass123@cluster0.example.net:27017/mydb";
    const result = redact(text);
    assert.ok(result.redacted.includes("[REDACTED_DB_CONNECTION]"));
  });
});
