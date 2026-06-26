"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

test("review agent CLI scans a folder and writes JSON and Markdown reports", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "vendor-review-agent-"));
  const source = path.join(root, "source");
  const reports = path.join(root, "reports");
  fs.mkdirSync(source);
  fs.writeFileSync(
    path.join(source, "Login.ts"),
    "const apiKey = 'abcdefghijklmnopqrstuvwxyz';\nfetch('http://bank.example.com/login');\n",
  );

  const result = spawnSync(process.execPath, [path.join(__dirname, "review-agent.js"), source, reports], {
    encoding: "utf8",
  });

  assert.equal(result.status, 2);
  assert.match(result.stdout, /Decision: Reject/);

  const outputs = fs.readdirSync(reports);
  const jsonFile = outputs.find((name) => name.endsWith(".json"));
  const markdownFile = outputs.find((name) => name.endsWith(".md"));
  assert.ok(jsonFile);
  assert.ok(markdownFile);

  const report = JSON.parse(fs.readFileSync(path.join(reports, jsonFile), "utf8"));
  assert.equal(report.summary.decision, "Reject");
  assert.equal(report.findings.some((finding) => finding.id === "hardcoded-secret"), true);
  assert.equal(report.findings.some((finding) => finding.id === "http-url"), true);
});
