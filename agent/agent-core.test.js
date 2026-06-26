"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  buildInventory,
  buildMarkdownReport,
  buildReviewPack,
  isReviewableFile,
  scanText,
  shouldSkipDirectory,
  summarize,
} = require("./agent-core");

test("detects critical secret and auth bypass patterns", () => {
  const findings = scanText(
    "const apiKey = 'abcdefghijklmnopqrstuvwxyz';\nconst skipAuth = true;",
    "Auth.ts",
  );
  assert.equal(findings.some((finding) => finding.id === "hardcoded-secret"), true);
  assert.equal(findings.some((finding) => finding.id === "auth-bypass"), true);
  assert.equal(summarize(findings).decision, "Reject");
});

test("detects high-risk banking transport and storage issues", () => {
  const findings = scanText(
    "fetch('http://bank.example.com/login')\nAsyncStorage.setItem('token', sessionToken)",
    "network.ts",
  );
  assert.equal(findings.some((finding) => finding.id === "http-url"), true);
  assert.equal(findings.some((finding) => finding.id === "async-storage-sensitive"), true);
  assert.equal(summarize(findings).decision, "Hold");
});

test("builds inventory and review pack gates", () => {
  const inventory = buildInventory([
    { relativePath: "android/app/src/main/AndroidManifest.xml" },
    { relativePath: "src/login.test.ts" },
  ]);
  const pack = buildReviewPack([], inventory);
  assert.equal(inventory.android, true);
  assert.equal(inventory.testFiles, 1);
  assert.equal(pack.releaseGates.some((item) => item.includes("No critical")), true);
  assert.equal(pack.evidenceRequests.some((item) => item.includes("Mobile platform")), true);
});

test("markdown report includes findings and release sections", () => {
  const findings = scanText("eval(userInput)", "danger.js");
  const report = {
    generatedAt: "2026-06-26T00:00:00.000Z",
    sourcePath: "vendor",
    summary: summarize(findings),
    findings,
    reviewPack: buildReviewPack(findings, {}),
  };
  const markdown = buildMarkdownReport(report);
  assert.match(markdown, /Vendor Code Review Agent Report/);
  assert.match(markdown, /Dynamic code execution/);
  assert.match(markdown, /Release Gates/);
});

test("file and directory filtering avoids generated dependency folders", () => {
  assert.equal(isReviewableFile("src/App.tsx"), true);
  assert.equal(isReviewableFile("image.png"), false);
  assert.equal(shouldSkipDirectory("node_modules"), true);
  assert.equal(shouldSkipDirectory("src"), false);
});
