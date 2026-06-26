#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const {
  analyzeLogs,
  buildInventory,
  buildMarkdownReport,
  buildReviewPack,
  extractApiInventory,
  isReviewableFile,
  scanText,
  shouldSkipDirectory,
  summarize,
} = require("./agent-core");

const sourcePath = path.resolve(process.argv[2] || ".");
const outputDir = path.resolve(process.argv[3] || "reports");

if (!fs.existsSync(sourcePath)) {
  console.error(`Source path not found: ${sourcePath}`);
  process.exit(1);
}

fs.mkdirSync(outputDir, { recursive: true });

const files = collectFiles(sourcePath);
const findings = [];
const logFindings = [];

for (const file of files) {
  const content = fs.readFileSync(file.absolutePath, "utf8");
  file.content = content;
  findings.push(...scanText(content, file.relativePath));
  if (file.relativePath.toLowerCase().endsWith(".log")) {
    logFindings.push(...analyzeLogs(content, file.relativePath));
  }
}

const inventory = buildInventory(files);
const summary = summarize(findings);
const apiInventory = extractApiInventory(files);
const reviewPack = buildReviewPack(findings, inventory, apiInventory, logFindings);
const generatedAt = new Date().toISOString();
const report = {
  tool: "private-code-review-agent",
  generatedAt,
  sourcePath,
  inventory,
  apiInventory,
  summary,
  findings,
  logFindings,
  reviewPack,
};

const stamp = generatedAt.replace(/[:.]/g, "-");
const jsonPath = path.join(outputDir, `agent-review-${stamp}.json`);
const markdownPath = path.join(outputDir, `agent-review-${stamp}.md`);

fs.writeFileSync(jsonPath, `${JSON.stringify(report, null, 2)}\n`);
fs.writeFileSync(markdownPath, buildMarkdownReport(report));

console.log(`Decision: ${summary.decision}`);
console.log(`Risk score: ${summary.riskScore}`);
console.log(`Findings: ${findings.length}`);
console.log(`APIs: ${apiInventory.length}`);
console.log(`Log findings: ${logFindings.length}`);
console.log(`JSON: ${jsonPath}`);
console.log(`Markdown: ${markdownPath}`);

if (summary.counts.critical > 0 || summary.counts.high > 0) {
  process.exitCode = 2;
}

function collectFiles(root) {
  const collected = [];
  walk(root);
  return collected;

  function walk(current) {
    const entries = fs.readdirSync(current, { withFileTypes: true });
    for (const entry of entries) {
      const absolutePath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        if (!shouldSkipDirectory(entry.name)) walk(absolutePath);
        continue;
      }
      if (!entry.isFile() || !isReviewableFile(absolutePath)) continue;
      const relativePath = path.relative(root, absolutePath).replaceAll(path.sep, "/");
      collected.push({ absolutePath, relativePath });
    }
  }
}
