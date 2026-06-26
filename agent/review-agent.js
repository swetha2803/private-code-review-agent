#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const os = require("node:os");
const { spawnSync } = require("node:child_process");
const {
  analyzeLogs,
  buildInventory,
  buildMarkdownReport,
  buildReviewPack,
  explainApplicationFlow,
  extractApiInventory,
  isReviewableFile,
  scanText,
  shouldSkipDirectory,
  summarize,
} = require("./agent-core");

const inputPath = path.resolve(process.argv[2] || ".");
const outputDir = path.resolve(process.argv[3] || "reports");

if (!fs.existsSync(inputPath)) {
  console.error(`Source path not found: ${inputPath}`);
  process.exit(1);
}

fs.mkdirSync(outputDir, { recursive: true });

const { sourcePath, cleanup } = prepareSource(inputPath);
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
const applicationFlow = explainApplicationFlow(files, apiInventory);
const reviewPack = buildReviewPack(findings, inventory, apiInventory, logFindings, applicationFlow);
const generatedAt = new Date().toISOString();
const report = {
  tool: "private-code-review-agent",
  generatedAt,
  sourcePath,
  inputPath,
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

cleanup();

if (summary.counts.critical > 0 || summary.counts.high > 0) {
  process.exitCode = 2;
}

function prepareSource(currentPath) {
  const stat = fs.statSync(currentPath);
  if (stat.isDirectory()) {
    return { sourcePath: currentPath, cleanup: () => {} };
  }

  if (path.extname(currentPath).toLowerCase() !== ".zip") {
    console.error("Source must be a folder or .zip file.");
    process.exit(1);
  }

  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "review-agent-zip-"));
  const command = `Expand-Archive -LiteralPath '${escapePowerShellPath(currentPath)}' -DestinationPath '${escapePowerShellPath(tempRoot)}' -Force`;
  const result = spawnSync(
    "powershell",
    ["-NoProfile", "-Command", command],
    { encoding: "utf8" },
  );

  if (result.status !== 0) {
    console.error(result.stderr || result.stdout || "Failed to extract zip.");
    process.exit(1);
  }

  return {
    sourcePath: tempRoot,
    cleanup: () => fs.rmSync(tempRoot, { recursive: true, force: true }),
  };
}

function escapePowerShellPath(value) {
  return String(value).replaceAll("'", "''");
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
