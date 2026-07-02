# Testing Guide

## Quick Validation

Run all syntax and unit tests:

```powershell
npm run check
npm test
```

Expected result:

```text
npm run check passed
8 tests passed
```

## Sample End-to-End Review

Run the included dummy sample review:

```powershell
.\tools\test-sample-review.ps1
```

Expected result:

```text
Decision: Reject
Risk score: 185
Findings: 15
APIs: 5
Log findings: 5
Sample review validation passed.
Sample ZIP review validation passed.
```

## Manual Browser Test

Open the dashboard:

```powershell
start .\index.html
```

Recommended checks:

1. Paste code and click `Run Review`.
2. Upload a folder using the file picker.
3. Paste sanitized logs and confirm log findings appear.
4. Fill Integration Lead Workbench fields and generate work pack.
5. Fill EA architecture and ISG security fields and generate pack.
6. Fill LLD/claim notes and validate LLD.
7. Upload a sanitized LLD `.txt`, `.docx`, or `.pptx` and confirm it fills the LLD content box locally.
8. In Source, choose `Code review using LLD`, paste code and LLD notes, then confirm code-vs-LLD findings appear when coverage is missing.
9. Choose `ISG security review` and confirm ISG evidence gaps appear as security findings.
10. Upload a sanitized `.txt`, `.docx`, or `.pptx` EA architecture sample and confirm document change recommendations are generated locally.
7. Save local session.
8. Load latest session.
9. Export session JSON.
10. Import session JSON.
11. Export tracker CSV.
12. Export Markdown report.

## ZIP Review Test

The browser dashboard supports local ZIP upload through bundled `lib/fflate.js`. For repeatable CLI validation, use the local agent:

```powershell
npm run agent -- "C:\path\to\vendor-code.zip"
```

The ZIP is extracted to a local temp folder, scanned locally, and removed after the report is generated.

## Privacy Checks

The project should not contain external service calls for review logic:

```powershell
Select-String -Path index.html,app.js,styles.css,service-worker.js,manifest.webmanifest,README.md,agent\*.js,tools\*.ps1 -Pattern "openai|anthropic|gemini|sendBeacon|XMLHttpRequest"
```

Expected result:

```text
No real external AI/API upload integration.
```

## Test Data Rules

Use only synthetic samples:

- No real customer data.
- No real account numbers.
- No real card numbers.
- No real OTPs.
- No real passwords.
- No production tokens.
- No internal URLs unless masked.

## Release Checklist

Before sharing a ZIP or pushing to Git:

```powershell
npm run check
npm test
.\tools\test-sample-review.ps1
```

Then rebuild package:

```powershell
$items = @('index.html','app.js','styles.css','manifest.webmanifest','service-worker.js','README.md','PRODUCT_PLAN.md','TESTING.md','package.json','agent','tools','scanner-config','samples')
Compress-Archive -Path $items -DestinationPath .\private-code-review-agent.zip -Force
```
