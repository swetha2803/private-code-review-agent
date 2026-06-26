"use strict";

const path = require("node:path");

const allowedExtensions = new Set([
  ".js",
  ".jsx",
  ".ts",
  ".tsx",
  ".json",
  ".yml",
  ".yaml",
  ".java",
  ".kt",
  ".kts",
  ".swift",
  ".xml",
  ".gradle",
  ".properties",
  ".env",
  ".md",
  ".txt",
  ".log",
]);

const ignoredDirectories = new Set([
  ".git",
  ".next",
  ".turbo",
  "build",
  "dist",
  "coverage",
  "reports",
  "reports-self",
  "node_modules",
  "Pods",
  ".gradle",
  ".idea",
  ".vscode",
]);

const rules = [
  rule("hardcoded-secret", "Possible hardcoded secret", "critical", /\b(api[_-]?key|secret|token|password|passwd|pwd|client[_-]?secret|private[_-]?key)\b\s*[:=]\s*["']?([A-Za-z0-9_./+=-]{12,})/i, "Move secrets to vault/config and rotate exposed values."),
  rule("private-key", "Private key material detected", "critical", /-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/i, "Remove key material and rotate affected credentials."),
  rule("auth-bypass", "Possible auth bypass", "critical", /(bypass|skip|disable|mock).{0,60}(auth|authorization|login|otp|mfa|biometric)/i, "Remove bypass logic from production paths."),
  rule("tls-disabled", "TLS validation disabled", "critical", /(rejectUnauthorized\s*:\s*false|TrustAll|HostnameVerifier|allowAllHostnameVerifier|NSAllowsArbitraryLoads\s*[:=]\s*true)/i, "Restore certificate validation and verify pinning policy."),
  rule("pinning-bypass", "Certificate pinning bypass", "critical", /(pinning|certificatePinner|sslPinning|TrustKit).{0,120}(disable|bypass|false|debug|mock)/i, "Ensure bypass cannot ship in release builds."),
  rule("command-injection", "Possible command injection", "critical", /(exec|spawn|Runtime\.getRuntime\(\)\.exec|ProcessBuilder|system\().{0,120}(input|request|param|body|command)/i, "Remove shell execution or strictly allowlist commands and arguments."),
  rule("jwt", "JWT-like token detected", "high", /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/, "Remove token and verify exposure scope."),
  rule("http-url", "Insecure HTTP endpoint", "high", /http:\/\/(?!localhost|127\.0\.0\.1)[^\s"'<>]+/i, "Use HTTPS and enforce cleartext blocking."),
  rule("async-storage-sensitive", "Sensitive data in insecure storage", "high", /(AsyncStorage|localStorage|SharedPreferences|UserDefaults).{0,100}(token|pin|password|account|session|secret)/i, "Use Keychain, Keystore, or approved encrypted storage."),
  rule("weak-crypto", "Weak cryptography", "high", /\b(MD5|SHA1|DES|3DES|RC4|ECB|PKCS1Padding)\b/i, "Use approved modern cryptography."),
  rule("eval", "Dynamic code execution", "high", /\b(eval|new Function|setTimeout\s*\(\s*["'`]|setInterval\s*\(\s*["'`])\b/, "Replace dynamic execution with explicit logic."),
  rule("sql-concat", "Possible SQL concatenation", "high", /(SELECT|INSERT|UPDATE|DELETE).{0,120}(\+|\$\{).{0,120}(where|values|from|into)/i, "Use parameterized queries."),
  rule("pii-in-code", "PII or banking identifier exposure", "high", /(accountNumber|customerId|cif|pan|iban|aadhaar|ssn|dateOfBirth|dob).{0,80}(["'`]|console|Log\.|print)/i, "Mask or tokenize sensitive values."),
  rule("otp-weakness", "OTP or MFA weakness", "high", /(otp|mfa|oneTimePassword).{0,120}(hardcode|default|123456|000000|autoFill|clipboard|log|console)/i, "Verify expiry, retry, lockout, redaction, and replay prevention."),
  rule("webview-risk", "Risky WebView configuration", "high", /(javaScriptEnabled\s*[:=]\s*true|setJavaScriptEnabled\s*\(\s*true|allowFileAccess\s*[:=]\s*true|setAllowFileAccess\s*\(\s*true|originWhitelist\s*=\s*\{\s*\[\s*['"]\*['"])/i, "Restrict origins and file access."),
  rule("insecure-random", "Insecure randomness", "high", /\b(Math\.random|Random\(|arc4random\(|java\.util\.Random)\b/, "Use cryptographically secure randomness."),
  rule("insecure-cookie", "Cookie security attributes may be missing", "high", /Set-Cookie(?!.*HttpOnly)(?!.*Secure)(?!.*SameSite)/i, "Use Secure, HttpOnly, and SameSite."),
  rule("android-exported", "Android exported component", "high", /android:exported\s*=\s*["']true["']/i, "Require permission and auth validation."),
  rule("android-backup-enabled", "Android backup enabled", "high", /android:allowBackup\s*=\s*["']true["']/i, "Disable backup or define exclusions."),
  rule("clipboard-sensitive", "Sensitive clipboard use", "high", /(Clipboard|UIPasteboard|setString|setPrimaryClip).{0,100}(otp|token|password|pin|account|card)/i, "Avoid copying sensitive data."),
  rule("unsafe-deserialization", "Unsafe deserialization", "critical", /(ObjectInputStream|readObject\(|pickle\.loads|yaml\.load\(|JSON\.parse\().{0,120}(request|input|payload|body|params)/i, "Use strict schemas and safe parsers."),
  rule("path-traversal", "Possible path traversal", "high", /(readFile|writeFile|File\(|Paths\.get|path\.join).{0,120}(request|param|input|filename|fileName|path)/i, "Normalize paths and constrain directories."),
  rule("cors-wide-open", "Wide-open CORS", "high", /(Access-Control-Allow-Origin|cors\().{0,80}(\*|origin\s*:\s*true)/i, "Restrict allowed origins."),
  rule("analytics-sensitive", "Sensitive telemetry", "high", /(analytics|firebase|crashlytics|appcenter|sentry|datadog|newrelic).{0,120}(account|card|pan|token|password|otp|pin|customer)/i, "Redact telemetry and crash data."),
  rule("console-log", "Runtime logging", "medium", /\b(console\.(log|warn|error|debug)|Log\.(d|i|w|e)|print\s*\()/, "Remove debug logs or use redacting logger."),
  rule("debug-enabled", "Debug mode enabled", "medium", /\b(debuggable\s+true|DEBUG\s*=\s*true|__DEV__\s*===?\s*true|devMode\s*[:=]\s*true)\b/i, "Disable debug in release builds."),
  rule("biometric-fallback", "Biometric fallback review", "medium", /(biometric|faceId|touchId|LocalAuthentication).{0,120}(fallback|passcode|skip|cancel)/i, "Review fallback and step-up rules."),
  rule("root-jailbreak-missing", "Root/jailbreak bypassable", "medium", /(rooted|jailbreak|tamper|frida|magisk).{0,120}(false|skip|bypass|disable|mock)/i, "Enforce release policy."),
  rule("excessive-permission", "Sensitive mobile permission", "medium", /(READ_SMS|RECEIVE_SMS|READ_CONTACTS|READ_CALL_LOG|ACCESS_FINE_LOCATION|RECORD_AUDIO|CAMERA)/, "Require business/privacy justification."),
  rule("dependency-risk", "Dynamic dependency resolution", "medium", /(resolutionStrategy|force\s+["']|latest\.release|\+["']|changing\s*=\s*true)/i, "Pin approved versions."),
  rule("screenshot-risk", "Screen capture control review", "medium", /(FLAG_SECURE|isScreenCaptureEnabled|UIScreenCapturedDidChange|screenCapture).{0,120}(false|disable|remove|TODO|FIXME)/i, "Verify sensitive screen protection."),
  rule("deep-link-risk", "Deep link review", "medium", /(intent-filter|CFBundleURLSchemes|Linking\.addEventListener|openURL|handleOpenURL|deepLink|deeplink)/i, "Require auth and parameter validation."),
  rule("rate-limit-review", "Rate-limit review needed", "medium", /(login|otp|mfa|password|pin|beneficiary|transfer).{0,120}(endpoint|route|api|mutation|request)/i, "Verify lockout, replay, idempotency, and fraud monitoring."),
  rule("test-only-code", "Test-only banking logic", "medium", /(mock|stub|fake|dummy|sandbox).{0,100}(payment|transfer|auth|otp|login|account|beneficiary)/i, "Exclude test-only code from release artifacts."),
  rule("todo-security", "Security-sensitive TODO", "low", /(TODO|FIXME|HACK).{0,100}(security|auth|encrypt|token|password|temporary|bypass)/i, "Track and close before release."),
  rule("mojibake-encoding", "Possible corrupted pasted characters or encoding issue", "medium", /[\u00e2\ufffd]/, "Remove corrupted characters or save/compile with the correct UTF-8 encoding."),
  rule("filewriter-dynamic-path", "Dynamic file write path needs validation", "medium", /new\s+FileWriter\s*\(\s*[A-Za-z0-9_]+|Files\.write\s*\(\s*[A-Za-z0-9_]+/i, "Validate and constrain output paths before writing files."),
  rule("mutable-map-return", "Mutable internal map may be exposed", "medium", /Map<[^>]+>\s+get[A-Za-z0-9_]*\s*\(\)\s*\{\s*return\s+[A-Za-z0-9_]+;\s*\}/, "Return an unmodifiable copy instead of exposing internal mutable state."),
  rule("interrupted-no-reinterrupt", "InterruptedException may not restore interrupt status", "medium", /catch\s*\([^)]*InterruptedException[^)]*\)\s*\{(?![^}]*Thread\.currentThread\(\)\.interrupt\(\))/s, "Call Thread.currentThread().interrupt() when InterruptedException is caught."),
  rule("quantity-no-validation", "Quantity input may lack positive-value validation", "medium", /(addItem|reduceStock)\s*\([^)]*int\s+quantity[^)]*\)\s*\{(?![^}]*quantity\s*<=\s*0)(?![^}]*quantity\s*<\s*1)/s, "Validate quantity is positive before stock or order calculations."),
  rule("money-double", "Money represented with double", "low", /\bdouble\s+(price|subtotal|finalTotal|amount|tax|discount)|double\s+calculate\s*\(/i, "Use BigDecimal or a money type for financial calculations."),
];

function rule(id, title, severity, pattern, fix) {
  return {
    id,
    title,
    severity,
    pattern,
    description: title,
    fix,
  };
}

function isReviewableFile(filePath) {
  const base = path.basename(filePath);
  if (base === "Dockerfile" || base === "Podfile" || base === "Gemfile") return true;
  return allowedExtensions.has(path.extname(filePath).toLowerCase());
}

function shouldSkipDirectory(directoryName) {
  return ignoredDirectories.has(directoryName);
}

function scanText(content, file = "input") {
  const findings = [];
  const lines = String(content).split(/\r?\n/);

  lines.forEach((line, index) => {
    for (const item of rules) {
      item.pattern.lastIndex = 0;
      if (item.pattern.test(line)) {
        findings.push({
          id: item.id,
          title: item.title,
          severity: item.severity,
          description: item.description,
          fix: item.fix,
          file,
          line: index + 1,
          snippet: line.trim().slice(0, 360),
          source: "review-agent",
        });
      }
    }
  });

  findings.push(...reviewFileShape(file, lines));
  return findings;
}

function extractApiInventory(files) {
  const apiMap = new Map();

  for (const file of files) {
    const content = file.content || "";
    const lines = content.split(/\r?\n/);
    lines.forEach((line, index) => {
      const candidates = [
        ...line.matchAll(/\b(fetch|axios\.(get|post|put|patch|delete)|client\.(get|post|put|patch|delete))\s*\(\s*["'`]([^"'`]+)["'`]/gi),
        ...line.matchAll(/\b(GET|POST|PUT|PATCH|DELETE)\s+([/][A-Za-z0-9_./:{}?-]+)/gi),
        ...line.matchAll(/\b(url|endpoint|path)\s*[:=]\s*["'`]([^"'`]*\/[A-Za-z0-9_./:{}?-]+)["'`]/gi),
      ];

      for (const match of candidates) {
        const rawMethod = (match[2] || match[1] || "UNKNOWN").toUpperCase();
        const method = ["GET", "POST", "PUT", "PATCH", "DELETE"].includes(rawMethod)
          ? rawMethod
          : inferMethod(line);
        const endpoint = normalizeEndpoint(lastMatchGroup(match));
        if (!endpoint || endpoint.length < 2) continue;
        const key = `${method} ${endpoint}`;
        const existing = apiMap.get(key) || {
          method,
          endpoint,
          files: new Set(),
          firstLine: index + 1,
          risk: classifyApiRisk(endpoint, line),
          reviewed: "Needs review",
        };
        existing.files.add(file.relativePath || file.name || "input");
        existing.risk = mergeRisk(existing.risk, classifyApiRisk(endpoint, line));
        apiMap.set(key, existing);
      }
    });
  }

  return [...apiMap.values()].map((api) => ({
    method: api.method,
    endpoint: api.endpoint,
    files: [...api.files],
    firstLine: api.firstLine,
    risk: api.risk,
    reviewed: api.reviewed,
    reviewFocus: apiReviewFocus(api.endpoint),
  }));
}

function explainApplicationFlow(files, apiInventory = []) {
  const classNames = new Set();
  const methodNames = new Set();
  const filesByType = {
    mobile: [],
    frontend: [],
    backend: [],
    config: [],
    logs: [],
    tests: [],
  };

  for (const file of files) {
    const name = (file.relativePath || file.name || "").toLowerCase();
    const content = file.content || "";
    for (const match of content.matchAll(/\b(class|interface|enum)\s+([A-Za-z0-9_]+)/g)) {
      classNames.add(match[2]);
    }
    for (const match of content.matchAll(/\b(public|private|protected|async|function)\s+[A-Za-z0-9_<>,\[\]\s]+\s+([A-Za-z0-9_]+)\s*\(/g)) {
      methodNames.add(match[2]);
    }

    if (/android|ios|mobile|react-native|swift|kotlin/.test(name)) filesByType.mobile.push(file.relativePath || file.name);
    else if (/frontend|screen|component|page|tsx|jsx|html|css/.test(name)) filesByType.frontend.push(file.relativePath || file.name);
    else if (/api|service|controller|repository|backend|java|kt|ts|js/.test(name)) filesByType.backend.push(file.relativePath || file.name);
    else if (/\.(json|ya?ml|properties|gradle|xml|env)$/.test(name)) filesByType.config.push(file.relativePath || file.name);
    else if (/\.log$/.test(name)) filesByType.logs.push(file.relativePath || file.name);
    if (/(\.test\.|\.spec\.|__tests__|test\/|tests\/)/.test(name)) filesByType.tests.push(file.relativePath || file.name);
  }

  const highRiskApis = apiInventory.filter((api) => api.risk !== "low");
  return {
    summary: [
      `Files reviewed: ${files.length}`,
      `Classes/interfaces detected: ${classNames.size}`,
      `Methods/functions detected: ${methodNames.size}`,
      `APIs/endpoints detected: ${apiInventory.length}`,
      `High/medium risk APIs: ${highRiskApis.length}`,
    ],
    likelyFlow: [
      filesByType.mobile.length && "Mobile/UI layer collects user input and calls service/API layer.",
      filesByType.frontend.length && "Frontend components/screens appear to handle user interaction and API calls.",
      filesByType.backend.length && "Backend/service layer appears to process business logic, integration calls, and data operations.",
      apiInventory.length && "API layer should be reviewed for authentication, authorization, validation, timeout, retry, and error mapping.",
      filesByType.config.length && "Configuration files should be reviewed for environment values, secrets, endpoints, and security flags.",
      filesByType.logs.length && "Logs should be reviewed for errors, correlation IDs, PII masking, and integration ownership.",
      filesByType.tests.length ? "Automated tests are present and should be mapped to FS/security scenarios." : "No obvious test files detected; request unit/SIT/UAT evidence.",
    ].filter(Boolean),
    keyComponents: [...classNames].slice(0, 30),
    keyMethods: [...methodNames].slice(0, 30),
    filesByType,
    reviewQuestions: [
      "What is the entry point and trigger for this change?",
      "Which APIs/systems are upstream and downstream?",
      "Where is authentication and authorization enforced?",
      "Where is customer/financial data stored, logged, cached, or transmitted?",
      "What happens on timeout, retry, duplicate request, and partial failure?",
      "Which team owns each API, log, defect, and deployment step?",
    ],
  };
}

function analyzeLogs(text, file = "logs") {
  const findings = [];
  const lines = String(text || "").split(/\r?\n/);
  const patterns = [
    ["log-secret", "Secret or token may appear in logs", "critical", /(api[_-]?key|secret|token|password|authorization|bearer)\s*[:=]?\s*(bearer\s+)?[A-Za-z0-9_.:/+=-]{8,}/i, "Remove value from logs and rotate if real."],
    ["log-pii", "PII or banking identifier may appear in logs", "high", /(accountNumber|customerId|cif|pan|iban|aadhaar|ssn|cardNumber|mobileNumber|email)\s*[:=]/i, "Mask PII and banking identifiers."],
    ["log-stacktrace", "Stack trace or internal error exposed", "medium", /(Exception|StackTrace|NullPointerException|TypeError|ReferenceError|at\s+[A-Za-z0-9_.]+\()/, "Return generic errors and keep detailed traces server-side only."],
    ["log-auth-failure", "Authentication failure pattern", "medium", /(401|403|invalid otp|otp failed|login failed|unauthorized|forbidden)/i, "Check lockout, alerting, and user-safe messages."],
    ["log-timeout", "Timeout or integration instability", "medium", /(timeout|timed out|ECONNRESET|ENOTFOUND|503|504|gateway)/i, "Confirm retry, idempotency, and escalation ownership."],
  ];

  lines.forEach((line, index) => {
    for (const [id, title, severity, pattern, fix] of patterns) {
      if (pattern.test(line)) {
        findings.push({
          id,
          title,
          severity,
          description: title,
          fix,
          file,
          line: index + 1,
          snippet: line.trim().slice(0, 360),
          source: "log-analyzer",
        });
      }
    }
  });

  return findings;
}

function reviewFileShape(file, lines) {
  const content = lines.join("\n");
  const extension = path.extname(file).toLowerCase();
  const findings = [];

  if ([".js", ".jsx", ".ts", ".tsx", ".java", ".kt", ".swift"].includes(extension) && lines.length > 700) {
    findings.push(extraFinding("large-file", "Large source file", "low", file, 1, `${lines.length} lines`, "Split responsibilities and require focused tests."));
  }

  if (/(axios|fetch\s*\(|URLSession|OkHttp|Retrofit)/.test(content) && !/(timeout|AbortController|callTimeout|readTimeout|timeoutInterval)/.test(content)) {
    findings.push(extraFinding("network-timeout", "Network call may lack timeout", "medium", file, findLine(lines, /(axios|fetch\s*\(|URLSession|OkHttp|Retrofit)/), "Network call detected without obvious timeout.", "Add timeout, cancellation, retry, and failure handling tests."));
  }

  if (/password|pin|otp|token/i.test(content) && !/mask|redact|secureTextEntry|obscure/i.test(content)) {
    findings.push(extraFinding("sensitive-ui-masking", "Sensitive UI masking review", "medium", file, findLine(lines, /password|pin|otp|token/i), "Sensitive keyword found without obvious masking pattern.", "Verify masking, redaction, and screenshot controls."));
  }

  return findings;
}

function extraFinding(id, title, severity, file, line, snippet, fix) {
  return {
    id,
    title,
    severity,
    description: title,
    fix,
    file,
    line,
    snippet,
    source: "review-agent",
  };
}

function summarize(findings) {
  const counts = findings.reduce(
    (all, finding) => {
      all[finding.severity] += 1;
      return all;
    },
    { critical: 0, high: 0, medium: 0, low: 0 },
  );
  const riskScore = counts.critical * 40 + counts.high * 15 + counts.medium * 5 + counts.low;
  const decision =
    counts.critical > 0
      ? "Reject"
      : counts.high > 0
        ? "Hold"
        : counts.medium > 5
          ? "Needs review"
          : findings.length
            ? "Conditional"
            : "No blocking findings";
  return { counts, riskScore, decision, total: findings.length };
}

function buildReviewPack(findings, inventory = {}, apiInventory = [], logFindings = [], flow = null) {
  const { counts, riskScore, decision } = summarize(findings);
  const ids = new Set(findings.map((finding) => finding.id));
  const hasMobile = Boolean(inventory.android || inventory.ios || inventory.reactNative);
  const highRiskApis = apiInventory.filter((api) => api.risk !== "low");

  return {
    generatedAt: new Date().toISOString(),
    decision,
    riskScore,
    counts,
    evidenceRequests: [
      "SAST report with rule set, scan date, commit hash, and zero unresolved critical/high issues.",
      "Secret scan report and written confirmation that no real credentials are present.",
      "SCA/dependency report with CVE status, license status, and risk acceptance for exceptions.",
      "Unit test and coverage report for changed modules, including negative/security tests.",
      "Release build evidence showing debug disabled and test/mock code excluded.",
      hasMobile && "Mobile platform evidence for secure storage, TLS/pinning, manifest/plist, anti-tamper, and sensitive permissions.",
      ids.has("analytics-sensitive") && "Telemetry/crash data dictionary proving no PII, account, OTP, PIN, token, or card leakage.",
      ids.has("android-exported") && "Android exported component justification and permission/auth validation evidence.",
      ids.has("pinning-bypass") && "MITM test result proving pinning cannot be bypassed in release builds.",
    ].filter(Boolean),
    securityTests: [
      "Run SAST, secret scanning, dependency scanning, and release artifact review.",
      "Test login, OTP/MFA, beneficiary, transfer, cards, statements, profile, and logout flows.",
      "Test API authZ by modifying customer/account/beneficiary IDs.",
      "Test replay, duplicate submit, idempotency, timeout-after-debit, and pending transaction recovery.",
      "Test rooted/jailbroken, emulator, proxy, invalid certificate, clock tamper, offline, and app resume scenarios.",
      ids.has("webview-risk") && "Test WebView origin, JavaScript bridge, file access, and link handling.",
      ids.has("clipboard-sensitive") && "Test clipboard exposure and clearing behavior.",
    ].filter(Boolean),
    unitTests: [
      "Generate unit tests for success, failure, timeout, retry, cancellation, null, malformed, and oversized response paths.",
      "Generate authorization tests for wrong customer/account/beneficiary IDs.",
      "Generate logout/session-expiry tests proving sensitive cache/state is cleared.",
      "Generate validation tests for amount precision, limits, currency mismatch, and beneficiary status.",
      "Generate redaction tests for logs, telemetry, errors, and crash payloads.",
      ids.has("sql-concat") && "Generate injection tests for SQL/query inputs.",
      ids.has("deep-link-risk") && "Generate deep-link tests proving protected screens require re-authentication.",
    ].filter(Boolean),
    manualReview: [
      "Trace every auth/session/token path from UI to API and logout.",
      "Trace every money-movement path for authorization, confirmation, audit, and idempotency.",
      "Review all configs for environment mix-ups, mock endpoints, feature flags, and internal URLs.",
      "Review third-party SDK initialization, permissions, telemetry, and data collection.",
      "Review CI/build scripts for skipped tests, ignored scanner failures, or release signing shortcuts.",
      "Review every TODO/FIXME/HACK in auth, payment, crypto, storage, logging, and API code.",
    ],
    abuseCases: [
      "Replay a transfer with same request ID and changed amount.",
      "Open protected screens from deep links, push notifications, browser redirects, and app shortcuts.",
      "Submit OTP after expiry, after successful use, and across devices/sessions.",
      "Use long strings, Unicode, path traversal, SQL meta characters, and JSON type confusion payloads.",
      "Try screenshots, screen recordings, clipboard reads, and notification preview leakage.",
    ],
    releaseGates: [
      counts.critical > 0 ? "BLOCK: Critical findings must be fixed." : "PASS: No critical findings in this result set.",
      counts.high > 0 ? "HOLD: High findings require remediation or formal risk acceptance." : "PASS: No high findings in this result set.",
      "Require clean secret scan.",
      "Require SCA/dependency evidence.",
      "Require manual review sign-off for auth, payment, beneficiary, and statement flows.",
      "Require retest evidence after vendor remediation.",
    ],
    dummyTests: [
      "Synthetic customer IDs, accounts, cards, phones, emails, names, and addresses only.",
      "Profiles: valid, locked, dormant, KYC-pending, high-risk, closed, and migrated customer.",
      "Balances: zero, maximum, decimal precision, currency mismatch, insufficient funds, and limit exceeded.",
      "Auth: wrong PIN, expired OTP, reused OTP, locked account, changed device, and session timeout.",
      "Transactions: duplicate submit, retry after timeout, pending status, reversal, and failed beneficiary validation.",
    ],
    apiReview: apiInventory,
    logAnalysis: {
      totalFindings: logFindings.length,
      findings: logFindings,
      requiredActions: [
        "Confirm logs do not contain tokens, passwords, OTPs, PANs, account numbers, or customer identifiers.",
        "Confirm correlation IDs exist for integration tracing without exposing sensitive data.",
        "Confirm timeout/retry errors identify owning team, API, timestamp, environment, and request ID.",
      ],
    },
    communication: buildCommunicationPack(findings, apiInventory, logFindings, decision, riskScore, highRiskApis),
    applicationFlow: flow || {
      summary: ["Flow analysis requires source files."],
      likelyFlow: ["Upload/paste source or run the local agent to generate flow explanation."],
      keyComponents: [],
      keyMethods: [],
      filesByType: {},
      reviewQuestions: [],
    },
  };
}

function buildCommunicationPack(findings, apiInventory, logFindings, decision, riskScore, highRiskApis) {
  const criticalHigh = findings.filter((finding) => ["critical", "high"].includes(finding.severity));
  const subjectPrefix = decision === "Reject" || decision === "Hold" ? "Action Required" : "Review Update";
  const topIssues = criticalHigh.slice(0, 6).map((finding) => `${finding.severity.toUpperCase()}: ${finding.file}:${finding.line} ${finding.title}`);
  const apiLines = highRiskApis.slice(0, 8).map((api) => `${api.method} ${api.endpoint} - ${api.risk} risk`);
  const logLines = logFindings.slice(0, 6).map((finding) => `${finding.severity.toUpperCase()}: ${finding.file}:${finding.line} ${finding.title}`);

  return {
    vendorMessage: [
      `Subject: ${subjectPrefix}: Vendor code review findings and evidence request`,
      "",
      "Hi Team,",
      "",
      `We completed the local review pass. Current decision is ${decision} with risk score ${riskScore}.`,
      criticalHigh.length
        ? "Please address the below blocking/security findings and share remediation evidence:"
        : "No critical/high automated findings are currently open, but the below evidence is still required for closure:",
      ...bulletLines(topIssues.length ? topIssues : ["SAST, SCA, secret scan, unit test, and release build evidence required."]),
      "",
      "Please provide fix commits, test proof, owner, ETA, and retest notes for each item.",
      "",
      "Regards,",
    ].join("\n"),
    apiReviewMessage: [
      `Subject: API review status and integration evidence required`,
      "",
      "Hi Team,",
      "",
      `We identified ${apiInventory.length} API/endpoints from the submitted source. ${highRiskApis.length} need focused integration/security review.`,
      ...bulletLines(apiLines.length ? apiLines : ["No high-risk API patterns detected by the local parser. Manual API contract review is still required."]),
      "",
      "Please share API contracts, auth scheme, request/response samples with masked data, timeout/retry behavior, error mapping, and owning team contacts.",
      "",
      "Regards,",
    ].join("\n"),
    logIssueMessage: [
      `Subject: Log analysis findings and integration follow-up`,
      "",
      "Hi Team,",
      "",
      `Log analysis found ${logFindings.length} item(s) requiring review.`,
      ...bulletLines(logLines.length ? logLines : ["No log findings imported or detected. Please share sanitized logs with correlation IDs if analysis is needed."]),
      "",
      "Please confirm masking, correlation ID, timestamp, environment, API name, owning team, retry behavior, and closure action.",
      "",
      "Regards,",
    ].join("\n"),
    meetingAgenda: [
      "Review blocker summary and decision gate.",
      "Confirm API inventory and ownership.",
      "Walk through critical/high findings and remediation ETA.",
      "Review logs, correlation IDs, and integration failure ownership.",
      "Confirm evidence pack: SAST, SCA, secret scan, unit tests, release build, and retest proof.",
      "Agree next checkpoint and closure criteria.",
    ],
    statusSummary: [
      `Decision: ${decision}`,
      `Risk score: ${riskScore}`,
      `Total findings: ${findings.length}`,
      `APIs identified: ${apiInventory.length}`,
      `Log findings: ${logFindings.length}`,
      `Blocking findings: ${criticalHigh.length}`,
    ],
  };
}

function buildInventory(files) {
  const names = files.map((file) => file.relativePath.toLowerCase());
  return {
    fileCount: files.length,
    android: names.some((name) => name.endsWith("androidmanifest.xml") || name.includes("/android/")),
    ios: names.some((name) => name.endsWith("info.plist") || name.includes("/ios/")),
    reactNative: names.some((name) => name.endsWith("package.json")) || names.some((name) => name.includes("react-native")),
    configFiles: names.filter((name) => /\.(json|ya?ml|properties|gradle|env|xml)$/.test(name)).length,
    testFiles: names.filter((name) => /(\.test\.|\.spec\.|__tests__|test\/|tests\/)/.test(name)).length,
  };
}

function buildMarkdownReport(report) {
  const lines = [
    "# Vendor Code Review Agent Report",
    "",
    `Generated: ${report.generatedAt}`,
    `Source: ${report.sourcePath}`,
    `Decision: ${report.summary.decision}`,
    `Risk score: ${report.summary.riskScore}`,
    `Findings: critical ${report.summary.counts.critical}, high ${report.summary.counts.high}, medium ${report.summary.counts.medium}, low ${report.summary.counts.low}`,
    "",
    "## Findings",
  ];

  if (report.findings.length) {
    for (const finding of report.findings) {
      lines.push(`- [${finding.severity.toUpperCase()}] ${finding.file}:${finding.line} ${finding.title} (${finding.id})`);
    }
  } else {
    lines.push("- No automated findings in this result set.");
  }

  const sections = [
    ["Application Flow", [...report.reviewPack.applicationFlow.summary, ...report.reviewPack.applicationFlow.likelyFlow]],
    ["Flow Review Questions", report.reviewPack.applicationFlow.reviewQuestions],
    ["API Inventory", report.reviewPack.apiReview.map((api) => `${api.method} ${api.endpoint} - ${api.risk} risk - ${api.reviewFocus}`)],
    ["Log Analysis Actions", report.reviewPack.logAnalysis.requiredActions],
    ["Vendor Message", [report.reviewPack.communication.vendorMessage]],
    ["API Review Message", [report.reviewPack.communication.apiReviewMessage]],
    ["Log Issue Message", [report.reviewPack.communication.logIssueMessage]],
    ["Evidence Requests", report.reviewPack.evidenceRequests],
    ["Security Tests", report.reviewPack.securityTests],
    ["Unit Tests To Request Or Generate", report.reviewPack.unitTests],
    ["Manual Review", report.reviewPack.manualReview],
    ["Abuse Cases", report.reviewPack.abuseCases],
    ["Release Gates", report.reviewPack.releaseGates],
    ["Dummy Test Data", report.reviewPack.dummyTests],
  ];

  for (const [title, items] of sections) {
    lines.push("", `## ${title}`);
    for (const item of items) lines.push(`- ${item}`);
  }

  return `${lines.join("\n")}\n`;
}

function inferMethod(line) {
  const lowered = line.toLowerCase();
  if (lowered.includes(".post") || lowered.includes("post")) return "POST";
  if (lowered.includes(".put") || lowered.includes("put")) return "PUT";
  if (lowered.includes(".patch") || lowered.includes("patch")) return "PATCH";
  if (lowered.includes(".delete") || lowered.includes("delete")) return "DELETE";
  return "GET";
}

function normalizeEndpoint(endpoint) {
  return String(endpoint)
    .replace(/^https?:\/\/[^/]+/i, "")
    .replace(/\?.*$/, "")
    .trim();
}

function lastMatchGroup(match) {
  for (let index = match.length - 1; index >= 1; index -= 1) {
    if (match[index]) return match[index];
  }
  return "";
}

function classifyApiRisk(endpoint, line) {
  const value = `${endpoint} ${line}`.toLowerCase();
  if (/(transfer|payment|beneficiary|otp|mfa|login|password|pin|card|account|statement)/.test(value)) return "high";
  if (/(profile|customer|user|session|token|auth|limit|balance)/.test(value)) return "medium";
  return "low";
}

function mergeRisk(a, b) {
  const order = { low: 1, medium: 2, high: 3 };
  return order[b] > order[a] ? b : a;
}

function apiReviewFocus(endpoint) {
  const value = endpoint.toLowerCase();
  if (/(transfer|payment)/.test(value)) return "Authorization, idempotency, limit checks, confirmation, audit trail, and timeout-after-debit handling.";
  if (/beneficiary/.test(value)) return "Cooling period, maker-checker where applicable, validation, fraud controls, and notification.";
  if (/(otp|mfa|login|password|pin)/.test(value)) return "Brute-force control, replay prevention, session binding, error leakage, and lockout.";
  if (/(account|statement|balance|profile|customer)/.test(value)) return "Customer authorization, PII masking, caching, and privacy logging.";
  return "Contract validation, auth, error handling, timeout, retry, and owning team.";
}

function bulletLines(items) {
  return items.map((item) => `- ${item}`);
}

function findLine(lines, pattern) {
  const index = lines.findIndex((line) => pattern.test(line));
  return index >= 0 ? index + 1 : 1;
}

module.exports = {
  allowedExtensions,
  ignoredDirectories,
  rules,
  buildInventory,
  analyzeLogs,
  extractApiInventory,
  explainApplicationFlow,
  buildMarkdownReport,
  buildReviewPack,
  isReviewableFile,
  scanText,
  shouldSkipDirectory,
  summarize,
};
