const fs = require("fs");
const path = require("path");
const source = fs.readFileSync(path.join(process.argv[2] || path.resolve(__dirname, "../.."), "src", "shellsentry", "web", "static", "scripts", "app.js"), "utf8");
const checks = [
  ["SSE consumer", /consumeSSE\(response/.test(source)],
  ["init evidence", /regex_evidence/.test(source)],
  ["verdict event", /event === "verdict"/.test(source)],
  ["done event", /event === "done"/.test(source)],
  ["error fallback", /showAuditError/.test(source)],
  ["history replay", /reportView\.loadHistory/.test(source)],
  ["deobfuscation view", /copyDecodedButton/.test(source)]
];
let fail = 0;
for (const [name, ok] of checks) { console.log(`${ok ? "PASS" : "FAIL"} ${name}`); if (!ok) fail++; }
console.log(`PASS=${checks.length - fail} FAIL=${fail}`);
process.exitCode = fail ? 1 : 0;
