const fs = require("fs");
const path = require("path");
const vm = require("vm");
const root = process.argv[2] || path.resolve(__dirname, "../..");
const staticDir = path.join(root, "src", "shellsentry", "web", "static");
const scripts = fs.readdirSync(path.join(staticDir, "scripts")).filter(name => name.endsWith(".js"));
let failures = 0;
let skipped = 0;

// 语法检查必须在**当前进程内**完成，不能 spawn 子进程。
//
// 事故记录（2026-10-07）：本守卫原先用 spawnSync(process.execPath, ["--check", file])，
// 在本机环境下 Node 进程内 spawn 任何 Node 都会返回 EBUSY —— 检查根本没执行，
// 而脚本却按 "status !== 0" 判成 FAIL；更糟的是后来改成 SKIP 后又变成假 PASS：
// 注入真实语法错误（function broken( {）依然报 PASS=12 FAIL=0。
// 即守卫在最需要它的场景下完全失效。现改为进程内解析，无子进程依赖。
//
// 另一个坑：这些前端文件是 ESM（含 import/export），按 CJS 规则解析会误报
// "Cannot use import statement outside a module"。解决办法是剥掉 ESM 语法
// 关键字后再交给 vm.Script —— 我们只关心括号/分号/字符串等结构性语法错误，
// 而 import/export 本身是合法的，只是 vm.Script 不认识。
function stripEsmSyntax(source) {
  return source
    // import ... from '...' / import '...'
    .replace(/^\s*import\s+[^;]*?from\s+["'][^"']+["'];?\s*$/gm, "")
    .replace(/^\s*import\s+["'][^"']+["'];?\s*$/gm, "")
    // export const/let/function/class/default/async function
    .replace(/^\s*export\s+default\s+/gm, "void ")
    .replace(/^\s*export\s+(?=(const|let|var|function|class|async))/gm, "")
    // export { a, b } / export * from '...'
    .replace(/^\s*export\s*\{[^}]*\}\s*;?\s*$/gm, "")
    .replace(/^\s*export\s+\*\s+from\s+["'][^"']+["'];?\s*$/gm, "");
}

for (const name of scripts) {
  const file = path.join(staticDir, "scripts", name);
  try {
    new vm.Script(stripEsmSyntax(fs.readFileSync(file, "utf8")), { filename: file });
    console.log(`PASS syntax ${name}`);
  } catch (err) {
    failures += 1;
    console.error(`FAIL syntax ${name}\n  ${err.message}`);
  }
}

const html = fs.readFileSync(path.join(staticDir, "index.html"), "utf8");
for (const required of ["appShell", "sourceInput", "intentSection", "restorationSection", "analysisSection", "responseSection", "settingsDrawer", "/static/scripts/app.js"]) {
  if (html.includes(required)) console.log(`PASS HTML ${required}`);
  else { failures += 1; console.error(`FAIL HTML ${required}`); }
}
console.log(`PASS=${scripts.length + 8 - failures} FAIL=${failures}` + (skipped ? ` SKIPPED=${skipped}` : ""));
process.exitCode = failures ? 1 : 0;