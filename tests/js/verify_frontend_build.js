/* 前端构建指纹可见性的静态契约。
 *
 * 背景：这套机制长期零前端校验。用户反复遇到"改了不知道生效没有"，
 * 只在 F12 控制台能看到 build 号。这里把三件事钉死：
 *   1. 页面存在展示位（#frontendBuildChip），且确有样式支撑（裸文本会出现 flags 看不见）
 *   2. 入口脚本会渲染它，并在回到页面时比对服务端当前指纹
 *   3. index.html 里的静态引用保持干净（版本号由服务端注入，不写死在文件里 ——
 *      否则每次改动都要人工 bump，迟早漏掉）
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "..", "..");
const staticDir = path.join(root, "src", "shellsentry", "web", "static");

const html = fs.readFileSync(path.join(staticDir, "index.html"), "utf8");
const appJs = fs.readFileSync(path.join(staticDir, "scripts", "app.js"), "utf8");
const css = fs.readFileSync(path.join(staticDir, "styles", "app.css"), "utf8");

let pass = 0;
let fail = 0;

function check(name, ok, detail = "") {
  if (ok) {
    pass += 1;
    console.log(`PASS ${name}`);
  } else {
    fail += 1;
    console.log(`FAIL ${name}${detail ? ` — ${detail}` : ""}`);
  }
}

check("page exposes a build chip", /id="frontendBuildChip"/.test(html));
check("build chip sits in the sidebar footer", /sidebar-footer[\s\S]*frontendBuildChip/.test(html));
check("chip has styling", /\.build-chip\{/.test(css));
check("chip has a stale state", /\.build-chip\.stale\{/.test(css));

check("app.js installs the version watch", /installFrontendVersionWatch\s*\(/.test(appJs));
check("watch runs during init", /function init\(\)[\s\S]{0,600}installFrontendVersionWatch\(\)/.test(appJs));
const grabsMetaName = appJs.includes('name="shellsentry-frontend-build"');
const grabsMetaValue = appJs.includes('content="([^"]+)"');
check(
  "watch parses server build from meta",
  grabsMetaName && grabsMetaValue,
  `应能从服务端返回的 HTML 中提取当前 build（name=${grabsMetaName} value=${grabsMetaValue}）`
);
check("watch does not poll on a timer", !/setInterval\([^)]*check/.test(appJs), "不应使用轮询，只在获得焦点时检查");
check("watch tolerates missing fetch", /typeof fetch !== "function"/.test(appJs), "缺少 fetch 时应静默退出，不得抛错");

// 版本号由服务端注入，静态文件里必须是干净的原始路径
const refs = [...html.matchAll(/["'](\/static\/[^"']+)["']/g)].map((m) => m[1]);
check("page references local assets", refs.length > 0);
check(
  "index.html carries no hard-coded version",
  refs.every((r) => !r.includes("?v=")),
  `不应写死版本号：${refs.filter((r) => r.includes("?v=")).join(", ")}`
);

console.log(`\nfrontend build contract: PASS=${pass} FAIL=${fail}`);
process.exit(fail === 0 ? 0 : 1);
