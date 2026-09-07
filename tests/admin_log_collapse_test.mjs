import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const html = readFileSync(new URL("../qianduan/admin.html", import.meta.url), "utf8");
const js = readFileSync(new URL("../qianduan/admin.js", import.meta.url), "utf8");
const css = readFileSync(new URL("../qianduan/styles.css", import.meta.url), "utf8");

assert.match(html, /id="logModalContent"[^>]*><\/div>/);
assert.match(html, /styles\.css\?v=20260904-sampling-collapse-6/);
assert.match(html, /admin\.js\?v=20260904-sampling-collapse-6/);
assert.match(js, /function renderLogModalContent\(content\)/);
assert.match(js, /<details class="admin-sampling-log">/);
assert.match(js, /服务器距官方开放/);
assert.match(js, /!entry\.includes\("时间采样汇总"\)/);
assert.match(js, /function formatAdminLogEntry\(entry\)/);
assert.match(js, /plainEntries\.map\(formatAdminLogEntry\)\.join\("\\n"\)/);
assert.doesNotMatch(js, /entries\.map\(entry =>/);
assert.match(css, /\.admin-sampling-log summary/);
assert.match(css, /\.admin-sampling-log:not\(\[open\]\) > pre\s*\{\s*display: none/);
assert.match(css, /\.admin-log-box \{[\s\S]*?overflow-x: hidden/);
assert.match(css, /\.admin-log-plain,[\s\S]*?overflow-wrap: anywhere/);

console.log("admin sampling log collapse check passed");
