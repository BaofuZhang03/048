import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const js = readFileSync(new URL("../qianduan/admin-reserve-results.js", import.meta.url), "utf8");
const html = readFileSync(new URL("../qianduan/admin-reserve-results.html", import.meta.url), "utf8");

assert.match(js, /failedCount \+ item\.backupCount \+ item\.partialCount/);
assert.match(js, /item\.backupCount \+ item\.partialCount/);
assert.match(html, /admin-reserve-results\.js\?v=20260904-partial-as-backup-1/);

console.log("partial success is counted as backup success");
