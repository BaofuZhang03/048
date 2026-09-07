import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const html = readFileSync(new URL("../qianduan/service.html", import.meta.url), "utf8");
const js = readFileSync(new URL("../qianduan/service.js", import.meta.url), "utf8");
const auditJs = readFileSync(new URL("../qianduan/service-audits.js", import.meta.url), "utf8");
const adminResultJs = readFileSync(new URL("../qianduan/admin-reserve-results.js", import.meta.url), "utf8");

assert.match(html, /service\.js/);
for (const label of [
  "我要续费",
  "修改预约时间",
  "修改座位",
  "没抢到或抢了别的座位",
  "更换账号或密码",
  "暂停或启动",
  "其他问题",
]) assert.match(js, new RegExp(label));
for (const endpoint of ["/api/login", "/api/me", "/api/logout", "/api/me/account", "/api/me/service-schedule", "/api/me/service-policy", "/api/me/service-rooms", "/api/me/sign-control", "/api/me/status", "/api/me/service-report", "/api/me/service-reports"]) assert.match(js, new RegExp(endpoint));
assert.match(js, /待处理/);
assert.match(js, /已完成/);
assert.match(js, /同一类型再次上报时，以最新提交内容为准/);
assert.match(js, /\["refund", "我要退款"/);
assert.match(js, /data-report="退款"/);
assert.match(js, /自动启动时间/);
assert.match(js, /formatPauseUntil/);
assert.match(js, /name="roomId"/);
assert.match(js, /name="roomName"/);
assert.match(js, /name="seatNumber"/);
assert.match(js, /item\[0\] !== "seat" \|\| !state\.roomsLoaded \|\| state\.rooms\.length/);
assert.match(js, /选择目标自习室并填写新的座位号/);
assert.match(js, /data-room-select/);
assert.doesNotMatch(js, /state\.currentSeatNumber/);
assert.match(js, /本页面不显示原座位，请勿误以为座位为空/);
assert.match(js, /item\[0\] !== "sign" \|\| state\.signControl\?\.featureVisible === true/);
assert.match(js, /data-toggle-auto-sign/);
assert.match(js, /placeholder="请输入新的座位号"/);
assert.match(js, /task-strip/);
assert.match(js, /task-row/);
assert.match(js, /学习通账号登录/);
assert.doesNotMatch(js, /login-intro|login-side/);
assert.doesNotMatch(js, /你好，需要办理什么|选择一项即可开始办理/);
assert.match(js, /schoolEndSecond > 40/);
assert.match(js, /保持安全区间/);
assert.match(js, /加快一点（80% 风险）/);
assert.doesNotMatch(js, /riskConfirm|我已了解加速可能导致提醒或七天限制/);
assert.match(js, /学校开放的毫秒级时间可能不稳定/);
assert.match(js, /问题描述（选填）/);
assert.match(js, /name="description"/);
assert.doesNotMatch(js, /type="file"/, "self-service UI must not request file uploads");
assert.match(js, /更换失败：/);
assert.match(js, /账号更换成功，已使用新账号自动登录/);
assert.match(js, /name="password" type="text"/);
assert.doesNotMatch(js, /passwordConfirm|确认新密码|两次输入的密码不一致/);
assert.doesNotMatch(js, /101|真实修改|真实保存|不会修改数据|界面预览阶段/);
assert.match(js, /当前包含分段时间/);
assert.match(js, /当前为单时段格式/);
assert.match(js, /data-add-segment/);
assert.match(js, /data-remove-segment/);
assert.match(js, /统一修改已有日期/);
assert.match(js, /按星期分别修改/);
assert.match(js, /当天未设置预约时间/);
assert.match(js, /不会自动新增/);
assert.match(js, /minute \+= 30/);
assert.doesNotMatch(js, /minute \+= 5/);
assert.match(js, /let hour = 5; hour <= 23/);
assert.doesNotMatch(js, /已读取 .* 的预约安排，请按现有分段逐项选择/);
assert.doesNotMatch(js, /URLSearchParams\(location\.search\).*endSecond/);
assert.match(js, /loadSchoolPolicy/);
assert.match(js, /schoolEndSecond > 40/);
for (const action of ["renew", "schedule", "submit-time"]) assert.match(auditJs, new RegExp(`resultActionUrl\\("${action}"`));
assert.match(adminResultJs, /openRequestedQuickAction/);
assert.match(adminResultJs, /await openRenewalEditor\(button\)/);
assert.match(adminResultJs, /await openScheduleEditor\(button\)/);
assert.match(adminResultJs, /await openSubmitTimeEditor\(button\)/);
assert.match(auditJs, /续费平台/);
assert.match(auditJs, /当前状态/);
assert.match(auditJs, /purchaseChannel/);
assert.match(auditJs, /currentStatus/);
assert.match(auditJs, /data-reply-audit/);
assert.match(auditJs, /data-complete-audit/);
assert.match(auditJs, /回复用户/);
assert.match(auditJs, /结束对话并标记完成/);
assert.match(auditJs, /status === "completed".*\.sort\(\(a, b\) => new Date\(b\.createdAt\) - new Date\(a\.createdAt\)/);
assert.match(js, /data-service-reply/);
assert.match(js, /\/api\/me\/service-report\/reply/);
assert.match(js, /管理员已处理此问题 · 查看对话/);
assert.match(js, /<details class="task-history">/);
assert.match(js, /state\.serviceTasks\.map\(item =>/);
assert.doesNotMatch(js, /new Map\(state\.serviceTasks\.map/);
assert.match(js, /function beginSubmit/);
assert.match(js, /if \(!beginSubmit\(\)\) return/);
assert.match(js, /persistent = error/);
assert.match(js, /addEventListener\("pointerdown"/);
assert.match(js, /toast\(error\.message, true\)/);
assert.match(js, /}, 4000\)/);
assert.match(js, /data-pause-days-open/);
assert.match(js, /event\.submitter\?\.value/);
assert.match(js, /state\.running \? .*一直暂停.*暂停几天/);
assert.match(js, /daysLeft >= 0 && daysLeft < 7/);
assert.match(js, /账号即将到期，请及时续费，系统到期将自动暂停/);
assert.match(js, /class="account-phone">\$\{escapeHtml\(state\.phone\)\}/);
assert.match(js, /现在状态：/);
assert.match(js, /state\.running \? "启动" : "暂停"/);
assert.match(js, /willRun \? "会启动" : "不会启动"/);
assert.match(js, /data\.grabRunStatus/);
assert.match(js, /async function loadGrabRunStatus/);
const css = readFileSync(new URL("../qianduan/service.css", import.meta.url), "utf8");
assert.match(css, /\.home-status/);
assert.match(css, /\.home-status__grab/);
assert.match(css, /@media \(max-width: 760px\)[\s\S]*\.account \.avatar \{ display: none; \}/);
assert.match(css, /@media \(max-width: 760px\)[\s\S]*\.account-phone \{[^}]*color: #fff;[^}]*background: #2f8b6d;[^}]*font-size: 13px/);
assert.match(css, /\.account-phone::before \{ content: "手机号："; \}/);
assert.doesNotMatch(css, /\.account span:not\(\.avatar\) \{ display: none; \}/);

console.log("service UI prototype check passed");
