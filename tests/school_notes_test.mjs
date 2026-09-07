import assert from "node:assert/strict";
import worker, { formatSeatConfigNote, normalizeSchoolNotes, resolveSeatApiFamily } from "../workers/tongyi/src/worker.js";

assert.deepEqual(normalizeSchoolNotes(["  第一条  ", "", 123, "第二条"]), ["第一条", "第二条"]);
assert.equal(normalizeSchoolNotes(["x".repeat(400)])[0].length, 300);
assert.equal(normalizeSchoolNotes(Array.from({ length: 25 }, (_, index) => `提醒${index}`)).length, 20);

const sameHours = Object.fromEntries(
  ["mon", "tues", "wed", "thur", "fri", "sat", "sun"].flatMap(day => [
    [`${day}StartTime`, "07:00"],
    [`${day}EndTime`, "22:30"],
  ]),
);
const seatConfigNote = formatSeatConfigNote({
  reserveBeforeDay: 1,
  reserveBeforeTime: "20:00",
  violateTimes: 3,
  violationLimitDay: 15,
  violationLimitDuration: 7,
  violationType: 1,
  securityVerify: 1,
  securityVerifyType: 3,
  reserveNumLimit: 2,
  reserveDuration: 5.0,
  commonTimeConfig: sameHours,
});
assert.match(seatConfigNote, /预约开放：前一天20:00/);
assert.match(seatConfigNote, /违约规则：3次 \/ 15天统计周期 \/ 限制7天/);
assert.match(seatConfigNote, /安全检测：开启，图标验证码/);
assert.match(seatConfigNote, /可预约时间：周一～周日 07:00～22:30/);
assert.match(seatConfigNote, /单次预约时长上限约 5 小时/);
assert.doesNotMatch(seatConfigNote, /违约限制类型/);

const splitHours = { ...sameHours };
for (const day of ["mon", "tues", "wed", "thur"]) splitHours[`${day}PauseTimes`] = [{ startTime: "12:30", endTime: "13:00" }];
for (const day of ["fri", "sat", "sun"]) {
  splitHours[`${day}StartTime`] = "08:00";
  splitHours[`${day}EndTime`] = "21:00";
  splitHours[`${day}PauseTimes`] = [];
}
const splitNote = formatSeatConfigNote({ securityVerify: 1, securityVerifyType: 4, commonTimeConfig: splitHours });
assert.match(splitNote, /安全检测：开启，滑块验证码 \/ 旋转滑块验证码/);
assert.match(splitNote, /周一～周四 07:00～22:30（12:30～13:00不可预约）/);
assert.match(splitNote, /周五～周日 08:00～21:00/);
assert.match(formatSeatConfigNote({ securityVerify: 1, securityVerifyType: 2 }), /安全检测：开启，选字验证码/);
assert.match(formatSeatConfigNote({ securityVerify: 1, securityVerifyType: 9 }), /安全检测：开启，type=9/);
assert.match(formatSeatConfigNote({ securityVerify: 0, securityVerifyType: 4 }), /安全检测：关闭/);
assert.equal(resolveSeatApiFamily("seat"), "seat");
assert.equal(resolveSeatApiFamily("seat_code"), "seat");
assert.equal(resolveSeatApiFamily("seatengine"), "seatengine");
assert.equal(resolveSeatApiFamily("seatengine_code"), "seatengine");
assert.equal(resolveSeatApiFamily("auto"), "seatengine");

const html = await (await worker.fetch(new Request("http://localhost"), {}, {})).text();
assert.match(html, /注意事项/);
assert.match(html, /function addSchoolNote\(\)/);
assert.match(html, /function toggleSchoolNotesPanel\(\)/);
assert.match(html, /function toggleSchoolNoteEditor\(index\)/);
assert.match(html, /school-note-pill/);
assert.match(html, /school-notes-toggle/);
assert.match(html, />事项<\/button>/);
assert.match(html, /读取座位规则/);
assert.match(html, /\/seat-config\/read/);
assert.match(html, /function saveSchoolNote\(index\)/);
assert.match(html, /function deleteSchoolNote\(index\)/);
assert.match(html, /school-detail-layout/);
assert.match(html, /function renderSchools\(\)[\s\S]*?<div class="container">/);
assert.match(html, /function renderSchoolDetail\(\)[\s\S]*?<div class="container school-detail-container">/);

console.log("school notes check passed");
