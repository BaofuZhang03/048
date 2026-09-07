// ====================================================================
// 多学校抢座管理中枢 — Cloudflare Worker
// ====================================================================
// 功能:
//   1. scheduled()  在预约窗口内轮询学校，并在每次 Cron 触发时立即写入心跳到 KV
//   2. fetch()      REST API + 内嵌 Web 管理面板
//
// KV Schema (binding: SEAT_KV):
//   schools                     → 学校 ID 列表 ["001", "002", "003"]
//   school:{id}                 → 学校配置 { id, name, trigger_time, endtime, repo, github_token_key, dispatch_target, server_url, strategy }
//   school:{id}:users           → 用户 ID 列表
//   school:{id}:user:{userId}   → 单用户完整配置
//
// Secrets: GH_TOKEN, API_KEY
// ====================================================================

const AES_KEY_RAW = "u2oh6Vu^HWe4_AES";
const PLAN_EXTRACT_MAX_HOURS_DEFAULT = 16;
const DEFAULT_INTERNAL_API_URL = "https://renewal-api.baofuzhang.me/api/internal/renewal-profile";
const DEFAULT_SERVER_DISPATCH_PROXY_URL = "https://renewal-api.baofuzhang.me/api/internal/server-dispatch-proxy";

async function getAesKey() {
  const raw = new TextEncoder().encode(AES_KEY_RAW);
  return crypto.subtle.importKey("raw", raw, { name: "AES-CBC" }, false, ["encrypt", "decrypt"]);
}

function pkcs7Pad(data) {
  const bs = 16;
  const pad = bs - (data.length % bs);
  const out = new Uint8Array(data.length + pad);
  out.set(data);
  out.fill(pad, data.length);
  return out;
}

async function aesEncrypt(plaintext) {
  const key = await getAesKey();
  const iv = new TextEncoder().encode(AES_KEY_RAW);
  const padded = pkcs7Pad(new TextEncoder().encode(plaintext));
  const encrypted = await crypto.subtle.encrypt({ name: "AES-CBC", iv }, key, padded);
  return btoa(String.fromCharCode(...new Uint8Array(encrypted)));
}

async function validateChaoxingLogin(username, password) {
  try {
    return { ok: true, jar: await loginChaoxingSession(username, password) };
  } catch (error) {
    return {
      ok: false,
      error: error?.message || "超星登录校验失败",
    };
  }
}

function pkcs7Unpad(data) {
  if (!data.length) return data;
  const pad = data[data.length - 1];
  if (pad < 1 || pad > 16 || pad > data.length) return data;
  for (let i = data.length - pad; i < data.length; i += 1) {
    if (data[i] !== pad) return data;
  }
  return data.slice(0, data.length - pad);
}

function base64ToBytes(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

async function aesDecrypt(ciphertext) {
  const text = String(ciphertext || "").trim();
  if (!text || text === "******") return "";
  try {
    const key = await getAesKey();
    const iv = new TextEncoder().encode(AES_KEY_RAW);
    const decrypted = await crypto.subtle.decrypt({ name: "AES-CBC", iv }, key, base64ToBytes(text));
    return new TextDecoder().decode(pkcs7Unpad(new Uint8Array(decrypted)));
  } catch (_error) {
    return text;
  }
}

function collectSetCookies(headers) {
  if (!headers) return [];
  if (typeof headers.getSetCookie === "function") {
    return headers.getSetCookie();
  }
  const combined = headers.get("set-cookie") || "";
  if (!combined) return [];
  return combined.split(/,(?=\s*[^;,]+=)/g).map(item => item.trim()).filter(Boolean);
}

function updateCookieJar(jar, headers) {
  for (const item of collectSetCookies(headers)) {
    const pair = String(item || "").split(";", 1)[0] || "";
    const eqIndex = pair.indexOf("=");
    if (eqIndex <= 0) continue;
    const name = pair.slice(0, eqIndex).trim();
    const value = pair.slice(eqIndex + 1).trim();
    if (name) jar.set(name, value);
  }
}

function cookieHeaderFromJar(jar) {
  return Array.from(jar.entries()).map(([name, value]) => `${name}=${value}`).join("; ");
}

async function fetchWithTimeout(url, options = {}, timeoutMs = 15000) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort("timeout"), timeoutMs);
  try {
    return await fetch(url, {
      ...options,
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timeout);
  }
}

async function loginChaoxingSession(account, password) {
  const username = String(account || "").trim();
  const rawPassword = String(password || "");
  if (!username || !rawPassword) {
    throw new Error("本组没有可用于登录的账号或密码");
  }

  const jar = new Map();
  const headers = {
    "Accept": "application/json, text/javascript, */*; q=0.01",
    "Accept-Language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
    "Cache-Control": "no-cache",
    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
    "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 10_3_1 like Mac OS X) AppleWebKit/603.1.3 (KHTML, like Gecko) Version/10.0 Mobile/14E304 Safari/602.1 wechatdevtools/1.05.2109131 MicroMessenger/8.0.5 Language/zh_CN webview/16364215743155638",
    "X-Requested-With": "XMLHttpRequest",
  };

  try {
    const bootstrap = await fetchWithTimeout(
      "https://passport2.chaoxing.com/mlogin?loginType=1&newversion=true&fid=",
      { method: "GET", headers },
      10000,
    ).catch(() => null);
    if (bootstrap) updateCookieJar(jar, bootstrap.headers);

    const params = new URLSearchParams({
      fid: "-1",
      uname: await aesEncrypt(username),
      password: await aesEncrypt(rawPassword),
      refer: "http%3A%2F%2Foffice.chaoxing.com%2Ffront%2Fthird%2Fapps%2Fseat%2Fcode%3Fid%3D4219%26seatNum%3D380",
      t: "true",
    });
    const loginHeaders = { ...headers };
    const cookie = cookieHeaderFromJar(jar);
    if (cookie) loginHeaders.Cookie = cookie;
    const response = await fetchWithTimeout(
      "https://passport2.chaoxing.com/fanyalogin",
      { method: "POST", headers: loginHeaders, body: params.toString() },
      12000,
    );
    updateCookieJar(jar, response.headers);
    const text = await response.text();
    let data = null;
    try {
      data = text ? JSON.parse(text) : null;
    } catch (_error) {
      throw new Error("超星登录返回非 JSON");
    }
    if (!data?.status) {
      throw new Error(data?.msg2 || data?.msg || "超星登录失败");
    }
  } catch (error) {
    if (error?.name === "AbortError") throw new Error("超星登录超时");
    throw error;
  }

  return jar;
}

function buildRoomName(item) {
  const parts = [
    String(item?.firstLevelName || "").trim(),
    String(item?.secondLevelName || "").trim(),
    String(item?.thirdLevelName || "").trim(),
  ].filter(Boolean);
  return parts.length ? parts.join("-") : String(item?.name || "未命名房间").trim();
}

function buildReadingZoneGroupsFromRooms(roomList) {
  const floorPattern = /\d+\s*[楼层]/;

  const pickFloorAndZone = (item) => {
    const first = String(item?.firstLevelName || "").trim();
    const second = String(item?.secondLevelName || "").trim();
    const third = String(item?.thirdLevelName || "").trim();

    for (const candidate of [first, second, third]) {
      if (candidate && floorPattern.test(candidate)) {
        const rest = [first, second, third].filter(part => part && part !== candidate);
        return {
          floor: candidate,
          zoneName: rest.length ? rest.join("-") : String(item?.name || candidate).trim(),
        };
      }
    }

    const floor = first || "未分层";
    const zoneName = [second, third].filter(Boolean).join("-") || buildRoomName(item);
    return { floor, zoneName };
  };

  const groups = new Map();
  for (const item of roomList || []) {
    const id = String(item?.id || "").trim();
    if (!id) continue;
    const { floor, zoneName } = pickFloorAndZone(item);
    if (!groups.has(floor)) groups.set(floor, []);
    groups.get(floor).push({ id, name: zoneName || id });
  }

  const floorSortKey = (floor) => {
    const digits = String(floor || "").replace(/\D/g, "");
    return digits ? [0, parseInt(digits, 10), String(floor)] : [1, 9999, String(floor)];
  };
  return Array.from(groups.entries())
    .sort(([a], [b]) => {
      const ka = floorSortKey(a);
      const kb = floorSortKey(b);
      return ka[0] - kb[0] || ka[1] - kb[1] || ka[2].localeCompare(kb[2], "zh-Hans-CN");
    })
    .map(([floor, zones]) => ({ floor, zones }));
}

function normalizeSearchText(value) {
  return String(value || "").trim().toLowerCase();
}

function userMatchesQuery(user, query) {
  const needle = normalizeSearchText(query);
  if (!needle) return false;
  const values = [
    user?.phone,
    user?.username,
    user?.remark,
    user?.nickname,
    user?.id,
  ];
  return values.some(value => normalizeSearchText(value).includes(needle));
}

function userSearchSummary(user) {
  return {
    id: String(user?.id || ""),
    phone: String(user?.phone || ""),
    username: String(user?.username || ""),
    remark: String(user?.remark || ""),
    status: String(user?.status || ""),
  };
}

function findFirstUserSeatHint(user) {
  const schedule = user?.schedule || {};
  for (const day of Object.keys(schedule)) {
    const daySchedule = schedule[day];
    const slots = Array.isArray(daySchedule?.slots)
      ? daySchedule.slots
      : [daySchedule].filter(Boolean);
    for (const slot of slots) {
      const fidEnc = String(slot?.fidEnc || "").trim();
      const roomid = String(slot?.roomid || "").trim();
      const seatPageId = String(slot?.seatPageId || slot?.roomid || "").trim();
      if (fidEnc || roomid || seatPageId) return { fidEnc, roomid, seatPageId };
    }
  }
  return { fidEnc: "", roomid: "", seatPageId: "" };
}

function findFirstCompleteUserSeatHint(user) {
  const schedule = user?.schedule || {};
  for (const daySchedule of Object.values(schedule)) {
    const slots = Array.isArray(daySchedule?.slots)
      ? daySchedule.slots
      : [daySchedule].filter(Boolean);
    for (const slot of slots) {
      const roomid = String(slot?.roomid || "").trim();
      const seatid = Array.isArray(slot?.seatid)
        ? slot.seatid.map(value => String(value).trim()).filter(Boolean).join(",")
        : String(slot?.seatid || "").trim();
      if (!roomid || !seatid) continue;
      return {
        roomid,
        seatid,
        seatPageId: String(slot?.seatPageId || roomid).trim(),
        fidEnc: String(slot?.fidEnc || "").trim(),
      };
    }
  }
  return { fidEnc: "", roomid: "", seatid: "", seatPageId: "" };
}

function extractPageToken(html) {
  const source = String(html || "");
  const input = source.match(/<input\b[^>]*(?:id|name)\s*=\s*["'](?:page_?token|token|submit_enc)["'][^>]*>/i)?.[0] || "";
  return input.match(/\bvalue\s*=\s*["']([^"']+)["']/i)?.[1]
    || source.match(/["'](?:page_?token|token)["']\s*[:=]\s*["']([^"']+)["']/i)?.[1]
    || "";
}

function resolveSeatApiFamily(mode) {
  const value = String(mode || "seat").toLowerCase();
  return value === "auto" || value.startsWith("seatengine") ? "seatengine" : "seat";
}

function buildChaoxingSeatPageUrl(school, user, family) {
  const hint = findFirstCompleteUserSeatHint(user);
  const fidEnc = String(hint.fidEnc || school?.fidEnc || "").trim();
  if (!hint.roomid || !hint.seatid || !hint.seatPageId || !fidEnc) {
    throw new Error("没有找到同时包含 roomid 和 seatid 的完整时段，或缺少 seatPageId/fidEnc");
  }
  const url = new URL(`https://office.chaoxing.com/front/third/apps/${family}/select`);
  url.search = new URLSearchParams({
    id: hint.roomid,
    day: beijingDate(),
    backLevel: "2",
    seatId: hint.seatPageId,
    fidEnc,
  }).toString();
  return url.toString();
}

async function validateChaoxingSeatPage(jar, user, school, maxAttempts = 3) {
  const family = resolveSeatApiFamily(school?.seat_api_mode);
  let lastError = "真实选座页没有返回页面 token";

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      const url = buildChaoxingSeatPageUrl(school, user, family);
      const response = await fetchWithTimeout(url, {
        method: "GET",
        headers: {
          "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
          "Cookie": cookieHeaderFromJar(jar),
          "Referer": "https://office.chaoxing.com/",
          "User-Agent": "Mozilla/5.0",
        },
      }, 10000);
      updateCookieJar(jar, response.headers);
      const token = extractPageToken(await response.text());
      if (response.ok && token) return { ok: true, attempts: attempt };
      lastError = response.ok
        ? "真实选座页没有返回页面 token"
        : `真实选座页返回 HTTP ${response.status}`;
    } catch (error) {
      lastError = error?.name === "AbortError"
        ? "真实选座页请求超时"
        : (error?.message || String(error));
    }
  }
  return { ok: false, attempts: maxAttempts, error: lastError };
}

function didLoginAccountChange(previousAccount, nextAccount) {
  return normalizeSecretText(previousAccount) !== normalizeSecretText(nextAccount);
}

function chooseUserForReadingZoneMapping(users) {
  for (const user of users || []) {
    const account = String(user?.phone || user?.username || "").trim();
    const password = String(user?.password || "").trim();
    if (account && password) return user;
  }
  return null;
}

const SEAT_CONFIG_DAY_FIELDS = [
  ["mon", "周一"], ["tues", "周二"], ["wed", "周三"], ["thur", "周四"],
  ["fri", "周五"], ["sat", "周六"], ["sun", "周日"],
];

function normalizeSeatPauseTimes(value) {
  if (value === undefined || value === null) return null;
  if (typeof value === "string") {
    const text = value.trim();
    if (!text) return [];
    try {
      return normalizeSeatPauseTimes(JSON.parse(text));
    } catch (_) {
      return text.split(/[,，;；]/).map(item => item.trim().replace(/\s*[-~至]\s*/g, "～")).filter(Boolean);
    }
  }
  if (!Array.isArray(value)) value = [value];
  return value.map(item => {
    if (typeof item === "string") return item.trim().replace(/\s*[-~至]\s*/g, "～");
    const start = item?.startTime ?? item?.beginTime ?? item?.start;
    const end = item?.endTime ?? item?.finishTime ?? item?.end;
    return start != null && end != null ? `${start}～${end}` : JSON.stringify(item);
  }).filter(Boolean);
}

function formatSeatConfigNote(seatConfig) {
  const config = seatConfig && typeof seatConfig === "object" ? seatConfig : {};
  const common = config.commonTimeConfig && typeof config.commonTimeConfig === "object"
    ? config.commonTimeConfig
    : {};
  const dayRules = [];
  for (const [field, label] of SEAT_CONFIG_DAY_FIELDS) {
    const start = String(common[`${field}StartTime`] || "").trim();
    const end = String(common[`${field}EndTime`] || "").trim();
    const pauses = normalizeSeatPauseTimes(common[`${field}PauseTimes`]);
    const signature = JSON.stringify([start, end, pauses]);
    const previous = dayRules.at(-1);
    if (previous?.signature === signature) previous.days.push(label);
    else dayRules.push({ days: [label], start, end, pauses, signature });
  }
  const timeText = dayRules.map(({ days, start, end, pauses }) => {
    const dayText = days.length > 1 ? `${days[0]}～${days.at(-1)}` : days[0];
    const hours = start && end ? `${start}～${end}` : "未返回";
    const pauseText = pauses === null
      ? "（暂停时段未返回）"
      : (pauses.length ? `（${pauses.join("、")}不可预约）` : "");
    return `${dayText} ${hours}${pauseText}`;
  }).join("；");
  const present = value => value !== undefined && value !== null && value !== "";
  const beforeDay = config.reserveBeforeDay;
  const beforeTime = config.reserveBeforeTime;
  const openText = present(beforeDay) && present(beforeTime)
    ? `${Number(beforeDay) === 1 ? "前一天" : (Number(beforeDay) === 0 ? "当天" : `提前${beforeDay}天`)}${beforeTime}`
    : "未返回";
  const violationText = [
    present(config.violateTimes) ? `${config.violateTimes}次` : "未返回",
    present(config.violationLimitDay) ? `${config.violationLimitDay}天统计周期` : "未返回",
    present(config.violationLimitDuration) ? `限制${config.violationLimitDuration}天` : "未返回",
  ].join(" / ");
  const reserveDuration = Number(config.reserveDuration);
  const durationText = Number.isFinite(reserveDuration) && reserveDuration > 0
    ? `${reserveDuration} 小时`
    : "未返回";
  let securityText = "未返回";
  if (Number(config.securityVerify) === 0) securityText = "关闭";
  if (Number(config.securityVerify) === 1) {
    const verifyTypeLabels = {
      2: "选字验证码",
      3: "图标验证码",
      4: "滑块验证码 / 旋转滑块验证码",
    };
    securityText = `开启，${verifyTypeLabels[Number(config.securityVerifyType)]
      || (present(config.securityVerifyType) ? `type=${config.securityVerifyType}` : "未返回")}`;
  }
  return [
    "==========【预约规则】==========",
    `预约开放：${openText}`,
    `违约规则：${violationText}`,
    `安全检测：${securityText}`,
    `可预约时间：${timeText || "未返回"}`,
    `单次预约时长上限约 ${durationText}`,
    `预约数量限制：${present(config.reserveNumLimit) ? config.reserveNumLimit : "未返回"}`,
    "==============================",
  ].join("\n");
}

async function fetchAndSaveSeatConfig(KV, school) {
  const users = await getSchoolUsersSnapshot(KV, school.id);
  const candidates = users.filter(user => {
    const hint = findFirstUserSeatHint(user);
    return (user?.phone || user?.username) && user?.password && hint.roomid && (school?.fidEnc || hint.fidEnc);
  });
  if (!candidates.length) throw new Error("本组没有同时配置账号、密码、roomid 和 fidEnc 的用户");
  const user = candidates[Math.floor(Math.random() * candidates.length)];
  const account = String(user.phone || user.username).trim();
  const hint = findFirstUserSeatHint(user);
  const fidEnc = String(school.fidEnc || hint.fidEnc).trim();
  const jar = await loginChaoxingSession(account, await aesDecrypt(user.password));
  const family = resolveSeatApiFamily(school.seat_api_mode);
  const response = await fetchWithTimeout(`https://office.chaoxing.com/data/apps/${family}/room/info`, {
    method: "POST",
    headers: {
      "Accept": "application/json, text/plain, */*",
      "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
      "Cookie": cookieHeaderFromJar(jar),
      "Referer": "https://office.chaoxing.com/",
      "User-Agent": "Mozilla/5.0",
    },
    body: new URLSearchParams({
      id: hint.roomid,
      toDay: beijingDateWithOffset(resolveScheduleReserveDayOffset(school)),
      fidEnc,
    }).toString(),
  }, 12000);
  const payload = await response.json().catch(() => null);
  const seatConfig = payload?.data?.seatConfig;
  if (!response.ok || !seatConfig) {
    throw new Error(payload?.msg || `room/info 请求失败（HTTP ${response.status}）`);
  }
  const note = formatSeatConfigNote(seatConfig);
  const prefix = "==========【预约规则】==========";
  const notes = normalizeSchoolNotes(school.notes);
  const existingIndex = notes.findIndex(item => item.startsWith(prefix));
  if (existingIndex >= 0) notes[existingIndex] = note;
  else if (notes.length >= 20) throw new Error("学校事项已满，请先删除一条事项");
  else notes.unshift(note);
  school.notes = normalizeSchoolNotes(notes);
  await saveSchool(KV, school);
  return { school, note };
}

async function fetchChaoxingRoomListForMapping(user, school) {
  const account = String(user?.phone || user?.username || "").trim();
  const password = await aesDecrypt(user?.password || "");
  const hint = findFirstUserSeatHint(user);
  const fidEnc = String(school?.fidEnc || hint.fidEnc || "").trim();
  if (!fidEnc) {
    throw new Error("缺少 fidEnc：请先在学校统一 fidEnc 或任一用户时段 fidEnc 中配置");
  }

  const jar = await loginChaoxingSession(account, password);
  const requestHeaders = {
    "Accept": "application/json, text/plain, */*",
    "Referer": "https://office.chaoxing.com/",
    "User-Agent": "Mozilla/5.0",
    "Cookie": cookieHeaderFromJar(jar),
  };
  const day = beijingDate();
  const pageSize = 200;
  const seatId = String(hint.seatPageId || "").trim();
  const urls = [
    "https://office.chaoxing.com/data/apps/seatengine/room/list"
      + `?time=&cpage=1&pageSize=${pageSize}&firstLevelName=&secondLevelName=&thirdLevelName=`
      + `&day=${encodeURIComponent(day)}&deptIdEnc=${encodeURIComponent(fidEnc)}`
      + (seatId ? `&seatId=${encodeURIComponent(seatId)}` : ""),
    "https://office.chaoxing.com/data/apps/seat/room/list"
      + `?cpage=1&pageSize=${pageSize}&firstLevelName=&secondLevelName=&thirdLevelName=&deptIdEnc=${encodeURIComponent(fidEnc)}`,
  ];

  let lastError = "";
  for (const url of urls) {
    try {
      const response = await fetchWithTimeout(url, { method: "GET", headers: requestHeaders }, 20000);
      updateCookieJar(jar, response.headers);
      const text = await response.text();
      let data = null;
      try {
        data = text ? JSON.parse(text) : null;
      } catch (_error) {
        lastError = `room/list 返回非 JSON：HTTP ${response.status}`;
        continue;
      }
      if (!data?.success) {
        lastError = data?.msg || "room/list 调用失败";
        continue;
      }
      const roomList = data?.data?.seatRoomList || [];
      if (Array.isArray(roomList) && roomList.length) {
        return { roomList, fidEnc, account };
      }
      lastError = "room/list 返回空房间列表";
    } catch (error) {
      lastError = error?.name === "AbortError" ? "room/list 请求超时" : (error?.message || String(error));
    }
  }

  throw new Error(lastError || "未能提取阅览区");
}

async function sanitizeUserForAdmin(user, options = {}) {
  const includePlainPassword = options.includePlainPassword === true;
  const school = options.school || null;
  const passwordCipher = String(user?.password || "");
  const safeUser = {
    ...user,
    schedule: scheduleForDisplay(school, user?.schedule || {}),
    password: passwordCipher ? "******" : "",
    hasPassword: !!passwordCipher,
  };
  if (includePlainPassword) {
    safeUser.passwordPlain = passwordCipher ? await aesDecrypt(passwordCipher) : "";
  }
  return safeUser;
}

// ─── 辅助函数 ───

function beijingNow() {
  return new Date(Date.now() + 8 * 3600 * 1000);
}

function beijingHHMM() {
  const d = beijingNow();
  return `${String(d.getUTCHours()).padStart(2, "0")}:${String(d.getUTCMinutes()).padStart(2, "0")}`;
}

function beijingSecondsOfDay() {
  const d = beijingNow();
  return d.getUTCHours() * 3600 + d.getUTCMinutes() * 60 + d.getUTCSeconds();
}

function beijingDate() {
  const d = beijingNow();
  const y = d.getUTCFullYear();
  const m = String(d.getUTCMonth() + 1).padStart(2, "0");
  const day = String(d.getUTCDate()).padStart(2, "0");
  return `${y}-${m}-${day}`;
}

function beijingDayOfWeek() {
  const days = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
  return days[beijingNow().getUTCDay()];
}

function beijingDateFromTimestamp(timestampMs = Date.now()) {
  const d = new Date(timestampMs + 8 * 3600 * 1000);
  const y = d.getUTCFullYear();
  const m = String(d.getUTCMonth() + 1).padStart(2, "0");
  const day = String(d.getUTCDate()).padStart(2, "0");
  return `${y}-${m}-${day}`;
}

function beijingDateWithOffset(offsetDays = 0, timestampMs = Date.now()) {
  return beijingDateFromTimestamp(timestampMs + offsetDays * 24 * 60 * 60 * 1000);
}

function beijingDayOfWeekFromTimestamp(timestampMs = Date.now()) {
  const days = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
  return days[new Date(timestampMs + 8 * 3600 * 1000).getUTCDay()];
}

function beijingDateHour() {
  const d = beijingNow();
  const y = d.getUTCFullYear();
  const m = String(d.getUTCMonth() + 1).padStart(2, "0");
  const day = String(d.getUTCDate()).padStart(2, "0");
  const hour = String(d.getUTCHours()).padStart(2, "0");
  return `${y}-${m}-${day}-${hour}`;
}

function beijingDateMinute(timestampMs = Date.now()) {
  const d = new Date(timestampMs + 8 * 3600 * 1000);
  const y = d.getUTCFullYear();
  const m = String(d.getUTCMonth() + 1).padStart(2, "0");
  const day = String(d.getUTCDate()).padStart(2, "0");
  const hour = String(d.getUTCHours()).padStart(2, "0");
  const minute = String(d.getUTCMinutes()).padStart(2, "0");
  return `${y}-${m}-${day}-${hour}:${minute}`;
}

function beijingIsoFromTimestamp(timestampMs) {
  const d = new Date(timestampMs + 8 * 3600 * 1000);
  const y = d.getUTCFullYear();
  const m = String(d.getUTCMonth() + 1).padStart(2, "0");
  const day = String(d.getUTCDate()).padStart(2, "0");
  const hour = String(d.getUTCHours()).padStart(2, "0");
  const minute = String(d.getUTCMinutes()).padStart(2, "0");
  const second = String(d.getUTCSeconds()).padStart(2, "0");
  return `${y}-${m}-${day}T${hour}:${minute}:${second}+08:00`;
}

function nextBeijingTimeOccurrence(timeText, nowMs = Date.now(), includeSeconds = false) {
  const seconds = includeSeconds ? parseEndtimeSeconds(timeText) : parseTriggerTimeSeconds(timeText);
  if (seconds === null) return null;
  const beijing = new Date(nowMs + 8 * 3600 * 1000);
  const midnightUtcMs = Date.UTC(
    beijing.getUTCFullYear(),
    beijing.getUTCMonth(),
    beijing.getUTCDate(),
  ) - 8 * 3600 * 1000;
  let occurrenceMs = midnightUtcMs + seconds * 1000;
  if (occurrenceMs <= nowMs) occurrenceMs += 24 * 60 * 60 * 1000;
  return occurrenceMs;
}

function emergencyTimingForSchool(school, nowMs = Date.now()) {
  const triggerTime = resolveEffectiveTriggerTime(school, { allowTestEndtimeOverride: false });
  const endtime = resolveEffectiveEndtime(school, { allowTestEndtimeOverride: false });
  const triggerAtMs = nextBeijingTimeOccurrence(triggerTime, nowMs, false);
  const triggerSeconds = parseTriggerTimeSeconds(triggerTime);
  const endSeconds = parseEndtimeSeconds(endtime);
  if (triggerAtMs === null || triggerSeconds === null || endSeconds === null) return null;

  let targetAtMs = triggerAtMs + (endSeconds - triggerSeconds) * 1000;
  if (endSeconds < triggerSeconds) targetAtMs += 24 * 60 * 60 * 1000;
  return {
    triggerAtMs,
    stageOffsetMinutes: emergencyStageOffsetMinutes(school?.id),
    stageAtMs: triggerAtMs - EMERGENCY_SNAPSHOT_LEAD_MS
      + emergencyStageOffsetMinutes(school?.id) * 60 * 1000,
    targetAtMs,
    fallbackAtMs: targetAtMs - EMERGENCY_FALLBACK_LEAD_SECONDS * 1000,
    executionDate: beijingDateFromTimestamp(targetAtMs),
    executionDay: beijingDayOfWeekFromTimestamp(targetAtMs),
    triggerAt: beijingIsoFromTimestamp(triggerAtMs),
    targetAt: beijingIsoFromTimestamp(targetAtMs),
    fallbackAt: beijingIsoFromTimestamp(targetAtMs - EMERGENCY_FALLBACK_LEAD_SECONDS * 1000),
  };
}

function emergencyStageOffsetMinutes(schoolId) {
  const text = String(schoolId || "");
  let hash = 0;
  for (let index = 0; index < text.length; index++) {
    hash = ((hash * 31) + text.charCodeAt(index)) >>> 0;
  }
  return (hash % 11) - 5;
}

function generateId() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
}

function jsonResp(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Cache-Control": "no-store, no-cache, must-revalidate",
      ...extraHeaders,
    },
  });
}

function normalizeSecretText(value) {
  return typeof value === "string" ? value.trim() : "";
}

function normalizeSchoolNotes(value) {
  if (!Array.isArray(value)) return [];
  return value
    .map(note => normalizeSecretText(note).slice(0, 300))
    .filter(Boolean)
    .slice(0, 20);
}

function normalizeTimeSeparatorText(value) {
  return String(value || "").trim().replace(/[：.]/g, ":");
}

function normalizePlanExtractMaxHours(value, fallback = PLAN_EXTRACT_MAX_HOURS_DEFAULT) {
  const text = String(value ?? "").trim();
  if (!text) return fallback;
  const num = Number(text);
  return Number.isFinite(num) && num >= 0 ? num : fallback;
}

function normalizeEndtimeHms(value) {
  const text = normalizeTimeSeparatorText(value);
  const match = text.match(/^(\d{1,2}):(\d{2})(?::(\d{2}))?$/);
  if (!match) return "";

  const hour = parseInt(match[1], 10);
  const minute = parseInt(match[2], 10);
  const second = parseInt(match[3] || "0", 10);
  if (hour < 0 || hour > 23 || minute < 0 || minute > 59 || second < 0 || second > 59) {
    return "";
  }

  return [
    String(hour).padStart(2, "0"),
    String(minute).padStart(2, "0"),
    String(second).padStart(2, "0"),
  ].join(":");
}

function normalizeOptionalUserRange(value, fieldLabel) {
  if (value === undefined || value === null || String(value).trim() === "") {
    return { value: undefined };
  }
  const raw = Array.isArray(value) ? value : String(value).split(",");
  if (raw.length !== 2) {
    return { error: `${fieldLabel} 应填写两个用逗号分隔的整数` };
  }
  const range = raw.map(item => Number(String(item).trim()));
  if (range.some(item => !Number.isInteger(item))) {
    return { error: `${fieldLabel} 应填写两个用逗号分隔的整数` };
  }
  return { value: range };
}

function normalizeUserTopConfig(input) {
  const source = input && typeof input === "object" ? input : {};
  const config = {};
  const rangeFields = [
    ["pre_fetch_token_range_ms", "pre_fetch_token_range_ms"],
    ["first_submit_offset_range_ms", "first_submit_offset_range_ms"],
    ["fast_probe_start_range_ms", "fast_probe_start_range_ms"],
    ["slider_lead_seconds_range", "slider_lead_seconds_range"],
  ];
  for (const [field, label] of rangeFields) {
    const normalized = normalizeOptionalUserRange(source[field], label);
    if (normalized.error) return normalized;
    if (normalized.value !== undefined) {
      config[field] = field === "slider_lead_seconds_range"
        ? normalized.value.map(normalizeSliderLeadRangeValueMs)
        : normalized.value;
    }
  }

  const endtimeText = String(source.endtime ?? "").trim();
  if (endtimeText) {
    const endtime = normalizeEndtimeHms(endtimeText);
    if (!endtime) return { error: "用户级正式截止时间格式应为 HH:MM:SS" };
    config.endtime = endtime;
  }

  const firstTokenDateMode = String(source.first_token_date_mode ?? "").trim();
  if (firstTokenDateMode) {
    if (!["today", "submit_date"].includes(firstTokenDateMode)) {
      return { error: "first_token_date_mode 只能为 today 或 submit_date" };
    }
    config.first_token_date_mode = firstTokenDateMode;
  }

  const mode = String(source.mode ?? "").trim().toUpperCase();
  if (mode) {
    if (!["A", "B", "C"].includes(mode)) {
      return { error: "mode 只能为 A、B 或 C" };
    }
    config.mode = mode;
  }
  return { value: config };
}

function validateUserTopConfigForSchool(config, school) {
  if (!config?.endtime) return "";
  const error = validateFormalTimeWindow(school?.trigger_time, config.endtime);
  return error ? `用户级${error}` : "";
}

function resolveUserTopModeForSchool(school, userEndtime = "", userMode = "") {
  const explicitMode = String(userMode || "").trim().toUpperCase();
  if (["A", "B", "C"].includes(explicitMode)) return explicitMode;

  const schoolMode = String(school?.strategy?.mode || "").trim().toUpperCase();
  return ["A", "B", "C"].includes(schoolMode) ? schoolMode : "C";
}

const FORMAL_TIME_WINDOW_LIMIT_SECONDS = 30 * 60;
const SECONDS_PER_DAY = 24 * 60 * 60;

function parseTriggerTimeSeconds(value) {
  const text = normalizeTimeSeparatorText(value);
  const match = text.match(/^(\d{1,2}):(\d{2})$/);
  if (!match) return null;

  const hour = parseInt(match[1], 10);
  const minute = parseInt(match[2], 10);
  if (hour < 0 || hour > 23 || minute < 0 || minute > 59) return null;
  return hour * 3600 + minute * 60;
}

function parseEndtimeSeconds(value) {
  const normalized = normalizeEndtimeHms(value);
  if (!normalized) return null;

  const [hour, minute, second] = normalized.split(":").map(v => parseInt(v, 10));
  return hour * 3600 + minute * 60 + second;
}

function getFormalTimeWindowDurationSeconds(startSeconds, endSeconds) {
  if (startSeconds === null || endSeconds === null) return null;
  if (endSeconds === startSeconds) return 0;
  return endSeconds > startSeconds
    ? endSeconds - startSeconds
    : endSeconds + SECONDS_PER_DAY - startSeconds;
}

function isFormalTimeWindowCrossMidnight(triggerTime, endtime) {
  const startSeconds = parseTriggerTimeSeconds(triggerTime);
  const endSeconds = parseEndtimeSeconds(endtime);
  return startSeconds !== null && endSeconds !== null && endSeconds < startSeconds;
}

function validateFormalTimeWindow(triggerTime, endtime) {
  const startSeconds = parseTriggerTimeSeconds(triggerTime);
  if (startSeconds === null) return "正式开始时间格式应为 HH:MM";

  const endSeconds = parseEndtimeSeconds(endtime);
  if (endSeconds === null) return "正式截止时间格式应为 HH:MM:SS";

  const durationSeconds = getFormalTimeWindowDurationSeconds(startSeconds, endSeconds);
  if (durationSeconds <= 0) return "正式截止时间必须晚于正式开始时间";
  if (durationSeconds > FORMAL_TIME_WINDOW_LIMIT_SECONDS) {
    return "正式开始时间和截止时间间隔不能超过 30 分钟";
  }
  return "";
}

function normalizeTriggerTimeHm(value) {
  const seconds = parseTriggerTimeSeconds(value);
  if (seconds === null) return "";
  const hour = Math.floor(seconds / 3600);
  const minute = Math.floor((seconds % 3600) / 60);
  return `${String(hour).padStart(2, "0")}:${String(minute).padStart(2, "0")}`;
}

function isSameTimeWindow(triggerTimeA, endtimeA, triggerTimeB, endtimeB) {
  return normalizeTriggerTimeHm(triggerTimeA) === normalizeTriggerTimeHm(triggerTimeB)
    && normalizeEndtimeHms(endtimeA) === normalizeEndtimeHms(endtimeB);
}

function validateTestTimeWindowAgainstFormal(school, testTriggerTime, testEndtime) {
  if (!testTriggerTime || !testEndtime) return "";
  if (isSameTimeWindow(testTriggerTime, testEndtime, school?.trigger_time, school?.endtime)) {
    return "测试时间不能和正式时间完全一致";
  }
  return "";
}

function applySchoolFormalTimeGuard(school, source = {}) {
  if (!school || !source || typeof source !== "object") return;
  const guardedTriggerTime = normalizeTriggerTimeHm(source.formal_trigger_time || source.current_trigger_time);
  const guardedEndtime = normalizeEndtimeHms(source.formal_endtime || source.current_endtime);
  if (guardedTriggerTime) school.trigger_time = guardedTriggerTime;
  if (guardedEndtime) school.endtime = guardedEndtime;
}

function isTimeWindowActive(triggerTime, endtime, nowSeconds = beijingSecondsOfDay()) {
  const triggerSeconds = parseTriggerTimeSeconds(triggerTime);
  if (triggerSeconds === null) return false;

  const endSeconds = parseEndtimeSeconds(endtime);
  if (endSeconds === null) return true;

  if (endSeconds < triggerSeconds) {
    return nowSeconds >= triggerSeconds || nowSeconds <= endSeconds;
  }
  return nowSeconds >= triggerSeconds && nowSeconds <= endSeconds;
}

function isFormalScheduleWindowActive(school, nowSeconds = beijingSecondsOfDay()) {
  return isTimeWindowActive(school?.trigger_time, school?.endtime, nowSeconds);
}

function shouldScheduledTriggerSchool(school, nowSeconds = beijingSecondsOfDay()) {
  return isTimeWindowActive(
    resolveEffectiveTriggerTime(school),
    resolveEffectiveEndtime(school),
    nowSeconds,
  );
}

function getActiveScheduleContextForSchool(school, nowSeconds = beijingSecondsOfDay(), timestampMs = Date.now()) {
  const effectiveTriggerTime = resolveEffectiveTriggerTime(school);
  const effectiveEndtime = resolveEffectiveEndtime(school);
  if (isFormalTimeWindowCrossMidnight(effectiveTriggerTime, effectiveEndtime)) {
    const triggerSeconds = parseTriggerTimeSeconds(effectiveTriggerTime);
    if (triggerSeconds !== null && nowSeconds >= triggerSeconds) {
      const nextTimestampMs = timestampMs + 24 * 60 * 60 * 1000;
      return {
        day: beijingDayOfWeekFromTimestamp(nextTimestampMs),
        date: beijingDateFromTimestamp(nextTimestampMs),
      };
    }
  }
  return {
    day: beijingDayOfWeekFromTimestamp(timestampMs),
    date: beijingDateFromTimestamp(timestampMs),
  };
}

function parseTriggerTimeMinutes(value) {
  const text = String(value || "").trim();
  const parts = text.match(/\d{1,2}/g);
  if (!parts || parts.length < 2) return Number.MAX_SAFE_INTEGER;
  const hour = parseInt(parts[0], 10);
  const minute = parseInt(parts[1], 10);
  if (Number.isNaN(hour) || Number.isNaN(minute)) return Number.MAX_SAFE_INTEGER;
  if (hour < 0 || hour > 23 || minute < 0 || minute > 59) return Number.MAX_SAFE_INTEGER;
  return hour * 60 + minute;
}

function getSortedSchoolsForDisplay(items) {
  return (Array.isArray(items) ? items : [])
    .filter(Boolean)
    .slice()
    .sort((a, b) => {
      const timeDiff = parseTriggerTimeMinutes(a?.trigger_time) - parseTriggerTimeMinutes(b?.trigger_time);
      if (timeDiff !== 0) return timeDiff;
      return String(a?.id || "").localeCompare(String(b?.id || ""));
    });
}

function normalizeConflictGroup(value) {
  return normalizeSecretText(value).toLowerCase();
}

function getSchoolConflictGroup(school) {
  const explicitGroup = normalizeConflictGroup(school?.conflict_group);
  if (explicitGroup) {
    return `group:${explicitGroup}`;
  }

  const fidEnc = normalizeConflictGroup(school?.fidEnc);
  if (fidEnc) return `fid:${fidEnc}`;

  return normalizeConflictGroup(school?.name);
}

function shouldCheckSeatConflicts(school) {
  if (school?.ignore_seat_conflicts) return false;
  return Boolean(normalizeConflictGroup(school?.fidEnc));
}

const GITHUB_TOKEN_BINDINGS = {
  a: "GH_TOKEN_A",
  b: "GH_TOKEN_B",
  c: "GH_TOKEN_C",
  d: "GH_TOKEN_D",
  e: "GH_TOKEN_E",
};

function resolveGitHubToken(env, school = null) {
  const tokenKey = normalizeSecretText(school?.github_token_key).toLowerCase();
  const bindingName = GITHUB_TOKEN_BINDINGS[tokenKey];
  if (bindingName) {
    const boundToken = normalizeSecretText(env?.[bindingName]);
    if (boundToken) return boundToken;
  }
  const schoolToken = normalizeSecretText(school?.github_token);
  if (schoolToken) return schoolToken;
  return normalizeSecretText(env?.GH_TOKEN);
}

function resolveServerApiKey(env, school = null) {
  const schoolKey = normalizeSecretText(school?.server_api_key);
  if (schoolKey) return schoolKey;
  return normalizeSecretText(env?.SERVER_DISPATCH_API_KEY);
}

function resolveDispatchTarget(school = null) {
  const raw = normalizeSecretText(school?.dispatch_target).toLowerCase();
  if (raw === "server") return "server_relay";
  return ["github", "server_relay", "both"].includes(raw) ? raw : "github";
}

function normalizeIconclickOcrProvider(value) {
  const raw = String(value ?? "").trim().toLowerCase();
  if (["tuling", "tulingcloud", "图灵", "图灵云"].includes(raw)) return "tulingcloud";
  if (["jfbym", "聚福", "聚福别样"].includes(raw)) return "jfbym";
  return "chaojiying";
}

function normalizeRotateOcrProvider(value) {
  const raw = String(value ?? "").trim().toLowerCase();
  return ["geepass", "tulingcloud", "jfbym"].includes(raw) ? raw : "geepass";
}

function parseReserveDayOffset(value) {
  if (value === null || value === undefined) return null;
  const text = String(value).trim();
  if (!text) return null;
  if (!/^-?\d+$/.test(text)) return null;
  const offset = parseInt(text, 10);
  if (Number.isNaN(offset)) return null;
  return Math.max(0, offset);
}

const SCHEDULE_WEEK_DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];

function scheduleUsesReserveDateStorage(school) {
  return school?.schedule_store_by_reserve_date === true;
}

function resolveScheduleReserveDayOffset(school) {
  const directOffset = parseReserveDayOffset(school?.reserve_day_offset);
  if (directOffset !== null) return directOffset;
  return school?.reserve_next_day === false ? 0 : 1;
}

function shiftScheduleDay(day, offsetDays = 0) {
  const index = SCHEDULE_WEEK_DAYS.indexOf(day);
  if (index < 0) return day;
  const normalizedOffset = ((Number(offsetDays) || 0) % 7 + 7) % 7;
  return SCHEDULE_WEEK_DAYS[(index + normalizedOffset) % 7];
}

function remapScheduleDays(schedule, offsetDays = 0) {
  const source = schedule && typeof schedule === "object" ? schedule : {};
  const mapped = {};
  for (const [day, daySchedule] of Object.entries(source)) {
    mapped[shiftScheduleDay(day, offsetDays)] = daySchedule;
  }
  return mapped;
}

function scheduleForStorage(school, displaySchedule) {
  if (!scheduleUsesReserveDateStorage(school)) return displaySchedule || {};
  return remapScheduleDays(displaySchedule, -resolveScheduleReserveDayOffset(school));
}

function scheduleForDisplay(school, storedSchedule) {
  if (!scheduleUsesReserveDateStorage(school)) return storedSchedule || {};
  return remapScheduleDays(storedSchedule, resolveScheduleReserveDayOffset(school));
}

function scheduleForConflict(school, storedSchedule) {
  return storedSchedule || {};
}

function storedScheduleDayForExecution(school, executionDay) {
  return executionDay;
}

function parseTestReserveDayOffset(value) {
  const offset = parseReserveDayOffset(value);
  return offset === null ? 1 : offset;
}

function resolveReserveDayOffset(env, school = null) {
  const dispatchTarget = resolveDispatchTarget(school);
  if (dispatchTarget !== "server_relay") return null;

  const directOffset = parseReserveDayOffset(school?.reserve_day_offset);
  if (directOffset !== null) return directOffset;

  const rawMap = normalizeSecretText(
    env?.SCHOOL_RESERVE_DAY_OFFSETS || env?.RESERVE_DAY_OFFSETS
  );
  if (!rawMap || !school) return null;

  try {
    const parsed = JSON.parse(rawMap);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      const candidates = [school.id, school.name].map(v => String(v || "").trim()).filter(Boolean);
      for (const key of candidates) {
        const offset = parseReserveDayOffset(parsed[key]);
        if (offset !== null) return offset;
      }
    }
  } catch (_) {
    for (const item of rawMap.split(",")) {
      const [key, value] = item.split(/[:=]/, 2).map(v => String(v || "").trim());
      if (!key || key !== String(school.id || "").trim()) continue;
      const offset = parseReserveDayOffset(value);
      if (offset !== null) return offset;
    }
  }

  return null;
}

const TEST_ENDTIME_OVERRIDE_TTL_MS = 3 * 60 * 1000;

function getActiveTestEndtimeOverride(school, nowMs = Date.now()) {
  const override = school?.test_endtime_override;
  if (!override || typeof override !== "object") return null;

  const trigger_time = normalizeSecretText(override.trigger_time);
  const endtime = normalizeEndtimeHms(override.endtime);
  const reserve_day_offset = parseTestReserveDayOffset(override.reserve_day_offset);
  const expiresMs = Date.parse(override.expires_at || "");
  if (!endtime || !Number.isFinite(expiresMs) || expiresMs <= nowMs) return null;

  return {
    trigger_time: normalizeTriggerTimeHm(trigger_time) || trigger_time,
    endtime,
    reserve_day_offset,
    enabled_at: override.enabled_at || "",
    expires_at: new Date(expiresMs).toISOString(),
    remaining_seconds: Math.max(0, Math.ceil((expiresMs - nowMs) / 1000)),
  };
}

function resolveEffectiveEndtime(school, options = {}) {
  const allowTestEndtimeOverride = options.allowTestEndtimeOverride !== false;
  const activeOverride = allowTestEndtimeOverride
    ? getActiveTestEndtimeOverride(school)
    : null;
  return activeOverride?.endtime || normalizeEndtimeHms(school?.endtime) || "20:00:40";
}

function resolveEffectiveTriggerTime(school, options = {}) {
  const allowTestEndtimeOverride = options.allowTestEndtimeOverride !== false;
  const activeOverride = allowTestEndtimeOverride
    ? getActiveTestEndtimeOverride(school)
    : null;
  return activeOverride?.trigger_time || normalizeSecretText(school?.trigger_time) || "19:57";
}

function sanitizeSchoolForClient(school) {
  if (!school || typeof school !== "object") return school;
  const hasGitHubToken = !!normalizeSecretText(school.github_token);
  const hasServerApiKey = !!normalizeSecretText(school.server_api_key);
  const tokenKey = normalizeSecretText(school.github_token_key).toLowerCase();
  const activeTestEndtime = getActiveTestEndtimeOverride(school);
  const { github_token, server_api_key, test_endtime_override, ...rest } = school;
  return {
    ...rest,
    notes: normalizeSchoolNotes(school.notes),
    test_endtime: normalizeEndtimeHms(school.test_endtime) || "",
    test_trigger_time: normalizeSecretText(school.test_trigger_time) || "",
    test_reserve_day_offset: parseTestReserveDayOffset(school.test_reserve_day_offset),
    test_endtime_override_active: !!activeTestEndtime,
    test_endtime_override_trigger_time: activeTestEndtime?.trigger_time || "",
    test_endtime_override_endtime: activeTestEndtime?.endtime || "",
    test_endtime_override_reserve_day_offset: activeTestEndtime?.reserve_day_offset ?? null,
    test_endtime_override_expires_at: activeTestEndtime?.expires_at || "",
    test_endtime_remaining_seconds: activeTestEndtime?.remaining_seconds || 0,
    effective_trigger_time: resolveEffectiveTriggerTime(school),
    effective_endtime: resolveEffectiveEndtime(school),
    github_token_key: tokenKey,
    dispatch_target: resolveDispatchTarget(school),
    has_github_token: hasGitHubToken || !!tokenKey,
    has_server_api_key: hasServerApiKey,
  };
}

const HEARTBEAT_LAST_TS_KEY = "meta:heartbeat:last_ts";
const HEARTBEAT_LAST_MINUTE_KEY = "meta:heartbeat:last_minute";
const FALLBACK_TRIGGER_PREFIX = "meta:fallback_trigger";
const FALLBACK_TRIGGER_TTL_SECONDS = 14 * 24 * 60 * 60;
const FALLBACK_IN_PROGRESS_TIMEOUT_MS = 3 * 60 * 1000;
const SCHOOLS_SNAPSHOT_KEY = "meta:schools:full";
const EMERGENCY_SCHEDULE_INDEX_KEY = "meta:emergency_snapshot:schedule_index";
const EMERGENCY_SNAPSHOT_RECORD_PREFIX = "meta:emergency_snapshot:record";
const EMERGENCY_SNAPSHOT_LEAD_MS = 2 * 60 * 60 * 1000;
const EMERGENCY_USER_REFRESH_CUTOFF_MS = 15 * 60 * 1000;
const EMERGENCY_FALLBACK_LEAD_SECONDS = 90;
const EMERGENCY_STAGE_RETRY_MS = 10 * 60 * 1000;
const EMERGENCY_STAGE_RECORD_TTL_SECONDS = 3 * 24 * 60 * 60;
const EMERGENCY_STAGE_CRON = "*/5 * * * *";
const PAUSED_USERS_INDEX_KEY = "meta:paused_users";
function schoolUsersSnapshotKey(schoolId) {
  return `school:${schoolId}:users:full`;
}

// ─── KV 操作 ───

async function getSchools(KV) {
  const raw = await KV.get("schools");
  return raw ? JSON.parse(raw) : [];
}

async function saveSchools(KV, schools) {
  await KV.put("schools", JSON.stringify(schools));
}

async function getSchoolsSnapshot(KV) {
  const raw = await KV.get(SCHOOLS_SNAPSHOT_KEY);
  if (raw) return getSortedSchoolsForDisplay(JSON.parse(raw));

  const schoolIds = await getSchools(KV);
  if (schoolIds.length === 0) return [];

  const schools = [];
  for (const schoolId of schoolIds) {
    const school = await getSchool(KV, schoolId);
    if (!school) continue;
    const userIds = await getSchoolUsers(KV, schoolId);
    schools.push({ ...school, userCount: userIds.length });
  }
  const nextSchools = getSortedSchoolsForDisplay(schools);
  await saveSchoolsSnapshot(KV, nextSchools);
  return nextSchools;
}

async function saveSchoolsSnapshot(KV, schools) {
  const sorted = getSortedSchoolsForDisplay(schools);
  await Promise.all([
    KV.put(SCHOOLS_SNAPSHOT_KEY, JSON.stringify(sorted)),
    saveEmergencyScheduleIndex(KV, sorted),
  ]);
}

function buildEmergencyScheduleIndex(schools) {
  return {
    version: 1,
    updated_at: new Date().toISOString(),
    schools: (Array.isArray(schools) ? schools : [])
      .filter(school => school?.id)
      .map(school => ({
        school_id: String(school.id),
        trigger_time: normalizeSecretText(school.trigger_time),
        stage_offset_minutes: emergencyStageOffsetMinutes(school.id),
        enabled: !!normalizeSecretText(school.server_url)
          && ["server_relay", "both"].includes(resolveDispatchTarget(school)),
      })),
  };
}

async function saveEmergencyScheduleIndex(KV, schools) {
  await KV.put(
    EMERGENCY_SCHEDULE_INDEX_KEY,
    JSON.stringify(buildEmergencyScheduleIndex(schools)),
  );
}

async function getEmergencyScheduleIndex(KV) {
  const raw = await KV.get(EMERGENCY_SCHEDULE_INDEX_KEY);
  if (raw) {
    const parsed = JSON.parse(raw);
    if (parsed && Array.isArray(parsed.schools)) return parsed;
  }
  const schools = await getSchoolsSnapshot(KV);
  const index = buildEmergencyScheduleIndex(schools);
  await KV.put(EMERGENCY_SCHEDULE_INDEX_KEY, JSON.stringify(index));
  return index;
}

async function upsertSchoolInSnapshot(KV, school, userCount = null) {
  const schools = await getSchoolsSnapshot(KV);
  const existing = schools.find(item => item && item.id === school.id);
  const nextSchool = {
    ...(existing || {}),
    ...school,
    userCount: userCount ?? existing?.userCount ?? 0,
  };
  const nextSchools = schools.filter(item => item && item.id !== school.id);
  nextSchools.push(nextSchool);
  await saveSchoolsSnapshot(KV, nextSchools);
}

async function removeSchoolFromSnapshot(KV, schoolId) {
  const schools = await getSchoolsSnapshot(KV);
  await saveSchoolsSnapshot(
    KV,
    schools.filter(item => item && item.id !== schoolId)
  );
}

async function setSchoolUserCountInSnapshot(KV, schoolId, userCount) {
  const schools = await getSchoolsSnapshot(KV);
  const nextSchools = schools.map(item => (
    item && item.id === schoolId ? { ...item, userCount } : item
  ));
  await saveSchoolsSnapshot(KV, nextSchools);
}

async function getSchool(KV, schoolId) {
  const raw = await KV.get(`school:${schoolId}`);
  return raw ? JSON.parse(raw) : null;
}

async function saveSchool(KV, school) {
  await Promise.all([
    KV.put(`school:${school.id}`, JSON.stringify(school)),
    upsertSchoolInSnapshot(KV, school),
  ]);
}

async function deleteSchool(KV, schoolId) {
  // 删除学校配置
  await KV.delete(`school:${schoolId}`);
  // 删除学校下所有用户
  const userIds = await getSchoolUsers(KV, schoolId);
  for (const uid of userIds) {
    await KV.delete(`school:${schoolId}:user:${uid}`);
  }
  await KV.delete(`school:${schoolId}:users`);
  await KV.delete(schoolUsersSnapshotKey(schoolId));
  // 从学校列表移除
  const schools = await getSchools(KV);
  await Promise.all([
    saveSchools(KV, schools.filter(id => id !== schoolId)),
    removeSchoolFromSnapshot(KV, schoolId),
  ]);
}

async function getSchoolUsers(KV, schoolId) {
  const raw = await KV.get(`school:${schoolId}:users`);
  return raw ? JSON.parse(raw) : [];
}

async function saveSchoolUsers(KV, schoolId, userIds) {
  await KV.put(`school:${schoolId}:users`, JSON.stringify(userIds));
}

async function getSchoolUsersSnapshot(KV, schoolId) {
  const raw = await KV.get(schoolUsersSnapshotKey(schoolId));
  if (raw) return JSON.parse(raw);

  const userIds = await getSchoolUsers(KV, schoolId);
  if (userIds.length === 0) return [];

  const users = [];
  for (const userId of userIds) {
    const user = await getUser(KV, schoolId, userId);
    if (user) users.push(user);
  }
  await saveSchoolUsersSnapshot(KV, schoolId, users);
  return users;
}

async function saveSchoolUsersSnapshot(KV, schoolId, users) {
  await KV.put(schoolUsersSnapshotKey(schoolId), JSON.stringify(users));
}

async function upsertUserInSnapshot(KV, schoolId, user) {
  const users = await getSchoolUsersSnapshot(KV, schoolId);
  const nextUsers = users.filter(item => item && item.id !== user.id);
  nextUsers.push(user);
  await saveSchoolUsersSnapshot(KV, schoolId, nextUsers);
}

async function removeUserFromSnapshot(KV, schoolId, userId) {
  const users = await getSchoolUsersSnapshot(KV, schoolId);
  await saveSchoolUsersSnapshot(
    KV,
    schoolId,
    users.filter(item => item && item.id !== userId)
  );
}

async function getUser(KV, schoolId, userId) {
  const raw = await KV.get(`school:${schoolId}:user:${userId}`);
  return raw ? JSON.parse(raw) : null;
}

async function saveUser(KV, schoolId, user) {
  await Promise.all([
    KV.put(`school:${schoolId}:user:${user.id}`, JSON.stringify(user)),
    upsertUserInSnapshot(KV, schoolId, user),
  ]);
}

function pauseUntilFromDays(days, nowMs = Date.now()) {
  const value = Number(days);
  if (!Number.isInteger(value) || value < 1 || value > 365) return "";
  return new Date(nowMs + value * 24 * 60 * 60 * 1000).toISOString();
}

async function getPausedUsersIndex(KV) {
  const raw = await KV.get(PAUSED_USERS_INDEX_KEY);
  if (!raw) return [];
  try {
    const rows = JSON.parse(raw);
    return Array.isArray(rows) ? rows : [];
  } catch (_error) {
    return [];
  }
}

async function updatePausedUserIndex(KV, schoolId, userId, resumeAt = "") {
  const rows = await getPausedUsersIndex(KV);
  const next = rows.filter(row => (
    String(row?.schoolId || "") !== String(schoolId)
    || String(row?.userId || "") !== String(userId)
  ));
  if (resumeAt) next.push({ schoolId, userId, resumeAt });
  await KV.put(PAUSED_USERS_INDEX_KEY, JSON.stringify(next));
}

async function resumeExpiredPausedUsers(env) {
  const KV = env.SEAT_KV;
  const rows = await getPausedUsersIndex(KV);
  if (!rows.length) return;

  const nowMs = Date.now();
  const pending = [];
  for (const row of rows) {
    const resumeAt = String(row?.resumeAt || "");
    if (Date.parse(resumeAt) > nowMs) {
      pending.push(row);
      continue;
    }

    const schoolId = String(row?.schoolId || "");
    const userId = String(row?.userId || "");
    const user = schoolId && userId ? await getUser(KV, schoolId, userId) : null;
    if (!user || user.status !== "paused" || user.pause_until !== resumeAt) continue;

    user.status = "active";
    delete user.pause_until;
    delete user.pause_days;
    user.updatedAt = new Date().toISOString();
    await saveUser(KV, schoolId, user);
    await syncUserExternalState(env, schoolId, user);
    const school = await getSchool(KV, schoolId);
    if (school) {
      await refreshEmergencySnapshotForChangedUser(env, school, user).catch(error => {
        console.error(
          `Emergency auto-resume refresh failed school=${schoolId} user=${userId}:`,
          error?.message || String(error),
        );
      });
    }
  }

  // ponytail: one small global index is enough; shard it only if paused-user volume becomes large.
  await KV.put(PAUSED_USERS_INDEX_KEY, JSON.stringify(pending));
}

async function deleteUser(KV, schoolId, userId) {
  const userIds = await getSchoolUsers(KV, schoolId);
  await Promise.all([
    KV.delete(`school:${schoolId}:user:${userId}`),
    saveSchoolUsers(KV, schoolId, userIds.filter(id => id !== userId)),
    removeUserFromSnapshot(KV, schoolId, userId),
    updatePausedUserIndex(KV, schoolId, userId),
  ]);
}

async function migrateUserToSchool(KV, sourceSchoolId, userId, targetSchoolId) {
  if (!targetSchoolId) {
    return { error: "请填写目标组 ID", status: 400 };
  }
  if (sourceSchoolId === targetSchoolId) {
    return { error: "目标组不能和当前组相同", status: 400 };
  }

  const [sourceSchool, targetSchool, user] = await Promise.all([
    getSchool(KV, sourceSchoolId),
    getSchool(KV, targetSchoolId),
    getUser(KV, sourceSchoolId, userId),
  ]);
  if (!sourceSchool) return { error: "Source school not found", status: 404 };
  if (!targetSchool) return { error: "目标组不存在", status: 404 };
  if (!user) return { error: "User not found", status: 404 };

  const existingTargetUser = await getUser(KV, targetSchoolId, userId);
  if (existingTargetUser) {
    return { error: "目标组已存在相同 ID 的用户", status: 409 };
  }

  const displaySchedule = scheduleForDisplay(sourceSchool, user.schedule || {});
  const targetStoredSchedule = scheduleForStorage(targetSchool, displaySchedule);
  const targetUsers = await getConflictScopeUsers(KV, targetSchoolId, targetSchool);
  const conflicts = await findSeatConflicts(
    KV,
    targetSchoolId,
    scheduleForConflict(targetSchool, targetStoredSchedule),
    { userId, phone: user.phone },
    targetUsers,
  );
  if (conflicts.length > 0) {
    return {
      error: buildSeatConflictError(conflicts),
      conflicts,
      status: 409,
    };
  }

  user.schedule = targetStoredSchedule;
  user.schoolId = targetSchoolId;
  const targetUserIds = await getSchoolUsers(KV, targetSchoolId);
  await saveUser(KV, targetSchoolId, user);
  if (!targetUserIds.includes(userId)) {
    targetUserIds.push(userId);
    await saveSchoolUsers(KV, targetSchoolId, targetUserIds);
  }
  await deleteUser(KV, sourceSchoolId, userId);
  if (user.pause_until) {
    await updatePausedUserIndex(KV, targetSchoolId, userId, user.pause_until);
  }

  const sourceUserIds = await getSchoolUsers(KV, sourceSchoolId);
  await Promise.all([
    setSchoolUserCountInSnapshot(KV, sourceSchoolId, sourceUserIds.length),
    setSchoolUserCountInSnapshot(KV, targetSchoolId, targetUserIds.length),
  ]);

  return {
    ok: true,
    user: await sanitizeUserForAdmin(user, { school: targetSchool }),
    sourceSchool: sanitizeSchoolForClient(sourceSchool),
    targetSchool: sanitizeSchoolForClient(targetSchool),
  };
}

function minuteBucket(timestampMs) {
  return Math.floor(timestampMs / 60000);
}

async function getHeartbeatTimestamp(KV) {
  const raw = await KV.get(HEARTBEAT_LAST_TS_KEY);
  const ts = parseInt(String(raw || "").trim(), 10);
  if (Number.isNaN(ts) || ts <= 0) return null;
  return ts;
}

async function getHeartbeatMinuteSlot(KV) {
  const raw = await KV.get(HEARTBEAT_LAST_MINUTE_KEY);
  const slot = String(raw || "").trim();
  return slot || null;
}

async function sleep(ms) {
  if (ms <= 0) return;
  await new Promise(resolve => setTimeout(resolve, ms));
}

async function writeHeartbeatTimestamp(KV, timestampMs = Date.now()) {
  const currentMinuteSlot = beijingDateMinute(timestampMs);
  await Promise.all([
    KV.put(HEARTBEAT_LAST_TS_KEY, String(timestampMs)),
    KV.put(HEARTBEAT_LAST_MINUTE_KEY, currentMinuteSlot),
  ]);
  return {
    written: true,
    timestamp: timestampMs,
    minuteSlot: currentMinuteSlot,
    minuteBucket: minuteBucket(timestampMs),
  };
}

function buildFallbackTriggerKey(date, schoolId, scope = "") {
  const scopeText = normalizeSecretText(scope);
  return scopeText
    ? `${FALLBACK_TRIGGER_PREFIX}:${date}:${schoolId}:${scopeText}`
    : `${FALLBACK_TRIGGER_PREFIX}:${date}:${schoolId}`;
}

function formalTriggerScope(school) {
  const triggerTime = normalizeTriggerTimeHm(school?.trigger_time);
  return triggerTime ? `formal-${triggerTime.replace(":", "-")}` : "formal";
}

async function getFallbackTriggerRecord(KV, date, schoolId, scope = "") {
  const raw = await KV.get(buildFallbackTriggerKey(date, schoolId, scope));
  return raw ? JSON.parse(raw) : null;
}

function isScheduledTriggerRecord(record) {
  return !!record && record.mode === "scheduled";
}

function isInProgressTriggerRecord(record) {
  return !!record && record.mode === "in_progress";
}

function isFreshInProgressTriggerRecord(record, timestampMs = Date.now()) {
  if (!isInProgressTriggerRecord(record)) return false;
  const startedAtMs = Date.parse(record.at || "");
  return Number.isFinite(startedAtMs)
    && timestampMs - startedAtMs >= 0
    && timestampMs - startedAtMs < FALLBACK_IN_PROGRESS_TIMEOUT_MS;
}

async function saveFallbackTriggerRecord(KV, date, schoolId, record, scope = "") {
  await KV.put(
    buildFallbackTriggerKey(date, schoolId, scope),
    JSON.stringify(record),
    {
      // 兜底标记是按“学校 + 日期”生成的，会自然累积；这里保留 14 天方便回看，同时避免无限增长。
      expirationTtl: FALLBACK_TRIGGER_TTL_SECONDS,
    }
  );
}

async function deleteKvKeysByPrefix(KV, prefix, limit = 1000) {
  let cursor = undefined;
  let deleted = 0;
  do {
    const page = await KV.list({ prefix, cursor, limit });
    const keys = (page.keys || []).map(item => item.name).filter(Boolean);
    if (keys.length) {
      await Promise.all(keys.map(key => KV.delete(key)));
      deleted += keys.length;
    }
    cursor = page.list_complete ? undefined : page.cursor;
  } while (cursor);
  return deleted;
}

async function cleanupYesterdayHeartbeatAndFallbackRecords(KV, timestampMs = Date.now()) {
  if (beijingHHMM() !== "05:56") {
    return { skipped: true, reason: "not_cleanup_minute" };
  }

  const yesterday = beijingDateWithOffset(-1, timestampMs);
  const prefixes = [
    `${FALLBACK_TRIGGER_PREFIX}:${yesterday}:`,
    `meta:heartbeat:${yesterday}`,
  ];

  const deletedByPrefix = {};
  for (const prefix of prefixes) {
    deletedByPrefix[prefix] = await deleteKvKeysByPrefix(KV, prefix);
  }

  const deleted = Object.values(deletedByPrefix).reduce((sum, count) => sum + count, 0);
  const record = {
    at: new Date(timestampMs).toISOString(),
    beijing_date: beijingDateFromTimestamp(timestampMs),
    beijing_time: beijingHHMM(),
    deleted_date: yesterday,
    deleted,
    deletedByPrefix,
  };
  await KV.put(`meta:cleanup:yesterday:${yesterday}`, JSON.stringify(record), {
    expirationTtl: FALLBACK_TRIGGER_TTL_SECONDS,
  });
  console.log(`Cleanup yesterday records ${yesterday}: deleted=${deleted}`);
  return { skipped: false, ...record };
}

// ─── 默认配置 ───

function defaultSchool(id, name) {
  return {
    id,
    name,
    conflict_group: "",
    trigger_time: "19:55",
    endtime: "20:00:40",
    test_trigger_time: "",
    test_endtime: "",
    test_reserve_day_offset: 1,
    test_endtime_override: null,
    seat_api_mode: "seat",
    reserve_next_day: true,
    reserve_day_offset: null,
    schedule_store_by_reserve_date: false,
    ignore_seat_conflicts: false,
    enable_slider: false,
    enable_textclick: false,
    enable_iconclick: false,
    iconclick_ocr_provider: "chaojiying",
    enable_rotate: false,
    rotate_ocr_provider: "geepass",
    fidEnc: "",
    plan_extract_max_hours: PLAN_EXTRACT_MAX_HOURS_DEFAULT,
    plan_extract_seat_page_id: "",
    reading_zone_groups: [],
    notes: [],
    repo: `BAOfuZhan/${id}`,
    dispatch_target: "github",
    github_token_key: "",
    github_token: "",
    server_url: "",
    server_api_key: "",
    server_max_concurrency: 13,
    strategy: {
      mode: "C",
      submit_mode: "serial",
      login_lead_seconds: 50,
      login_lead_seconds_range: [63, 65],
      slider_lead_seconds: 59,
      slider_lead_seconds_range: [59000, 61000],
      fast_probe_start_offset_ms: 7,
      fast_probe_start_range_ms: [7, 14],
      warm_connection_lead_ms: 2400,
      pre_fetch_token_ms: 1531,
      pre_fetch_token_range_ms: [2831, 2891],
      first_submit_offset_ms: 4,
      first_submit_offset_range_ms: [4, 9],
      token_fetch_delay_ms: 45,
      token_fetch_timeout_ms: 5830,
      fast_probe_timeout_ms: 5830,
      first_token_date_mode: "submit_date",
      skip_first_seat_query: true,
    },
  };
}

function defaultUser(id) {
  return {
    id,
    phone: "",
    username: "",
    password: "",
    remark: "",
    status: "active",
    sign_feature_visible: false,
    auto_sign_enabled: false,
    user_top_config_enabled: false,
    user_top_config: {},
    schedule: {
      Monday: { enabled: false, slots: [{roomid:"",seatid:"",times:"",seatPageId:"",fidEnc:""},{roomid:"",seatid:"",times:"",seatPageId:"",fidEnc:""},{roomid:"",seatid:"",times:"",seatPageId:"",fidEnc:""},{roomid:"",seatid:"",times:"",seatPageId:"",fidEnc:""}] },
      Tuesday: { enabled: false, slots: [{roomid:"",seatid:"",times:"",seatPageId:"",fidEnc:""},{roomid:"",seatid:"",times:"",seatPageId:"",fidEnc:""},{roomid:"",seatid:"",times:"",seatPageId:"",fidEnc:""},{roomid:"",seatid:"",times:"",seatPageId:"",fidEnc:""}] },
      Wednesday: { enabled: false, slots: [{roomid:"",seatid:"",times:"",seatPageId:"",fidEnc:""},{roomid:"",seatid:"",times:"",seatPageId:"",fidEnc:""},{roomid:"",seatid:"",times:"",seatPageId:"",fidEnc:""},{roomid:"",seatid:"",times:"",seatPageId:"",fidEnc:""}] },
      Thursday: { enabled: false, slots: [{roomid:"",seatid:"",times:"",seatPageId:"",fidEnc:""},{roomid:"",seatid:"",times:"",seatPageId:"",fidEnc:""},{roomid:"",seatid:"",times:"",seatPageId:"",fidEnc:""},{roomid:"",seatid:"",times:"",seatPageId:"",fidEnc:""}] },
      Friday: { enabled: false, slots: [{roomid:"",seatid:"",times:"",seatPageId:"",fidEnc:""},{roomid:"",seatid:"",times:"",seatPageId:"",fidEnc:""},{roomid:"",seatid:"",times:"",seatPageId:"",fidEnc:""},{roomid:"",seatid:"",times:"",seatPageId:"",fidEnc:""}] },
      Saturday: { enabled: false, slots: [{roomid:"",seatid:"",times:"",seatPageId:"",fidEnc:""},{roomid:"",seatid:"",times:"",seatPageId:"",fidEnc:""},{roomid:"",seatid:"",times:"",seatPageId:"",fidEnc:""},{roomid:"",seatid:"",times:"",seatPageId:"",fidEnc:""}] },
      Sunday: { enabled: false, slots: [{roomid:"",seatid:"",times:"",seatPageId:"",fidEnc:""},{roomid:"",seatid:"",times:"",seatPageId:"",fidEnc:""},{roomid:"",seatid:"",times:"",seatPageId:"",fidEnc:""},{roomid:"",seatid:"",times:"",seatPageId:"",fidEnc:""}] },
    },
  };
}

function getEnabledScheduleSlots(daySchedule) {
  if (!daySchedule || !daySchedule.enabled) return [];
  const rawSlots = Array.isArray(daySchedule.slots)
    ? daySchedule.slots
    : [{
        roomid: daySchedule.roomid,
        seatid: daySchedule.seatid,
        times: daySchedule.times,
        seatPageId: daySchedule.seatPageId || "",
        fidEnc: daySchedule.fidEnc || "",
      }];
  return rawSlots
    .map((slot, index) => slot && typeof slot === "object" ? { ...slot, __slotIndex: index } : slot)
    .filter(slot => slot && slot.times && slot.roomid);
}

function countActiveUsersForDay(users, day, school = null) {
  const storedDay = storedScheduleDayForExecution(school, day);
  return (Array.isArray(users) ? users : []).filter(user => (
    user
      && user.status === "active"
      && getEnabledScheduleSlots(user.schedule?.[storedDay]).length > 0
  )).length;
}

async function getSchoolCounts(KV, schoolId) {
  const today = beijingDayOfWeek();
  const [users, school] = await Promise.all([
    getSchoolUsersSnapshot(KV, schoolId),
    getSchool(KV, schoolId),
  ]);
  return {
    totalCount: users.length,
    activeTodayCount: countActiveUsersForDay(users, today, school),
    day: today,
  };
}

// ─── GitHub Dispatch ───

function githubApiHeaders(token) {
  return {
    Authorization: `Bearer ${token}`,
    Accept: "application/vnd.github+json",
    "User-Agent": "TongYi-Worker",
    "X-GitHub-Api-Version": "2022-11-28",
  };
}

async function dispatchGitHub(token, repo, payload) {
  try {
    const res = await fetch(`https://api.github.com/repos/${repo}/dispatches`, {
      method: "POST",
      headers: githubApiHeaders(token),
      body: JSON.stringify({ event_type: "reserve", client_payload: payload }),
    });
    return res.status === 204;
  } catch (e) {
    console.error("dispatchGitHub error:", e);
    return false;
  }
}

function runCreatedAfter(run, minCreatedAtMs) {
  const createdAt = Date.parse(run?.created_at || "");
  return Number.isFinite(createdAt) && createdAt >= minCreatedAtMs;
}

function isReserveWorkflowRun(run) {
  const path = String(run?.path || "").trim();
  const normalizedPath = path.split("@", 1)[0];
  return normalizedPath === ".github/workflows/reserve.yml"
    || normalizedPath.endsWith("/.github/workflows/reserve.yml")
    || normalizedPath.endsWith("/reserve.yml");
}

function runMatchesDispatchId(run, dispatchId) {
  const expected = normalizeSecretText(dispatchId);
  if (!expected) return true;
  const fields = [
    run?.display_title,
    run?.name,
    run?.head_commit?.message,
  ];
  return fields.some(value => normalizeSecretText(value).includes(expected));
}

async function fetchRecentRepositoryDispatchRuns(token, repo) {
  const url = new URL(`https://api.github.com/repos/${repo}/actions/runs`);
  url.searchParams.set("event", "repository_dispatch");
  url.searchParams.set("per_page", "20");
  const res = await fetch(url.toString(), {
    headers: githubApiHeaders(token),
  });
  const text = await res.text();
  let data = {};
  try {
    data = text ? JSON.parse(text) : {};
  } catch (_) {
    data = { raw: text };
  }
  if (!res.ok) {
    const detail = typeof data?.message === "string" ? data.message : text || `HTTP ${res.status}`;
    throw new Error(`actions runs check failed: HTTP ${res.status}: ${detail}`);
  }
  return Array.isArray(data.workflow_runs) ? data.workflow_runs : [];
}

async function snapshotRepositoryDispatchRunIds(token, repo) {
  const runs = await fetchRecentRepositoryDispatchRuns(token, repo);
  return new Set(runs.map(run => String(run?.id || "")).filter(Boolean));
}

async function waitForRepositoryDispatchRun(token, repo, minCreatedAtMs, seenRunIds, beforeRunIds, dispatchId = "") {
  const delaysMs = [900, 1300, 1800, 2500, 3500];
  let lastError = "";
  for (let attempt = 0; attempt < delaysMs.length; attempt++) {
    await sleep(delaysMs[attempt]);
    try {
      const runs = await fetchRecentRepositoryDispatchRuns(token, repo);
      const run = runs.find(item => {
        const id = String(item?.id || "");
        return id
          && !beforeRunIds.has(id)
          && !seenRunIds.has(id)
          && isReserveWorkflowRun(item)
          && runMatchesDispatchId(item, dispatchId)
          && runCreatedAfter(item, minCreatedAtMs);
      });
      if (run) {
        const id = String(run.id || "");
        seenRunIds.add(id);
        return {
          ok: true,
          runId: id,
          runUrl: run.html_url || "",
          createdAt: run.created_at || "",
          attempt: attempt + 1,
        };
      }
    } catch (e) {
      lastError = e.message || String(e);
      break;
    }
  }
  return {
    ok: false,
    detail: lastError || (
      dispatchId
        ? `dispatch accepted but no new reserve.yml repository_dispatch Actions run appeared for dispatch_id=${dispatchId}`
        : "dispatch accepted but no new reserve.yml repository_dispatch Actions run appeared"
    ),
  };
}

async function dispatchGitHubVerbose(token, repo, payload, options = {}) {
  const dispatchStartedAtMs = Date.now();
  const eventType = normalizeSecretText(options.eventType) || "reserve";
  try {
    const seenRunIds = options.seenRunIds instanceof Set ? options.seenRunIds : new Set();
    const beforeRunIds = await snapshotRepositoryDispatchRunIds(token, repo);
    for (const id of beforeRunIds) seenRunIds.add(id);

    const res = await fetch(`https://api.github.com/repos/${repo}/dispatches`, {
      method: "POST",
      headers: githubApiHeaders(token),
      body: JSON.stringify({ event_type: eventType, client_payload: payload }),
    });
    const text = await res.text();
    if (res.status !== 204) {
      return { ok: false, status: res.status, detail: text };
    }

    const minCreatedAtMs = Math.max(0, dispatchStartedAtMs - 5000);
    const runCheck = await waitForRepositoryDispatchRun(
      token,
      repo,
      minCreatedAtMs,
      seenRunIds,
      beforeRunIds,
      payload?.dispatch_id || "",
    );
    if (!runCheck.ok) {
      return {
        ok: false,
        status: res.status,
        detail: runCheck.detail,
        accepted: true,
      };
    }
    return {
      ok: true,
      status: res.status,
      detail: text,
      accepted: true,
      runId: runCheck.runId,
      runUrl: runCheck.runUrl,
      runCreatedAt: runCheck.createdAt,
      verifyAttempt: runCheck.attempt,
    };
  } catch (e) {
    return { ok: false, status: 0, detail: e.message || String(e) };
  }
}

async function dispatchGitHubVerifiedWithRetry(token, repo, payload, options = {}) {
  const retryDelaysMs = [0, 1800, 3200];
  let lastResp = null;
  for (let attempt = 0; attempt < retryDelaysMs.length; attempt++) {
    if (retryDelaysMs[attempt] > 0) await sleep(retryDelaysMs[attempt]);
    const resp = await dispatchGitHubVerbose(token, repo, payload, options);
    if (resp.ok) {
      return {
        ...resp,
        dispatchAttempt: attempt + 1,
      };
    }
    lastResp = resp;
    if (resp.status !== 204 || resp.accepted !== true) break;
  }
  return {
    ...(lastResp || { ok: false, status: 0, detail: "GitHub dispatch failed before verification" }),
    dispatchAttempt: retryDelaysMs.length,
  };
}

async function dispatchServer(url, apiKey, payload) {
  try {
    const res = await sendServerRequest(url, apiKey, payload);
    return res.ok;
  } catch (e) {
    console.error("dispatchServer error:", e);
    return false;
  }
}

async function dispatchServerVerbose(url, apiKey, payload) {
  try {
    const res = await sendServerRequest(url, apiKey, payload);
    const text = await res.text();
    return { ok: res.ok, status: res.status, detail: text };
  } catch (e) {
    return { ok: false, status: 0, detail: e.message || String(e) };
  }
}

function cloudflareServerFetchUrl(serverUrl) {
  const url = new URL(normalizeSecretText(serverUrl));
  if (url.protocol === "http:" && /^\d{1,3}(?:\.\d{1,3}){3}$/.test(url.hostname)) {
    return DEFAULT_SERVER_DISPATCH_PROXY_URL;
  }
  return url.toString();
}

async function sendServerRequest(serverUrl, apiKey, payload, probe = false) {
  const targetUrl = normalizeSecretText(serverUrl);
  const proxyUrl = cloudflareServerFetchUrl(targetUrl);
  const usesProxy = proxyUrl === DEFAULT_SERVER_DISPATCH_PROXY_URL;
  const headers = { "Content-Type": "application/json", "User-Agent": "TongYi-Worker" };
  if (usesProxy) {
    if (apiKey) headers["X-Tongyi-Key"] = apiKey;
  } else {
    if (apiKey) headers["X-API-Key"] = apiKey;
    if (probe) headers["X-Config-Probe"] = "1";
  }
  return fetch(proxyUrl, {
    method: "POST",
    headers,
    body: JSON.stringify(usesProxy ? {
      serverUrl: targetUrl,
      serverApiKey: apiKey,
      probe,
      payload,
    } : payload),
    ...(probe ? { signal: AbortSignal.timeout(8000) } : {}),
  });
}

async function probeServerConnection(serverUrl, apiKey) {
  if (!normalizeSecretText(serverUrl)) {
    return { ok: false, error: "服务器地址不能为空" };
  }
  try {
    const response = await sendServerRequest(
      serverUrl,
      apiKey,
      { type: "config_probe", sent_at: new Date().toISOString() },
      true,
    );
    const responseText = await response.text();
    let data = {};
    try { data = responseText ? JSON.parse(responseText) : {}; } catch (_) { data = {}; }
    if (!response.ok || data?.ok !== true || data?.service !== "server-dispatch") {
      const detail = String(data?.error || responseText || "").replace(/\s+/g, " ").trim().slice(0, 160);
      return {
        ok: false,
        error: response.status === 401
          ? "服务器 API Key 验证失败"
          : `服务器连接检测失败（HTTP ${response.status}${detail ? "：" + detail : ""}）`,
      };
    }
    return { ok: true, checkedAt: new Date().toISOString() };
  } catch (error) {
    return { ok: false, error: "服务器连接失败：" + (error?.message || String(error)) };
  }
}

async function syncRenewalProfile(env, user) {
  const expiresOn = String(user.renewalExpiresOn || "").trim();
  const purchaseChannel = String(user.purchaseChannel || "").trim();
  if (!expiresOn && !purchaseChannel) return;

  const url = new URL(String(env.RENEWAL_API_URL || DEFAULT_INTERNAL_API_URL).trim());
  const token = normalizeSecretText(env.SERVER_DISPATCH_API_KEY);
  if (!token) throw new Error("Worker 未配置 SERVER_DISPATCH_API_KEY，无法同步续费信息");

  const response = await fetch(url.toString(), {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Tongyi-Key": token,
    },
    body: JSON.stringify({
      phone: user.phone,
      schoolId: user.schoolId,
      userId: user.id,
      username: user.username,
      status: user.status,
      expiresOn,
      purchaseChannel,
    }),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || !data.ok) {
    throw new Error(data.error || `续费信息同步失败：HTTP ${response.status}`);
  }
}

async function fetchRenewalProfile(env, schoolId, phone) {
  const token = normalizeSecretText(env.SERVER_DISPATCH_API_KEY);
  if (!token) throw new Error("Worker 未配置 SERVER_DISPATCH_API_KEY，无法读取续费信息");

  const baseUrl = String(env.RENEWAL_API_URL || DEFAULT_INTERNAL_API_URL).trim();
  const url = new URL(baseUrl);
  url.searchParams.set("schoolId", schoolId);
  url.searchParams.set("phone", phone);
  const response = await fetch(url, { headers: { "X-Tongyi-Key": token } });
  const text = await response.text();
  if (!response.ok) throw new Error(`读取续费信息失败：HTTP ${response.status} ${text.slice(0, 200)}`);
  const data = JSON.parse(text);
  return (data.rows || []).find(item => String(item.phone || "") === String(phone || "")) || null;
}

function internalApiUrlFromRenewalEnv(env, path) {
  const renewalUrl = String(env.RENEWAL_API_URL || DEFAULT_INTERNAL_API_URL).trim();
  return new URL(path, renewalUrl).toString();
}

function signControlToken(env) {
  return normalizeSecretText(env.SIGN_CONTROL_TOKEN) || normalizeSecretText(env.SERVER_DISPATCH_API_KEY);
}

function signControlHeaders(env) {
  const token = signControlToken(env);
  if (!token) throw new Error("Worker 未配置 SIGN_CONTROL_TOKEN 或 SERVER_DISPATCH_API_KEY，无法读取自动签到设置");
  return {
    "Content-Type": "application/json",
    "X-Sign-Control-Token": token,
    "X-Tongyi-Key": token,
  };
}

function applySignControlStatus(user, status) {
  if (!status || status.ok === false) return user;
  const visible = status.featureVisible === true || status.autoEnabled === true;
  return {
    ...user,
    sign_feature_visible: visible,
    auto_sign_enabled: visible && status.autoEnabled === true,
  };
}

async function fetchSignControlStatus(env, schoolId, userId) {
  const url = new URL(internalApiUrlFromRenewalEnv(env, "/api/internal/sign-control"));
  url.searchParams.set("schoolId", schoolId);
  url.searchParams.set("userId", userId);
  const response = await fetch(url.toString(), { headers: signControlHeaders(env) });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || !data.ok) {
    throw new Error(data.error || `读取自动签到设置失败：HTTP ${response.status}`);
  }
  return data;
}

async function fetchSignFeatureDashboard(env) {
  const response = await fetch(internalApiUrlFromRenewalEnv(env, "/api/internal/sign-feature-dashboard"), {
    headers: signControlHeaders(env),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || !data.ok) {
    throw new Error(data.error || `读取自动签到显示控制失败：HTTP ${response.status}`);
  }
  return data;
}

async function mergeSignStatusesForUsers(env, schoolId, users) {
  try {
    const dashboard = await fetchSignFeatureDashboard(env);
    const school = (dashboard.schools || []).find(item => String(item?.schoolId || "") === String(schoolId));
    const statuses = new Map((school?.users || []).map(item => [String(item?.userId || ""), item]));
    return users.map(user => applySignControlStatus(user, statuses.get(String(user?.id || ""))));
  } catch (error) {
    console.warn(`Failed to read sign dashboard for school ${schoolId}:`, error?.message || String(error));
    return users;
  }
}

async function mergeSignStatusForUser(env, schoolId, user) {
  try {
    return applySignControlStatus(user, await fetchSignControlStatus(env, schoolId, user.id));
  } catch (error) {
    console.warn(`Failed to read sign settings school=${schoolId} user=${user?.id || ""}:`, error?.message || String(error));
    return user;
  }
}

async function syncSignFeatureUser(env, schoolId, user) {
  if (!Object.prototype.hasOwnProperty.call(user, "sign_feature_visible")) return;
  const token = signControlToken(env);
  if (!token) throw new Error("Worker 未配置 SERVER_DISPATCH_API_KEY，无法同步自动签到显示权限");
  const response = await fetch(internalApiUrlFromRenewalEnv(env, "/api/internal/sign-feature-user"), {
    method: "PUT",
    headers: signControlHeaders(env),
    body: JSON.stringify({
      schoolId,
      userId: user.id,
      override: user.sign_feature_visible === true ? "show" : "hide",
    }),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || !data.ok) {
    throw new Error(data.error || `自动签到显示权限同步失败：HTTP ${response.status}`);
  }
}

async function syncSignControl(env, schoolId, user) {
  if (!Object.prototype.hasOwnProperty.call(user, "auto_sign_enabled")) return;
  const token = signControlToken(env);
  if (!token) throw new Error("Worker 未配置 SERVER_DISPATCH_API_KEY，无法同步自动签到开关");
  const response = await fetch(internalApiUrlFromRenewalEnv(env, "/api/internal/sign-control"), {
    method: "PUT",
    headers: signControlHeaders(env),
    body: JSON.stringify({
      schoolId,
      userId: user.id,
      enabled: user.auto_sign_enabled === true,
    }),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || !data.ok) {
    throw new Error(data.error || `自动签到开关同步失败：HTTP ${response.status}`);
  }
}

async function syncSignSettings(env, schoolId, user) {
  await syncSignFeatureUser(env, schoolId, user);
  await syncSignControl(env, schoolId, user);
}

async function syncUserToServer(env, schoolId, user, sourceSchoolId = "") {
  const token = normalizeSecretText(env.SERVER_DISPATCH_API_KEY);
  if (!token) throw new Error("Worker 未配置 SERVER_DISPATCH_API_KEY，无法同步用户");
  const response = await fetch(internalApiUrlFromRenewalEnv(env, "/api/internal/user-sync"), {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Tongyi-Key": token,
    },
    body: JSON.stringify({ schoolId, user, ...(sourceSchoolId ? { sourceSchoolId } : {}) }),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || !data.ok) {
    throw new Error(data.error || `用户同步服务器失败：HTTP ${response.status}`);
  }
}

async function syncUserDeleteToServer(env, schoolId, userId) {
  const token = normalizeSecretText(env.SERVER_DISPATCH_API_KEY);
  if (!token) throw new Error("Worker 未配置 SERVER_DISPATCH_API_KEY，无法同步删除用户");
  const response = await fetch(internalApiUrlFromRenewalEnv(env, "/api/internal/user-delete"), {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Tongyi-Key": token,
    },
    body: JSON.stringify({ schoolId, userId }),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || !data.ok) {
    throw new Error(data.error || `用户删除同步服务器失败：HTTP ${response.status}`);
  }
}

async function syncUserExternalState(env, schoolId, user, options = {}) {
  try {
    await syncUserToServer(env, schoolId, user, options.sourceSchoolId);
  } catch (error) {
    console.error("Post-save user sync failed:", error?.message || String(error));
  }

  if (options.renewalExpiresOn !== undefined || options.purchaseChannel !== undefined) {
    try {
      await syncRenewalProfile(env, {
        ...user,
        renewalExpiresOn: options.renewalExpiresOn,
        purchaseChannel: options.purchaseChannel,
      });
    } catch (error) {
      console.error("Post-save renewal sync failed:", error?.message || String(error));
    }
  }

  try {
    await syncSignSettings(env, schoolId, user);
  } catch (error) {
    console.warn("Post-save sign settings sync skipped:", error?.message || String(error));
  }
}

function scheduleUserExternalSync(ctx, env, schoolId, user, options = {}) {
  const task = syncUserExternalState(env, schoolId, user, options);
  if (ctx && typeof ctx.waitUntil === "function") {
    ctx.waitUntil(task);
    return;
  }
  task.catch(error => {
    console.error("Post-save external sync failed:", error?.message || String(error));
  });
}

const BATCH_SIZE = 10;
const GITHUB_DISPATCH_PAYLOAD_LIMIT_BYTES = 62 * 1024;
const GITHUB_DISPATCH_PAYLOAD_MAX_PROPERTIES = 10;

function randIntInclusive(min, max) {
  const lo = Math.min(min, max);
  const hi = Math.max(min, max);
  return Math.floor(Math.random() * (hi - lo + 1)) + lo;
}

function randIntUniqueInclusive(min, max, usedValues) {
  const lo = Math.min(min, max);
  const hi = Math.max(min, max);
  const capacity = hi - lo + 1;
  const usedInRange = usedValues instanceof Set
    ? [...usedValues].filter(v => v >= lo && v <= hi).length
    : 0;
  if (!(usedValues instanceof Set) || usedInRange >= capacity) {
    return randIntInclusive(lo, hi);
  }

  for (let i = 0; i < 12; i++) {
    const candidate = randIntInclusive(lo, hi);
    if (!usedValues.has(candidate)) {
      usedValues.add(candidate);
      return candidate;
    }
  }

  for (let candidate = lo; candidate <= hi; candidate++) {
    if (!usedValues.has(candidate)) {
      usedValues.add(candidate);
      return candidate;
    }
  }
  return randIntInclusive(lo, hi);
}

function parseRangeWithFallback(v, fallback) {
  if (Array.isArray(v) && v.length >= 2) {
    const a = parseInt(v[0], 10);
    const b = parseInt(v[1], 10);
    if (!Number.isNaN(a) && !Number.isNaN(b)) return [a, b];
  }
  if (typeof v === "string" && v.includes(",")) {
    const parts = v.split(",").map(x => parseInt(x.trim(), 10));
    if (parts.length >= 2 && !Number.isNaN(parts[0]) && !Number.isNaN(parts[1])) {
      return [parts[0], parts[1]];
    }
  }
  return [fallback, fallback];
}

function normalizeSliderLeadRangeValueMs(value) {
  const parsed = parseInt(value, 10);
  const milliseconds = parsed >= 0 && parsed < 30 ? parsed * 1000 : parsed;
  return Math.max(5000, Number.isNaN(milliseconds) ? 10000 : milliseconds);
}

function randomizeStrategy(base, options = {}) {
  const s = { ...(base || {}) };
  const loginLeadRange = parseRangeWithFallback(
    s.login_lead_seconds_range,
    s.login_lead_seconds || 18,
  );
  const sliderLeadRange = s.slider_lead_seconds_range !== undefined
    ? parseRangeWithFallback(s.slider_lead_seconds_range, 10000).map(normalizeSliderLeadRangeValueMs)
    : null;
  const probeStartRange = parseRangeWithFallback(
    s.fast_probe_start_range_ms,
    s.fast_probe_start_offset_ms || 14,
  );
  const firstSubmitRange = parseRangeWithFallback(
    s.first_submit_offset_range_ms,
    s.first_submit_offset_ms || 9,
  );
  const preFetchTokenRange = parseRangeWithFallback(
    s.pre_fetch_token_range_ms,
    s.pre_fetch_token_ms || 1531,
  );

  s.login_lead_seconds = randIntUniqueInclusive(
    loginLeadRange[0],
    loginLeadRange[1],
    options.loginLeadUsedValues,
  );
  if (sliderLeadRange) {
    const sliderLeadMs = randIntUniqueInclusive(
      sliderLeadRange[0],
      sliderLeadRange[1],
      options.sliderLeadUsedValues,
    );
    s.slider_lead_seconds_range = [sliderLeadMs, sliderLeadMs];
  }
  s.fast_probe_start_offset_ms = randIntInclusive(probeStartRange[0], probeStartRange[1]);
  s.pre_fetch_token_ms = randIntUniqueInclusive(
    preFetchTokenRange[0],
    preFetchTokenRange[1],
    options.preFetchTokenUsedValues,
  );
  s.first_submit_offset_ms = randIntUniqueInclusive(
    firstSubmitRange[0],
    firstSubmitRange[1],
    options.firstSubmitUsedValues,
  );
  delete s.burst_offsets_ms;
  delete s.burst_jitter_range_ms;
  return s;
}

function buildDispatchPayloadForUser(env, school, user, options = {}) {
  const dispatchTarget = resolveDispatchTarget(school);
  const reserveDayOffset = resolveReserveDayOffset(env, school);
  const allowTestEndtimeOverride = options.allowTestEndtimeOverride === true;
  const activeTestEndtime = allowTestEndtimeOverride
    ? getActiveTestEndtimeOverride(school)
    : null;
  const userTopConfig = user?.user_top_config_enabled && user?.user_top_config
    ? user.user_top_config
    : {};
  const userEndtime = normalizeEndtimeHms(userTopConfig.endtime);
  const effectiveEndtime = activeTestEndtime?.endtime
    || userEndtime
    || resolveEffectiveEndtime(school, { allowTestEndtimeOverride: false });
  const effectiveTriggerTime = activeTestEndtime?.trigger_time
    || resolveEffectiveTriggerTime(school, { allowTestEndtimeOverride: false });
  const effectiveReserveDayOffset = activeTestEndtime
    ? activeTestEndtime.reserve_day_offset
    : reserveDayOffset;
  const slots = Array.isArray(user?.slots)
    ? user.slots.map(slot => {
        const nextSlot = { ...slot };
        const slotUseCustomDay = !!nextSlot.use_custom_day
          || (dispatchTarget === "server_relay" && isCustomDayTimes(nextSlot.times));
        if (slotUseCustomDay) {
          nextSlot.use_custom_day = true;
        }
        return nextSlot;
      })
    : user?.slots;
  const {
    user_top_config_enabled: _userTopConfigEnabled,
    user_top_config: _userTopConfig,
    ...dispatchUser
  } = user || {};
  const strategyOverrides = {};
  for (const field of [
    "pre_fetch_token_range_ms",
    "first_submit_offset_range_ms",
    "fast_probe_start_range_ms",
    "first_token_date_mode",
    "slider_lead_seconds_range",
    "mode",
  ]) {
    if (userTopConfig[field] !== undefined && userTopConfig[field] !== "") {
      strategyOverrides[field] = userTopConfig[field];
    }
  }
  strategyOverrides.mode = resolveUserTopModeForSchool(school, userEndtime, userTopConfig.mode);
  return {
    ...dispatchUser,
    ...(slots ? { slots } : {}),
    trigger_time: effectiveTriggerTime,
    trigger_time_source: activeTestEndtime?.trigger_time ? "test_override" : "formal",
    endtime: effectiveEndtime,
    endtime_source: activeTestEndtime
      ? "test_override"
      : (userEndtime ? "user_override" : "formal"),
    seat_api_mode: school.seat_api_mode || "seat",
    reserve_next_day: activeTestEndtime ? effectiveReserveDayOffset > 0 : school.reserve_next_day !== false,
    ...(effectiveReserveDayOffset !== null ? { reserve_day_offset: effectiveReserveDayOffset } : {}),
    enable_slider: !!school.enable_slider,
    enable_textclick: !!school.enable_textclick,
    enable_iconclick: !!school.enable_iconclick,
    iconclick_ocr_provider: normalizeIconclickOcrProvider(school.iconclick_ocr_provider),
    enable_rotate: !!school.enable_rotate,
    rotate_ocr_provider: normalizeRotateOcrProvider(school.rotate_ocr_provider),
    strategy: randomizeStrategy({ ...(school.strategy || {}), ...strategyOverrides }, {
      loginLeadUsedValues: options.loginLeadUsedValues,
      sliderLeadUsedValues: options.sliderLeadUsedValues,
      preFetchTokenUsedValues: options.preFetchTokenUsedValues,
      firstSubmitUsedValues: options.firstSubmitUsedValues,
    }),
  };
}

function chunkArray(arr, size) {
  const chunks = [];
  for (let i = 0; i < arr.length; i += size) {
    chunks.push(arr.slice(i, i + size));
  }
  return chunks;
}

function githubDispatchRequestByteLength(clientPayload) {
  const body = JSON.stringify({
    event_type: "reserve",
    client_payload: clientPayload,
  });
  return new TextEncoder().encode(body).length;
}

function githubDispatchPayloadPropertyCount(clientPayload) {
  return clientPayload && typeof clientPayload === "object"
    ? Object.keys(clientPayload).length
    : 0;
}

function fitGitHubDispatchPayloadProperties(payload) {
  const nextPayload = { ...(payload || {}) };
  if (githubDispatchPayloadPropertyCount(nextPayload) > GITHUB_DISPATCH_PAYLOAD_MAX_PROPERTIES) {
    delete nextPayload.batch_total;
  }
  return nextPayload;
}

function buildDispatchBatchPayload(school, dispatchTarget, serverMaxConcurrency, reserveDayOffset, users, batchIndex, batchTotal, serverUrl, serverApiKey, options = {}) {
  const dispatchId = options.dispatchId || [
    options.executionDate || beijingDate(),
    school.id || "school",
    String(batchIndex).padStart(2, "0"),
    generateId(),
  ].join("-");
  return fitGitHubDispatchPayloadProperties({
    dispatch_id: dispatchId,
    school_id: school.id,
    ...(dispatchTarget !== "server_relay" ? { school_name: school.name } : {}),
    ...(dispatchTarget !== "server_relay" ? { trigger_date: beijingDate() } : {}),
    batch_total: batchTotal,
    dispatch_target: dispatchTarget,
    server_max_concurrency: serverMaxConcurrency,
    ...(reserveDayOffset !== null ? { reserve_day_offset: reserveDayOffset } : {}),
    schedule_mapping: {
      enabled: scheduleUsesReserveDateStorage(school),
      day_offset: resolveScheduleReserveDayOffset(school),
    },
    ...(options.emergency ? { emergency: options.emergency } : {}),
    ...(options.dispatchContext ? { dispatch_context: options.dispatchContext } : {}),
    users,
    ...(dispatchTarget === "server_relay" ? { server_url: serverUrl } : {}),
    ...(serverApiKey ? { server_api_key: serverApiKey } : {}),
  });
}

function splitDispatchUsersByPayloadSize(school, dispatchTarget, serverMaxConcurrency, reserveDayOffset, users, maxUsersPerBatch, serverUrl, serverApiKey, options = {}) {
  const batches = [];
  let current = [];
  const safeMaxUsersPerBatch = Math.max(1, maxUsersPerBatch || 1);

  const payloadSizeFor = candidateUsers => githubDispatchRequestByteLength(
    buildDispatchBatchPayload(
      school,
      dispatchTarget,
      serverMaxConcurrency,
      reserveDayOffset,
      candidateUsers,
      1,
      1,
      serverUrl,
      serverApiKey,
      options,
    )
  );

  for (const user of users) {
    const candidate = current.concat([user]);
    const candidateBytes = payloadSizeFor(candidate);
    if (current.length > 0 && (candidate.length > safeMaxUsersPerBatch || candidateBytes > GITHUB_DISPATCH_PAYLOAD_LIMIT_BYTES)) {
      batches.push(current);
      current = [user];
    } else {
      current = candidate;
    }

    if (current.length === 1) {
      const singleBytes = payloadSizeFor(current);
      if (singleBytes > GITHUB_DISPATCH_PAYLOAD_LIMIT_BYTES) {
        console.warn(
          `Dispatch payload for school ${school.id} single user ${normalizeSecretText(user?.remark || user?.nickname || user?.username)} `
          + `is ${singleBytes} bytes, above ${GITHUB_DISPATCH_PAYLOAD_LIMIT_BYTES} bytes`
        );
      }
    }
  }
  if (current.length > 0) batches.push(current);
  return batches;
}

async function buildTodayDispatchUsers(KV, schoolId, school, today, schoolUsers = null, dateText = "") {
  const sourceUsers = Array.isArray(schoolUsers) ? schoolUsers : await getSchoolUsersSnapshot(KV, schoolId);
  const storedDay = storedScheduleDayForExecution(school, today);
  const users = [];
  for (const user of sourceUsers) {
    if (!user || user.status !== "active") continue;

    const daySchedule = user.schedule?.[storedDay];
    const activeSlots = getEnabledScheduleSlots(daySchedule);
    if (activeSlots.length === 0) continue;
    users.push({
      id: user.id,
      username: user.phone || user.username,
      password: user.password,
      remark: user.remark || user.username || user.phone,
      nickname: user.username,
      user_top_config_enabled: !!user.user_top_config_enabled,
      user_top_config: user.user_top_config || {},
      slots: activeSlots.map((s, slotIndex) => {
        const originalSlotIndex = Number.isInteger(s.__slotIndex) ? s.__slotIndex : slotIndex;
        return {
        roomid: s.roomid,
        seatid: parseSeatIdsRaw(s.seatid),
        times: s.times,
        seatPageId: s.seatPageId || "",
        fidEnc: school?.fidEnc || s.fidEnc || "",
        backupSeats: typeof s.backupSeats === "string" ? s.backupSeats : "",
        backupSlots: Array.isArray(s.backupSlots) ? s.backupSlots : [],
      };
      }),
    });
  }
  return users;
}

async function dispatchUsersInBatches(env, school, users, options = {}) {
  const dispatchToken = resolveGitHubToken(env, school);
  const dispatchTarget = resolveDispatchTarget(school);
  const needsServerDispatch = dispatchTarget === "server_relay" || dispatchTarget === "both";
  const serverUrl = needsServerDispatch ? normalizeSecretText(school?.server_url) : "";
  const serverApiKey = resolveServerApiKey(env, school);
  const serverMaxConcurrency = Math.max(
    1,
    parseInt(school?.server_max_concurrency, 10) || 13,
  );
  const reserveDayOffset = resolveReserveDayOffset(env, school);
  const buildOptions = options.dispatchContext
    ? { dispatchContext: options.dispatchContext }
    : {};
  const loginLeadUsedValues = new Set();
  const sliderLeadUsedValues = new Set();
  const preFetchTokenUsedValues = new Set();
  const firstSubmitUsedValues = new Set();
  const dispatchUsers = users.map(u => buildDispatchPayloadForUser(env, school, u, {
    allowTestEndtimeOverride: options.allowTestEndtimeOverride === true,
    loginLeadUsedValues,
    sliderLeadUsedValues,
    preFetchTokenUsedValues,
    firstSubmitUsedValues,
  }));
  const batchSize = dispatchTarget === "server_relay" ? serverMaxConcurrency : BATCH_SIZE;
  const batches = splitDispatchUsersByPayloadSize(
    school,
    dispatchTarget,
    serverMaxConcurrency,
    reserveDayOffset,
    dispatchUsers,
    batchSize,
    serverUrl,
    serverApiKey,
    buildOptions,
  );
  const verifiedGitHubRunIds = new Set();
  let okBatches = 0;
  const dispatchErrors = [];

  if ((dispatchTarget === "github" || dispatchTarget === "server_relay" || dispatchTarget === "both") && !dispatchToken) {
    console.log(`Dispatch skipped for school ${school.id}: missing GitHub token`);
    return { okBatches: 0, totalBatches: batches.length, error: "Missing GitHub token" };
  }
  if ((dispatchTarget === "server_relay" || dispatchTarget === "both") && !serverUrl) {
    console.log(`Dispatch skipped for school ${school.id}: missing server_url`);
    return { okBatches: 0, totalBatches: batches.length, error: "Missing server_url" };
  }

  for (let i = 0; i < batches.length; i++) {
    const payload = buildDispatchBatchPayload(
      school,
      dispatchTarget,
      serverMaxConcurrency,
      reserveDayOffset,
      batches[i],
      i + 1,
      batches.length,
      serverUrl,
      serverApiKey,
      buildOptions,
    );
    const payloadBytes = githubDispatchRequestByteLength(payload);
    const payloadProperties = githubDispatchPayloadPropertyCount(payload);

    let githubStatus = "skip";
    let serverStatus = "skip";
    let githubDetail = "";
    let serverDetail = "";
    let githubRunUrl = "";

    if (payloadBytes > GITHUB_DISPATCH_PAYLOAD_LIMIT_BYTES) {
      githubStatus = "fail";
      githubDetail = `payload too large: ${payloadBytes}/${GITHUB_DISPATCH_PAYLOAD_LIMIT_BYTES} bytes`;
    }
    if (payloadProperties > GITHUB_DISPATCH_PAYLOAD_MAX_PROPERTIES) {
      githubStatus = "fail";
      githubDetail = `too many client_payload properties: ${payloadProperties}/${GITHUB_DISPATCH_PAYLOAD_MAX_PROPERTIES}`;
    }

    if ((dispatchTarget === "github" || dispatchTarget === "both") && githubStatus !== "fail") {
      const githubResp = await dispatchGitHubVerifiedWithRetry(dispatchToken, school.repo, payload, {
        seenRunIds: verifiedGitHubRunIds,
      });
      githubStatus = githubResp.ok ? "ok" : "fail";
      githubRunUrl = githubResp.runUrl || "";
      if (!githubResp.ok) {
        const detailText = normalizeSecretText(githubResp.detail);
        githubDetail = detailText
          ? `${githubResp.status || 0}: ${detailText}`
          : String(githubResp.status || 0);
      }
    }
    if (dispatchTarget === "server_relay" && githubStatus !== "fail") {
      const githubResp = await dispatchGitHubVerifiedWithRetry(dispatchToken, school.repo, payload, {
        seenRunIds: verifiedGitHubRunIds,
      });
      serverStatus = githubResp.ok ? "ok" : "fail";
      githubRunUrl = githubResp.runUrl || "";
      if (!githubResp.ok) {
        const detailText = normalizeSecretText(githubResp.detail);
        serverDetail = detailText
          ? `via-github-relay, ${githubResp.status || 0}: ${detailText}`
          : `via-github-relay, ${String(githubResp.status || 0)}`;
      } else {
        serverDetail = "via-github-relay";
      }
    }
    if (dispatchTarget === "both") {
      const serverResp = await dispatchServerVerbose(serverUrl, serverApiKey, payload);
      serverStatus = serverResp.ok ? "ok" : "fail";
      if (!serverResp.ok) {
        const detailText = normalizeSecretText(serverResp.detail);
        serverDetail = detailText
          ? `${serverResp.status || 0}: ${detailText}`
          : String(serverResp.status || 0);
      }
    }

    const ok = githubStatus !== "fail" && serverStatus !== "fail";
    if (ok) {
      okBatches++;
    } else {
      const parts = [`batch ${i + 1}: github=${githubStatus}, server=${serverStatus}`];
      if (githubDetail) parts.push(`github_detail=${githubDetail}`);
      if (serverDetail) parts.push(`server_detail=${serverDetail}`);
      dispatchErrors.push(
        parts.join(", ")
      );
    }
    console.log(
      `Dispatch batch ${school.id} ${i + 1}/${batches.length}: ${ok ? "OK" : "FAIL"} `
      + `(target=${dispatchTarget}, github=${githubStatus}, server=${serverStatus}`
      + `, payload_bytes=${payloadBytes}/${GITHUB_DISPATCH_PAYLOAD_LIMIT_BYTES}`
      + `, payload_properties=${payloadProperties}/${GITHUB_DISPATCH_PAYLOAD_MAX_PROPERTIES}`
      + `${githubDetail ? `, github_detail=${githubDetail}` : ""}`
      + `${serverDetail ? `, server_detail=${serverDetail}` : ""})`
      + `${githubRunUrl ? ` run=${githubRunUrl}` : ""}`
    );
  }

  return {
    okBatches,
    totalBatches: batches.length,
    error: dispatchErrors.length ? dispatchErrors.join("; ") : "",
  };
}

function emergencySnapshotRecordKey(executionDate, schoolId) {
  return `${EMERGENCY_SNAPSHOT_RECORD_PREFIX}:${executionDate}:${schoolId}`;
}

async function saveEmergencySnapshotRecord(KV, key, record) {
  await KV.put(key, JSON.stringify(record), {
    expirationTtl: EMERGENCY_STAGE_RECORD_TTL_SECONDS,
  });
}

async function fetchGitHubWorkflowRun(token, repo, runId) {
  const res = await fetch(`https://api.github.com/repos/${repo}/actions/runs/${runId}`, {
    headers: githubApiHeaders(token),
  });
  const text = await res.text();
  let data = {};
  try {
    data = text ? JSON.parse(text) : {};
  } catch (_) {
    data = { raw: text };
  }
  if (!res.ok) {
    const detail = typeof data?.message === "string" ? data.message : text || `HTTP ${res.status}`;
    throw new Error(`workflow run ${runId} check failed: HTTP ${res.status}: ${detail}`);
  }
  return data;
}

function prepareEmergencyDispatchUsers(env, school, users) {
  const loginLeadUsedValues = new Set();
  const sliderLeadUsedValues = new Set();
  const preFetchTokenUsedValues = new Set();
  const firstSubmitUsedValues = new Set();
  return users.map(user => buildDispatchPayloadForUser(env, school, user, {
    allowTestEndtimeOverride: false,
    loginLeadUsedValues,
    sliderLeadUsedValues,
    preFetchTokenUsedValues,
    firstSubmitUsedValues,
  }));
}

async function dispatchEmergencySnapshotInBatches(env, school, preparedUsers, timing, options = {}) {
  const token = resolveGitHubToken(env, school);
  const serverUrl = normalizeSecretText(school?.server_url);
  const serverApiKey = resolveServerApiKey(env, school);
  const maxConcurrency = Math.max(1, parseInt(school?.server_max_concurrency, 10) || 13);
  const reserveDayOffset = resolveReserveDayOffset(env, school);
  if (!token) return { ok: false, error: "Missing GitHub token", runs: [] };
  if (!serverUrl) return { ok: false, error: "Missing server_url", runs: [] };

  const snapshotId = `${timing.executionDate}:${school.id}`;
  const operation = options.mode === "delete" ? "delete" : "stage";
  const emergency = {
    mode: operation,
    snapshot_id: snapshotId,
    school_name: school.name || "",
    execution_date: timing.executionDate,
    trigger_at: timing.triggerAt,
    target_at: timing.targetAt,
    fallback_at: timing.fallbackAt,
    fallback_lead_seconds: EMERGENCY_FALLBACK_LEAD_SECONDS,
  };
  const buildOptions = { emergency, executionDate: timing.executionDate };
  const batches = splitDispatchUsersByPayloadSize(
    school,
    "server_relay",
    maxConcurrency,
    reserveDayOffset,
    preparedUsers,
    maxConcurrency,
    serverUrl,
    serverApiKey,
    buildOptions,
  );
  const seenRunIds = new Set();
  const runs = [];
  const errors = [];

  for (let index = 0; index < batches.length; index++) {
    const batchEmergency = {
      ...emergency,
      batch_index: index + 1,
      batch_total: batches.length,
    };
    const payload = buildDispatchBatchPayload(
      school,
      "server_relay",
      maxConcurrency,
      reserveDayOffset,
      batches[index],
      index + 1,
      batches.length,
      serverUrl,
      serverApiKey,
      {
        emergency: batchEmergency,
        executionDate: timing.executionDate,
        dispatchId: `${operation}-${timing.executionDate}-${school.id}-${String(index + 1).padStart(2, "0")}`,
      },
    );
    // Keep staged users under emergency.users. An old server implementation
    // only understands top-level users and will safely reject this payload
    // instead of accidentally launching main.py two hours early.
    payload.emergency = { ...payload.emergency, users: payload.users };
    delete payload.users;
    const resp = await dispatchGitHubVerifiedWithRetry(token, school.repo, payload, {
      seenRunIds,
      eventType: "reserve",
    });
    if (!resp.ok) {
      errors.push(`batch ${index + 1}: ${resp.status || 0} ${normalizeSecretText(resp.detail)}`.trim());
      continue;
    }
    runs.push({
      batch_index: index + 1,
      run_id: String(resp.runId || ""),
      run_url: resp.runUrl || "",
      created_at: resp.runCreatedAt || "",
    });
  }
  return {
    ok: runs.length === batches.length,
    totalBatches: batches.length,
    runs,
    error: errors.join("; "),
  };
}

async function inspectEmergencySnapshotRuns(token, repo, record) {
  const runs = Array.isArray(record?.runs) ? record.runs : [];
  if (!runs.length || runs.some(item => !item?.run_id)) {
    return { state: "failed", detail: "missing GitHub workflow run id" };
  }
  const details = await Promise.all(
    runs.map(async item => ({ ...item, run: await fetchGitHubWorkflowRun(token, repo, item.run_id) })),
  );
  if (details.every(item => item.run?.status === "completed" && item.run?.conclusion === "success")) {
    return { state: "stored", details };
  }
  if (details.some(item => item.run?.status === "completed" && item.run?.conclusion !== "success")) {
    return { state: "failed", details, detail: "one or more stage workflows failed" };
  }
  return { state: "pending", details };
}

async function handleEmergencySnapshotScheduled(env, options = {}) {
  const nowMs = Date.now();
  const force = options.force === true;
  const selectedSchoolIds = Array.isArray(options.schoolIds) && options.schoolIds.length
    ? new Set(options.schoolIds.map(value => String(value)))
    : null;
  const index = await getEmergencyScheduleIndex(env.SEAT_KV);
  for (const entry of index.schools || []) {
    if (!entry?.enabled || !entry.school_id) continue;
    if (selectedSchoolIds && !selectedSchoolIds.has(String(entry.school_id))) continue;
    const triggerAtMs = nextBeijingTimeOccurrence(entry.trigger_time, nowMs, false);
    if (triggerAtMs === null) continue;
    const stageOffsetMinutes = Number(entry.stage_offset_minutes);
    const stageAtMs = triggerAtMs - EMERGENCY_SNAPSHOT_LEAD_MS
      + (Number.isFinite(stageOffsetMinutes) ? stageOffsetMinutes : emergencyStageOffsetMinutes(entry.school_id)) * 60 * 1000;
    if (!force && (nowMs < stageAtMs || nowMs >= triggerAtMs)) continue;

    const school = await getSchool(env.SEAT_KV, entry.school_id);
    if (!school) continue;
    const timing = emergencyTimingForSchool(school, nowMs);
    if (!timing || (!force && (nowMs < timing.stageAtMs || nowMs >= timing.triggerAtMs))) continue;
    const recordKey = emergencySnapshotRecordKey(timing.executionDate, school.id);
    let record = JSON.parse((await env.SEAT_KV.get(recordKey)) || "null");
    if (record?.status === "stored") {
      await refreshChangedUsersFromKv(env, school, record);
      continue;
    }

    const token = resolveGitHubToken(env, school);
    if (record?.status === "github_dispatched" && token) {
      try {
        const inspection = await inspectEmergencySnapshotRuns(token, school.repo, record);
        if (inspection.state === "stored") {
          record = { ...record, status: "stored", stored_at: new Date().toISOString() };
          await saveEmergencySnapshotRecord(env.SEAT_KV, recordKey, record);
          console.log(`Emergency snapshot stored: school=${school.id} date=${timing.executionDate}`);
          continue;
        }
        const lastAttemptMs = Date.parse(record.last_attempt_at || "");
        if (!force && inspection.state === "pending" && Number.isFinite(lastAttemptMs)
          && nowMs - lastAttemptMs < EMERGENCY_STAGE_RETRY_MS) {
          continue;
        }
        record = { ...record, status: "retry_pending", last_error: inspection.detail || inspection.state };
      } catch (error) {
        const lastAttemptMs = Date.parse(record.last_attempt_at || "");
        if (!force && Number.isFinite(lastAttemptMs) && nowMs - lastAttemptMs < EMERGENCY_STAGE_RETRY_MS) continue;
        record = { ...record, status: "retry_pending", last_error: error.message || String(error) };
      }
    }

    let preparedUsers = Array.isArray(record?.users) ? record.users : null;
    if (!preparedUsers) {
      const users = await buildTodayDispatchUsers(
        env.SEAT_KV,
        school.id,
        school,
        timing.executionDay,
        null,
        timing.executionDate,
      );
      preparedUsers = prepareEmergencyDispatchUsers(env, school, users);
      record = {
        snapshot_id: `${timing.executionDate}:${school.id}`,
        school_id: school.id,
        school_name: school.name,
        execution_date: timing.executionDate,
        trigger_at: timing.triggerAt,
        target_at: timing.targetAt,
        fallback_at: timing.fallbackAt,
        stage_offset_minutes: timing.stageOffsetMinutes,
        created_at: new Date().toISOString(),
        status: "prepared",
        attempts: 0,
        users: preparedUsers,
      };
      await saveEmergencySnapshotRecord(env.SEAT_KV, recordKey, record);
    }

    if (preparedUsers.length === 0) {
      await saveEmergencySnapshotRecord(env.SEAT_KV, recordKey, {
        ...record,
        status: "stored",
        stored_at: new Date().toISOString(),
        empty: true,
      });
      continue;
    }

    const result = await dispatchEmergencySnapshotInBatches(env, school, preparedUsers, timing);
    await saveEmergencySnapshotRecord(env.SEAT_KV, recordKey, {
      ...record,
      status: result.ok ? "github_dispatched" : "retry_pending",
      attempts: Number(record.attempts || 0) + 1,
      last_attempt_at: new Date().toISOString(),
      runs: result.runs,
      total_batches: result.totalBatches,
      last_error: result.error || "",
    });
    console.log(
      `Emergency snapshot dispatch school=${school.id} date=${timing.executionDate} `
      + `batches=${result.runs.length}/${result.totalBatches} ok=${result.ok}`,
    );
  }
}

async function refreshEmergencySnapshotForChangedUser(env, school, user) {
  if (!school?.id || !user?.id) return { ok: false, skipped: true, reason: "missing school/user id" };
  const nowMs = Date.now();
  const timing = emergencyTimingForSchool(school, nowMs);
  if (!timing) return { ok: false, skipped: true, reason: "missing emergency timing" };
  if (
    nowMs < timing.targetAtMs - EMERGENCY_SNAPSHOT_LEAD_MS
    || nowMs >= timing.targetAtMs
  ) {
    return { ok: false, skipped: true, reason: "outside refresh window" };
  }

  const recordKey = emergencySnapshotRecordKey(timing.executionDate, school.id);
  const record = JSON.parse((await env.SEAT_KV.get(recordKey)) || "null");
  if (!record || record.status !== "stored" || !Array.isArray(record.users)) {
    return { ok: false, skipped: true, reason: "emergency snapshot not stored" };
  }
  const existingIndex = record.users.findIndex(item => String(item?.id || "") === String(user.id));
  if (existingIndex < 0) {
    return { ok: false, skipped: true, reason: "user not in emergency snapshot" };
  }

  const dispatchUsers = await buildTodayDispatchUsers(
    env.SEAT_KV,
    school.id,
    school,
    timing.executionDay,
    [user],
    timing.executionDate,
  );
  const preparedUsers = prepareEmergencyDispatchUsers(env, school, dispatchUsers);
  if (!preparedUsers.length) {
    if (user.status !== "paused") {
      return { ok: false, skipped: true, reason: "user not active for execution day" };
    }
    const deleteUser = {
      id: user.id,
      user_id: user.id,
      username: user.username || "",
      phone: user.phone || "",
      status: user.status || "",
      updatedAt: user.updatedAt || new Date().toISOString(),
    };
    const result = await dispatchEmergencySnapshotInBatches(
      env,
      school,
      [deleteUser],
      timing,
      { mode: "delete" },
    );
    const nextUsers = record.users.slice();
    nextUsers[existingIndex] = { ...record.users[existingIndex], ...deleteUser };
    await saveEmergencySnapshotRecord(env.SEAT_KV, recordKey, {
      ...record,
      users: result.ok ? nextUsers : record.users,
      last_user_refresh_at: new Date().toISOString(),
      last_user_refresh_id: String(user.id),
      last_user_refresh_ok: !!result.ok,
      last_user_refresh_error: result.error || "",
    });
    return result;
  }
  if (nowMs >= timing.targetAtMs - EMERGENCY_USER_REFRESH_CUTOFF_MS) {
    return { ok: false, skipped: true, reason: "inside active-user refresh cutoff" };
  }

  const nextUsers = record.users.slice();
  nextUsers[existingIndex] = preparedUsers[0];
  const result = await dispatchEmergencySnapshotInBatches(env, school, preparedUsers, timing);
  await saveEmergencySnapshotRecord(env.SEAT_KV, recordKey, {
    ...record,
    users: result.ok ? nextUsers : record.users,
    last_user_refresh_at: new Date().toISOString(),
    last_user_refresh_id: String(user.id),
    last_user_refresh_ok: !!result.ok,
    last_user_refresh_error: result.error || "",
  });
  return result;
}

async function refreshChangedUsersFromKv(env, school, record) {
  const currentUsers = await getSchoolUsersSnapshot(env.SEAT_KV, school.id);
  const stagedById = new Map(
    (record.users || []).map(user => [String(user?.id || ""), user]),
  );
  let refreshed = 0;
  for (const user of currentUsers) {
    const staged = stagedById.get(String(user?.id || ""));
    if (!staged) continue;
    const currentUpdatedAt = Date.parse(user?.updatedAt || "");
    const stagedUpdatedAt = Date.parse(staged?.updatedAt || record.created_at || "");
    if (!Number.isFinite(currentUpdatedAt)
      || (Number.isFinite(stagedUpdatedAt) && currentUpdatedAt <= stagedUpdatedAt)) {
      continue;
    }
    const result = await refreshEmergencySnapshotForChangedUser(env, school, user);
    if (result.ok) refreshed++;
  }
  return refreshed;
}

function parseSeatIdsRaw(seatidRaw) {
  if (Array.isArray(seatidRaw)) {
    return seatidRaw.map(v => String(v || "").trim()).filter(Boolean);
  }
  return String(seatidRaw || "")
    .split(",")
    .map(v => v.trim())
    .filter(Boolean);
}

const DATE_TEXT_RE = /^\d{4}-\d{2}-\d{2}$/;
const DATE_PAIR_TEXT_RE = /^\s*(\d{4}-\d{2}-\d{2})\s*[,，]\s*(\d{4}-\d{2}-\d{2})\s*$/;

function parseTimesInput(rawTimes) {
  if (Array.isArray(rawTimes) && rawTimes.length >= 2) {
    return [
      String(rawTimes[0] || "").trim(),
      String(rawTimes[1] || "").trim(),
    ];
  }
  const text = String(rawTimes || "").trim();
  if (!text) return ["", ""];

  const datePairMatch = text.match(DATE_PAIR_TEXT_RE);
  if (datePairMatch) {
    return [datePairMatch[1], datePairMatch[2]];
  }

  const parts = text.split(/-|~|至/).map(s => s.trim()).filter(Boolean);
  if (parts.length >= 2) {
    return [parts[0], parts[1]];
  }
  return [text, ""];
}

function isCustomDayTimes(rawTimes) {
  const [start, end] = parseTimesInput(rawTimes);
  return DATE_TEXT_RE.test(start) && DATE_TEXT_RE.test(end);
}

function normalizeTimesLabel(rawTimes) {
  const [start, end] = parseTimesInput(rawTimes);
  if (start && end) {
    return isCustomDayTimes([start, end]) ? `${start}，${end}` : `${start}-${end}`;
  }
  return String(rawTimes || "").trim();
}

function parseHmsToSeconds(hms) {
  const text = String(hms || "").trim();
  const match = text.match(/^(\d{1,2}):(\d{2})(?::(\d{2}))?$/);
  if (!match) return null;

  const hour = parseInt(match[1], 10);
  const minute = parseInt(match[2], 10);
  const second = parseInt(match[3] || "0", 10);
  if (hour < 0 || hour > 23 || minute < 0 || minute > 59 || second < 0 || second > 59) {
    return null;
  }
  return hour * 3600 + minute * 60 + second;
}

function parseTimesRange(rawTimes) {
  const label = normalizeTimesLabel(rawTimes);
  const [start, end] = parseTimesInput(rawTimes);
  if (!start || !end) {
    return { label, startSec: null, endSec: null, valid: false };
  }

  const startSec = parseHmsToSeconds(start);
  const endSec = parseHmsToSeconds(end);
  if (startSec === null || endSec === null || endSec <= startSec) {
    return { label, startSec: null, endSec: null, valid: false };
  }
  return { label, startSec, endSec, valid: true };
}

function isTimeOverlapped(a, b) {
  if (a.valid && b.valid) {
    return a.startSec < b.endSec && b.startSec < a.endSec;
  }
  return a.label && b.label && a.label === b.label;
}

function collectScheduleSeatEntries(schedule) {
  const days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
  const entries = [];

  for (const day of days) {
    const dayCfg = schedule && schedule[day];
    if (!dayCfg || !dayCfg.enabled) continue;

    const rawSlots = Array.isArray(dayCfg.slots)
      ? dayCfg.slots
      : [{
          roomid: dayCfg.roomid,
          seatid: dayCfg.seatid,
          times: dayCfg.times,
          seatPageId: dayCfg.seatPageId,
          fidEnc: dayCfg.fidEnc,
        }];

    for (const slot of rawSlots) {
      if (!slot || typeof slot !== "object") continue;
      const roomid = String(slot.roomid || "").trim();
      const seatList = parseSeatIdsRaw(slot.seatid);
      const times = parseTimesRange(slot.times);
      if (!roomid || !times.label || seatList.length === 0) continue;

      for (const seat of seatList) {
        entries.push({
          day,
          roomid,
          seat,
          times,
        });
      }
    }
  }

  return entries;
}

function buildSeatConflictKey(entry) {
  return `${entry.day}|${entry.roomid}|${entry.seat}`;
}

function dayNameZh(day) {
  const map = {
    Monday: "周一",
    Tuesday: "周二",
    Wednesday: "周三",
    Thursday: "周四",
    Friday: "周五",
    Saturday: "周六",
    Sunday: "周日",
  };
  return map[day] || day;
}

async function getConflictScopeUsers(KV, schoolId, school = null) {
  const targetSchool = school || await getSchool(KV, schoolId);
  if (!targetSchool) return [];
  if (!shouldCheckSeatConflicts(targetSchool)) return [];

  const schools = await getSchoolsSnapshot(KV);
  const targetGroup = getSchoolConflictGroup(targetSchool);
  const relatedSchools = schools.filter(item => {
    if (!item || !item.id) return false;
    return getSchoolConflictGroup(item) === targetGroup;
  });

  const usersBySchool = await Promise.all(
    relatedSchools.map(async item => {
      const users = await getSchoolUsersSnapshot(KV, item.id);
      return users.map(user => ({
        ...user,
        schedule: scheduleForConflict(item, user.schedule || {}),
        __schoolId: item.id,
        __schoolName: item.name || item.id,
      }));
    })
  );

  return usersBySchool.flat();
}

async function findSeatConflicts(KV, schoolId, schedule, excludeIdentity = {}, schoolUsers = null) {
  const incomingEntries = collectScheduleSeatEntries(schedule);
  if (incomingEntries.length === 0) return [];

  const sourceUsers = Array.isArray(schoolUsers) ? schoolUsers : await getConflictScopeUsers(KV, schoolId);
  const existingByKey = new Map();
  const conflicts = [];
  const seenConflictKeys = new Set();
  const excludeUserId = String(excludeIdentity?.userId || "").trim();
  const excludePhone = String(excludeIdentity?.phone || "").trim();

  const pushConflict = (incoming, existing) => {
    const dedupeKey = `${buildSeatConflictKey(incoming)}|${existing.occupiedUserId || existing.occupiedBy || ""}`;
    if (seenConflictKeys.has(dedupeKey)) return;
    seenConflictKeys.add(dedupeKey);
    conflicts.push({
      day: incoming.day,
      roomid: incoming.roomid,
      seatid: incoming.seat,
      times: incoming.times.label,
      occupiedBy: existing.occupiedBy,
      occupiedUserId: existing.occupiedUserId || "",
      occupiedTimes: existing.occupiedTimes || "",
      occupiedSchoolId: existing.occupiedSchoolId || schoolId,
      occupiedSchoolName: existing.occupiedSchoolName || "",
    });
  };

  for (const existingUser of sourceUsers) {
    const uid = existingUser && existingUser.id;
    if (!uid) continue;
    if (excludeUserId && uid === excludeUserId) continue;
    if (!existingUser) continue;
    const existingPhone = String(existingUser.phone || "").trim();
    if (excludePhone && existingPhone && existingPhone === excludePhone) continue;

    const owner = String(existingUser.username || "").trim() || "未填写昵称";
    const existingEntries = collectScheduleSeatEntries(existingUser.schedule || {});
    for (const entry of existingEntries) {
      const key = buildSeatConflictKey(entry);
      const item = {
        ...entry,
        userId: uid,
        owner,
        schoolId: existingUser.__schoolId || schoolId,
        schoolName: existingUser.__schoolName || "",
      };
      const arr = existingByKey.get(key) || [];
      arr.push(item);
      existingByKey.set(key, arr);
    }
  }

  const incomingByKey = new Map();
  for (const incoming of incomingEntries) {
    const key = buildSeatConflictKey(incoming);
    if (incomingByKey.has(key)) {
      // 当前提交里自己重复填写了同一天/同房间/同座位时，不作为“冲突用户”报错。
      // 这里保留首条记录继续参与和其他用户的冲突判断，避免出现
      // “与昵称‘当前提交配置’冲突” 这种误导性提示。
      continue;
    }
    incomingByKey.set(key, incoming);

    const occupied = existingByKey.get(key) || [];
    for (const existing of occupied) {
      // 只要同一天、同房间、同座位就算冲突，不判断时间段
      pushConflict(incoming, {
        occupiedBy: existing.owner,
        occupiedUserId: existing.userId,
        occupiedTimes: existing.times.label,
        occupiedSchoolId: existing.schoolId,
        occupiedSchoolName: existing.schoolName,
      });
      break;
    }
  }

  return conflicts;
}

function buildSeatConflictError(conflicts) {
  if (!conflicts.length) return "";
  const first = conflicts[0];
  const prefix = `${dayNameZh(first.day)} ${first.roomid}/${first.seatid}`;
  const owner = first.occupiedBy || "未填写昵称";
  const suffix = conflicts.length > 1 ? `，另有 ${conflicts.length - 1} 处重复` : "";
  return `座位冲突：${prefix} 与昵称“${owner}”冲突${suffix}`;
}

// ─── Scheduled Handler ───

async function handleScheduled(env) {
  const nowSeconds = beijingSecondsOfDay();
  const nowTimestampMs = Date.now();
  const schools = await getSchoolsSnapshot(env.SEAT_KV);

  for (const school of schools) {
    if (!school || !shouldScheduledTriggerSchool(school, nowSeconds)) continue;
    const useTestTimeForScheduledDispatch = !isFormalScheduleWindowActive(school, nowSeconds);
    const activeTestOverride = useTestTimeForScheduledDispatch
      ? getActiveTestEndtimeOverride(school, nowTimestampMs)
      : null;
    const activeTestEnabledMs = Date.parse(activeTestOverride?.enabled_at || "");
    const fallbackRecordScope = activeTestOverride?.enabled_at
      ? `test-${Number.isFinite(activeTestEnabledMs) ? activeTestEnabledMs : Date.parse(activeTestOverride.expires_at)}`
      : formalTriggerScope(school);
    const scheduleContext = getActiveScheduleContextForSchool(school, nowSeconds, nowTimestampMs);
    const today = scheduleContext.day;
    const todayDate = scheduleContext.date;

    const existingRecord = await getFallbackTriggerRecord(env.SEAT_KV, todayDate, school.id, fallbackRecordScope);
    if (isScheduledTriggerRecord(existingRecord)) continue;
    if (isFreshInProgressTriggerRecord(existingRecord, nowTimestampMs)) {
      console.log(`Scheduled dispatch school ${school.id} skipped: dispatch already in progress`);
      continue;
    }
    await saveFallbackTriggerRecord(env.SEAT_KV, todayDate, school.id, {
      source: "tongyi",
      mode: "in_progress",
      schedule_scope: fallbackRecordScope || "formal",
      at: new Date().toISOString(),
      beijing_time: beijingHHMM(),
      schoolId: school.id,
      schoolName: school.name,
      triggerDate: todayDate,
      detail: "tongyi scheduled dispatch is running and waiting for GitHub Actions confirmation",
    }, fallbackRecordScope);

    const users = await buildTodayDispatchUsers(env.SEAT_KV, school.id, school, today, null, todayDate);
    if (users.length === 0) {
      await saveFallbackTriggerRecord(env.SEAT_KV, todayDate, school.id, {
        source: "tongyi",
        mode: "scheduled",
        schedule_scope: fallbackRecordScope || "formal",
        at: new Date().toISOString(),
        beijing_time: beijingHHMM(),
        schoolId: school.id,
        schoolName: school.name,
        triggeredUsers: 0,
        okBatches: 0,
        totalBatches: 0,
      }, fallbackRecordScope);
      continue;
    }
    const result = await dispatchUsersInBatches(env, school, users, {
      allowTestEndtimeOverride: useTestTimeForScheduledDispatch,
      dispatchContext: {
        source: "tongyi_scheduled",
        scope: "school",
      },
    });
    if (result.error) {
      console.log(`Scheduled dispatch school ${school.id} failed: ${result.error}`);
      continue;
    }
    await saveFallbackTriggerRecord(env.SEAT_KV, todayDate, school.id, {
      source: "tongyi",
      mode: "scheduled",
      schedule_scope: fallbackRecordScope || "formal",
      at: new Date().toISOString(),
      beijing_time: beijingHHMM(),
      schoolId: school.id,
      schoolName: school.name,
      triggeredUsers: users.length,
      okBatches: result.okBatches,
      totalBatches: result.totalBatches,
    }, fallbackRecordScope);
    console.log(
      `Scheduled dispatch school ${school.id}: users=${users.length}, batches=${result.okBatches}/${result.totalBatches}`
    );
  }
}

// ─── API Handler ───

async function handleAPI(request, env, path, ctx = null) {
  const KV = env.SEAT_KV;
  const method = request.method;

  // GET /api/status
  if (method === "GET" && path === "/api/status") {
    const schools = await getSchoolsSnapshot(KV);
    const lastHeartbeatTs = await getHeartbeatTimestamp(KV);
    const lastHeartbeatMinuteSlot = await getHeartbeatMinuteSlot(KV);
    const heartbeatAgeMs = lastHeartbeatTs === null ? null : Math.max(0, Date.now() - lastHeartbeatTs);
    return jsonResp({
      ok: true,
      worker: "tongyi",
      now: new Date().toISOString(),
      beijing_date: beijingDate(),
      beijing_time: beijingHHMM(),
      beijing_date_hour: beijingDateHour(),
      day_of_week: beijingDayOfWeek(),
      schoolCount: schools.length,
      heartbeat: {
        key: HEARTBEAT_LAST_TS_KEY,
        minuteKey: HEARTBEAT_LAST_MINUTE_KEY,
        lastTs: lastHeartbeatTs,
        lastMinuteSlot: lastHeartbeatMinuteSlot,
        ageMs: heartbeatAgeMs,
      },
    });
  }

  // GET /api/users/search?q=phone-or-username
  if (method === "GET" && path === "/api/users/search") {
    const url = new URL(request.url);
    const query = normalizeSearchText(url.searchParams.get("q"));
    if (!query) return jsonResp({ ok: true, query: "", results: [] });
    if (query.length < 2) {
      return jsonResp({ error: "请至少输入 2 个字符" }, 400);
    }

    const schools = await getSchoolsSnapshot(KV);
    const results = [];
    for (const school of schools) {
      if (!school?.id) continue;
      const schoolUsers = await getSchoolUsersSnapshot(KV, school.id);
      const matchedUsers = schoolUsers
        .filter(user => userMatchesQuery(user, query))
        .map(userSearchSummary)
        .slice(0, 20);
      if (!matchedUsers.length) continue;
      results.push({
        school: sanitizeSchoolForClient(school),
        users: matchedUsers,
        matchCount: matchedUsers.length,
      });
    }
    return jsonResp({ ok: true, query, results });
  }

  // POST /api/emergency-snapshot/dispatch-all
  // Manually stage the next daily emergency snapshot for every eligible
  // server_relay/both school. The work continues after the HTTP response.
  if (method === "POST" && path === "/api/emergency-snapshot/dispatch-all") {
    if (!ctx || typeof ctx.waitUntil !== "function") {
      return jsonResp({ error: "Execution context unavailable" }, 503);
    }
    const index = await getEmergencyScheduleIndex(KV);
    const eligibleSchools = (index.schools || []).filter(item => item?.enabled);
    const url = new URL(request.url);
    const selectedSchoolId = normalizeSecretText(url.searchParams.get("schoolId"));
    const selectedSchools = selectedSchoolId
      ? eligibleSchools.filter(item => String(item.school_id) === selectedSchoolId)
      : eligibleSchools;
    if (url.searchParams.get("dryRun") === "1") {
      return jsonResp({
        ok: true,
        dryRun: true,
        eligibleSchoolCount: eligibleSchools.length,
        eligibleSchoolIds: eligibleSchools.map(item => String(item.school_id)),
      });
    }
    if (selectedSchoolId && selectedSchools.length === 0) {
      return jsonResp({ error: "School is not eligible for emergency snapshot dispatch" }, 404);
    }
    ctx.waitUntil(handleEmergencySnapshotScheduled(env, {
      force: true,
      schoolIds: selectedSchools.map(item => String(item.school_id)),
    }));
    return jsonResp({
      ok: true,
      accepted: true,
      eligibleSchoolCount: selectedSchools.length,
      eligibleSchoolIds: selectedSchools.map(item => String(item.school_id)),
      message: "Emergency snapshot dispatch started in background",
      requestedAt: new Date().toISOString(),
    }, 202);
  }

  // GET /api/schools
  if (method === "GET" && path === "/api/schools") {
    const schools = await getSchoolsSnapshot(KV);
    return jsonResp(
      { schools: getSortedSchoolsForDisplay(schools).map(sanitizeSchoolForClient) },
      200,
      { "Cache-Control": "private, max-age=5" }
    );
  }

  // POST /api/school
  if (method === "POST" && path === "/api/school") {
    const body = await request.json();
    const id = body.id || generateId();
    const name = body.name || `学校 ${id}`;
    const school = defaultSchool(id, name);
    if (body.conflict_group !== undefined) {
      school.conflict_group = normalizeSecretText(body.conflict_group);
    }
    if (body.repo) school.repo = body.repo;
    if (body.seat_api_mode !== undefined) {
      school.seat_api_mode = normalizeSecretText(body.seat_api_mode).toLowerCase();
    }
    if (body.reserve_next_day !== undefined) school.reserve_next_day = !!body.reserve_next_day;
    if (body.reserve_day_offset !== undefined) school.reserve_day_offset = parseReserveDayOffset(body.reserve_day_offset);
    if (body.schedule_store_by_reserve_date !== undefined) {
      school.schedule_store_by_reserve_date = body.schedule_store_by_reserve_date === true;
    }
    if (body.ignore_seat_conflicts !== undefined) school.ignore_seat_conflicts = !!body.ignore_seat_conflicts;
    if (body.enable_slider !== undefined) school.enable_slider = !!body.enable_slider;
    if (body.enable_textclick !== undefined) school.enable_textclick = !!body.enable_textclick;
    if (body.enable_iconclick !== undefined) school.enable_iconclick = !!body.enable_iconclick;
    if (body.iconclick_ocr_provider !== undefined) {
      school.iconclick_ocr_provider = normalizeIconclickOcrProvider(body.iconclick_ocr_provider);
    }
    if (body.enable_rotate !== undefined) school.enable_rotate = !!body.enable_rotate;
    if (body.rotate_ocr_provider !== undefined) {
      school.rotate_ocr_provider = normalizeRotateOcrProvider(body.rotate_ocr_provider);
    }
    if (body.dispatch_target !== undefined) {
      school.dispatch_target = resolveDispatchTarget(body);
    }
    if (body.github_token_key !== undefined) {
      school.github_token_key = normalizeSecretText(body.github_token_key).toLowerCase();
    }
    if (body.github_token !== undefined) school.github_token = normalizeSecretText(body.github_token);
    if (body.server_url !== undefined) school.server_url = normalizeSecretText(body.server_url);
    if (body.server_api_key !== undefined) school.server_api_key = normalizeSecretText(body.server_api_key);
    if (body.server_max_concurrency !== undefined) {
      school.server_max_concurrency = Math.max(1, parseInt(body.server_max_concurrency, 10) || 13);
    }
    if (body.trigger_time) school.trigger_time = normalizeTriggerTimeHm(body.trigger_time) || normalizeSecretText(body.trigger_time);
    if (body.endtime) school.endtime = normalizeEndtimeHms(body.endtime) || normalizeSecretText(body.endtime);
    const timeWindowError = validateFormalTimeWindow(school.trigger_time, school.endtime);
    if (timeWindowError) return jsonResp({ error: timeWindowError }, 400);
    if (body.fidEnc !== undefined) school.fidEnc = body.fidEnc;
    if (body.plan_extract_max_hours !== undefined) {
      school.plan_extract_max_hours = normalizePlanExtractMaxHours(body.plan_extract_max_hours);
    }
    if (body.plan_extract_seat_page_id !== undefined) {
      school.plan_extract_seat_page_id = normalizeSecretText(body.plan_extract_seat_page_id);
    }
    let serverCheck = null;
    if (["server_relay", "both"].includes(resolveDispatchTarget(school))) {
      serverCheck = await probeServerConnection(school.server_url, resolveServerApiKey(env, school));
    }
    await saveSchool(KV, school);
    const schools = await getSchools(KV);
    if (!schools.includes(id)) {
      schools.push(id);
      await saveSchools(KV, schools);
      await saveSchoolUsersSnapshot(KV, id, []);
    }
    return jsonResp({ ok: true, school: sanitizeSchoolForClient(school), serverCheck });
  }

  // GET /api/school/:id
  const schoolMatch = path.match(/^\/api\/school\/([^/]+)$/);
  if (method === "GET" && schoolMatch) {
    const school = await getSchool(KV, schoolMatch[1]);
    if (!school) return jsonResp({ error: "School not found" }, 404);
    const schoolUsers = await getSchoolUsersSnapshot(KV, schoolMatch[1]);
    return jsonResp({ school: sanitizeSchoolForClient(school), userCount: schoolUsers.length });
  }

  const serverProbeMatch = path.match(/^\/api\/school\/([^/]+)\/server-probe$/);
  if (method === "GET" && serverProbeMatch) {
    const school = await getSchool(KV, serverProbeMatch[1]);
    if (!school) return jsonResp({ error: "School not found" }, 404);
    const result = await probeServerConnection(
      school.server_url,
      resolveServerApiKey(env, school),
    );
    return jsonResp({ ok: true, probe: result });
  }

  // PUT /api/school/:id
  if (method === "PUT" && schoolMatch) {
    const school = await getSchool(KV, schoolMatch[1]);
    if (!school) return jsonResp({ error: "School not found" }, 404);
    const body = await request.json();
    const previousServerUrl = normalizeSecretText(school.server_url);
    const previousServerApiKey = normalizeSecretText(school.server_api_key);
    if (body.github_token !== undefined) {
      body.github_token = normalizeSecretText(body.github_token);
    }
    if (body.github_token_key !== undefined) {
      body.github_token_key = normalizeSecretText(body.github_token_key).toLowerCase();
    }
    if (body.seat_api_mode !== undefined) {
      body.seat_api_mode = normalizeSecretText(body.seat_api_mode).toLowerCase();
    }
    if (body.reserve_next_day !== undefined) body.reserve_next_day = !!body.reserve_next_day;
    if (body.reserve_day_offset !== undefined) body.reserve_day_offset = parseReserveDayOffset(body.reserve_day_offset);
    if (body.schedule_store_by_reserve_date !== undefined) {
      body.schedule_store_by_reserve_date = body.schedule_store_by_reserve_date === true;
    }
    if (body.ignore_seat_conflicts !== undefined) body.ignore_seat_conflicts = !!body.ignore_seat_conflicts;
    if (body.enable_slider !== undefined) body.enable_slider = !!body.enable_slider;
    if (body.enable_textclick !== undefined) body.enable_textclick = !!body.enable_textclick;
    if (body.enable_iconclick !== undefined) body.enable_iconclick = !!body.enable_iconclick;
    if (body.iconclick_ocr_provider !== undefined) {
      body.iconclick_ocr_provider = normalizeIconclickOcrProvider(body.iconclick_ocr_provider);
    }
    if (body.enable_rotate !== undefined) body.enable_rotate = !!body.enable_rotate;
    if (body.rotate_ocr_provider !== undefined) {
      body.rotate_ocr_provider = normalizeRotateOcrProvider(body.rotate_ocr_provider);
    }
    if (body.dispatch_target !== undefined) {
      body.dispatch_target = resolveDispatchTarget(body);
    }
    if (body.conflict_group !== undefined) {
      body.conflict_group = normalizeSecretText(body.conflict_group);
    }
    if (body.server_url !== undefined) {
      body.server_url = normalizeSecretText(body.server_url);
    }
    if (body.server_api_key !== undefined) {
      body.server_api_key = normalizeSecretText(body.server_api_key);
    }
    if (body.server_max_concurrency !== undefined) {
      body.server_max_concurrency = Math.max(1, parseInt(body.server_max_concurrency, 10) || 13);
    }
    if (body.trigger_time !== undefined) {
      body.trigger_time = normalizeTriggerTimeHm(body.trigger_time) || normalizeSecretText(body.trigger_time);
    }
    if (body.endtime !== undefined) {
      body.endtime = normalizeEndtimeHms(body.endtime) || normalizeSecretText(body.endtime);
    }
    if (body.plan_extract_max_hours !== undefined) {
      body.plan_extract_max_hours = normalizePlanExtractMaxHours(body.plan_extract_max_hours);
    }
    if (body.plan_extract_seat_page_id !== undefined) {
      body.plan_extract_seat_page_id = normalizeSecretText(body.plan_extract_seat_page_id);
    }
    if (body.notes !== undefined) body.notes = normalizeSchoolNotes(body.notes);
    const nextSchool = { ...school, ...body, id: school.id };
    applySchoolFormalTimeGuard(nextSchool, body);
    const timeWindowError = validateFormalTimeWindow(nextSchool.trigger_time, nextSchool.endtime);
    if (timeWindowError) return jsonResp({ error: timeWindowError }, 400);

    const serverConnectionChanged = (
      normalizeSecretText(nextSchool.server_url) !== previousServerUrl
      || normalizeSecretText(nextSchool.server_api_key) !== previousServerApiKey
    );
    let serverCheck = null;
    if (serverConnectionChanged) {
      serverCheck = await probeServerConnection(nextSchool.server_url, resolveServerApiKey(env, nextSchool));
    }

    const changed = Object.keys(body).some(key => (
      JSON.stringify(school[key]) !== JSON.stringify(nextSchool[key])
    ));
    if (!changed) {
      return jsonResp({ ok: true, saveMode: "noop", school: sanitizeSchoolForClient(school), serverCheck });
    }
    nextSchool.config_revision = Math.max(0, parseInt(school.config_revision, 10) || 0) + 1;
    nextSchool.config_updated_at = new Date().toISOString();

    Object.assign(school, nextSchool);
    await saveSchool(KV, school);
    return jsonResp({ ok: true, saveMode: "updated", school: sanitizeSchoolForClient(school), serverCheck });
  }

  // POST /api/school/:id/reading-zones/map
  const readingZoneMapMatch = path.match(/^\/api\/school\/([^/]+)\/reading-zones\/map$/);
  if (method === "POST" && readingZoneMapMatch) {
    const schoolId = readingZoneMapMatch[1];
    const school = await getSchool(KV, schoolId);
    if (!school) return jsonResp({ error: "School not found" }, 404);
    let body = {};
    try {
      body = await request.json();
    } catch (_) {
      body = {};
    }
    applySchoolFormalTimeGuard(school, body);

    const users = await getSchoolUsersSnapshot(KV, schoolId);
    const user = chooseUserForReadingZoneMapping(users);
    if (!user) {
      return jsonResp({ error: "本组没有可用于映射的用户，请先添加至少一个带账号密码的用户" }, 400);
    }

    try {
      const { roomList, fidEnc, account } = await fetchChaoxingRoomListForMapping(user, school);
      const readingZoneGroups = buildReadingZoneGroupsFromRooms(roomList);
      if (!readingZoneGroups.length) {
        return jsonResp({ error: "已登录超星，但没有提取到可保存的阅览区" }, 502);
      }

      school.fidEnc = fidEnc || school.fidEnc || "";
      school.reading_zone_groups = readingZoneGroups;
      school.reading_zone_mapped_at = new Date().toISOString();
      await saveSchool(KV, school);
      return jsonResp({
        ok: true,
        school: sanitizeSchoolForClient(school),
        mapped: {
          userId: user.id || "",
          account,
          groupCount: readingZoneGroups.length,
          zoneCount: readingZoneGroups.reduce((sum, group) => sum + (Array.isArray(group.zones) ? group.zones.length : 0), 0),
          fidEnc,
        },
      });
    } catch (error) {
      return jsonResp({ error: error?.message || "阅览区映射失败" }, 502);
    }
  }

  // POST /api/school/:id/seat-config/read
  const seatConfigReadMatch = path.match(/^\/api\/school\/([^/]+)\/seat-config\/read$/);
  if (method === "POST" && seatConfigReadMatch) {
    const school = await getSchool(KV, seatConfigReadMatch[1]);
    if (!school) return jsonResp({ error: "School not found" }, 404);
    try {
      const result = await fetchAndSaveSeatConfig(KV, school);
      return jsonResp({
        ok: true,
        school: sanitizeSchoolForClient(result.school),
        note: result.note,
      });
    } catch (error) {
      return jsonResp({ error: error?.message || "座位规则读取失败" }, 502);
    }
  }

  // DELETE /api/school/:id
  if (method === "DELETE" && schoolMatch) {
    await deleteSchool(KV, schoolMatch[1]);
    return jsonResp({ ok: true });
  }

  // POST /api/school/:id/test-endtime
  const testEndtimeMatch = path.match(/^\/api\/school\/([^/]+)\/test-endtime$/);
  if (method === "POST" && testEndtimeMatch) {
    const school = await getSchool(KV, testEndtimeMatch[1]);
    if (!school) return jsonResp({ error: "School not found" }, 404);

    let body = {};
    try {
      body = await request.json();
    } catch (_) {
      body = {};
    }
    const action = normalizeSecretText(body.action || "start").toLowerCase();
    if (action === "stop" || action === "disable") {
      applySchoolFormalTimeGuard(school, body);
      school.test_endtime_override = null;
      await saveSchool(KV, school);
      return jsonResp({ ok: true, school: sanitizeSchoolForClient(school) });
    }

    if (action === "save" || action === "persist") {
      const testTriggerTime = normalizeSecretText(body.test_trigger_time || body.trigger_time || "");
      if (testTriggerTime && parseTriggerTimeSeconds(testTriggerTime) === null) {
        return jsonResp({ error: "测试开始时间格式应为 HH:MM" }, 400);
      }
      const testEndtimeInput = normalizeSecretText(body.test_endtime || body.endtime || "");
      const testEndtime = testEndtimeInput ? normalizeEndtimeHms(testEndtimeInput) : "";
      if (testEndtimeInput && !testEndtime) {
        return jsonResp({ error: "测试截止时间格式应为 HH:MM:SS" }, 400);
      }
      const sameTimeWindowError = validateTestTimeWindowAgainstFormal(school, testTriggerTime, testEndtime);
      if (sameTimeWindowError) return jsonResp({ error: sameTimeWindowError }, 400);
      applySchoolFormalTimeGuard(school, body);
      school.test_trigger_time = testTriggerTime;
      school.test_endtime = testEndtime;
      school.test_reserve_day_offset = parseTestReserveDayOffset(body.test_reserve_day_offset);
      await saveSchool(KV, school);
      return jsonResp({ ok: true, school: sanitizeSchoolForClient(school) });
    }

    const testTriggerTime = normalizeSecretText(body.test_trigger_time || body.trigger_time || school.test_trigger_time);
    if (testTriggerTime && parseTriggerTimeSeconds(testTriggerTime) === null) {
      return jsonResp({ error: "测试开始时间格式应为 HH:MM" }, 400);
    }

    const testEndtime = normalizeEndtimeHms(body.test_endtime || body.endtime || school.test_endtime);
    if (!testEndtime) {
      return jsonResp({ error: "测试截止时间格式应为 HH:MM:SS" }, 400);
    }
    const sameTimeWindowError = validateTestTimeWindowAgainstFormal(school, testTriggerTime, testEndtime);
    if (sameTimeWindowError) return jsonResp({ error: sameTimeWindowError }, 400);
    applySchoolFormalTimeGuard(school, body);

    const now = new Date();
    const expiresAt = new Date(now.getTime() + TEST_ENDTIME_OVERRIDE_TTL_MS);
    const testReserveDayOffset = parseTestReserveDayOffset(body.test_reserve_day_offset ?? school.test_reserve_day_offset);
    school.test_trigger_time = testTriggerTime;
    school.test_endtime = testEndtime;
    school.test_reserve_day_offset = testReserveDayOffset;
    school.test_endtime_override = {
      trigger_time: testTriggerTime,
      endtime: testEndtime,
      reserve_day_offset: testReserveDayOffset,
      enabled_at: now.toISOString(),
      expires_at: expiresAt.toISOString(),
    };
    await saveSchool(KV, school);
    return jsonResp({ ok: true, school: sanitizeSchoolForClient(school) });
  }

  // GET /api/school/:id/users
  const usersMatch = path.match(/^\/api\/school\/([^/]+)\/users$/);
  if (method === "GET" && usersMatch) {
    const schoolId = usersMatch[1];
    const [school, schoolUsers] = await Promise.all([
      getSchool(KV, schoolId),
      getSchoolUsersSnapshot(KV, schoolId),
    ]);
    const usersWithSignStatus = await mergeSignStatusesForUsers(env, schoolId, schoolUsers);
    const users = await Promise.all(usersWithSignStatus.map(user => sanitizeUserForAdmin(user, { school })));
    return jsonResp(
      { users },
      200,
      { "Cache-Control": "private, max-age=3" }
    );
  }

  // GET /api/school/:id/active-today-count
  const activeTodayCountMatch = path.match(/^\/api\/school\/([^/]+)\/active-today-count$/);
  if (method === "GET" && activeTodayCountMatch) {
    const schoolId = activeTodayCountMatch[1];
    const counts = await getSchoolCounts(KV, schoolId);
    return jsonResp(
      {
        count: counts.activeTodayCount,
        totalCount: counts.totalCount,
        checked_at: counts.checked_at,
      },
      200,
      { "Cache-Control": "private, max-age=10" }
    );
  }

  // GET /api/school/:id/counts
  const countsMatch = path.match(/^\/api\/school\/([^/]+)\/counts$/);
  if (method === "GET" && countsMatch) {
    const counts = await getSchoolCounts(KV, countsMatch[1]);
    return jsonResp(
      {
        totalCount: counts.totalCount,
        activeTodayCount: counts.activeTodayCount,
        checked_at: counts.checked_at,
      },
      200,
      { "Cache-Control": "private, max-age=10" }
    );
  }

  // POST /api/school/:id/user
  const userCreateMatch = path.match(/^\/api\/school\/([^/]+)\/user$/);
  if (method === "POST" && userCreateMatch) {
    const schoolId = userCreateMatch[1];
    const body = await request.json();
    const id = body.id || generateId();
    const school = await getSchool(KV, schoolId);
    if (!school) return jsonResp({ error: "School not found" }, 404);
    if (!body.password) return jsonResp({ error: "新增用户必须填写密码" }, 400);
    const loginCheck = await validateChaoxingLogin(body.phone || body.username, body.password);
    if (!loginCheck.ok) {
      return jsonResp({ error: `超星登录校验未通过：${loginCheck.error}` }, 400);
    }
    const schoolUsers = await getConflictScopeUsers(KV, schoolId, school);
    const user = defaultUser(id);
    user.schoolId = schoolId;
    user.phone = body.phone || "";
    user.username = body.username || "";
    user.password = body.password ? await aesEncrypt(body.password) : "";
    user.remark = body.remark || "";
    if (body.status === "active" || body.status === "paused") user.status = body.status;
    user.sign_feature_visible = body.sign_feature_visible === true;
    user.auto_sign_enabled = user.sign_feature_visible && body.auto_sign_enabled === true;
    if (body.schedule) user.schedule = scheduleForStorage(school, body.schedule);
    user.user_top_config_enabled = body.user_top_config_enabled === true;
    const normalizedTopConfig = normalizeUserTopConfig(body.user_top_config);
    if (normalizedTopConfig.error) return jsonResp({ error: normalizedTopConfig.error }, 400);
    const topConfigError = validateUserTopConfigForSchool(normalizedTopConfig.value, school);
    if (topConfigError) return jsonResp({ error: topConfigError }, 400);
    normalizedTopConfig.value.mode = resolveUserTopModeForSchool(
      school,
      normalizedTopConfig.value.endtime,
      normalizedTopConfig.value.mode,
    );
    user.user_top_config = normalizedTopConfig.value;

    const conflicts = await findSeatConflicts(
      KV,
      schoolId,
      scheduleForConflict(school, user.schedule || {}),
      { userId: id, phone: user.phone },
      schoolUsers,
    );
    if (conflicts.length > 0) {
      return jsonResp({
        error: buildSeatConflictError(conflicts),
        conflicts,
      }, 409);
    }

    user.updatedAt = new Date().toISOString();
    await saveUser(KV, schoolId, user);
    const userIds = await getSchoolUsers(KV, schoolId);
    if (!userIds.includes(id)) {
      userIds.push(id);
      await saveSchoolUsers(KV, schoolId, userIds);
    }
    await setSchoolUserCountInSnapshot(KV, schoolId, userIds.length);
    scheduleUserExternalSync(ctx, env, schoolId, user, {
      renewalExpiresOn: body.renewalExpiresOn,
      purchaseChannel: body.purchaseChannel,
    });
    const pageTokenCheck = await validateChaoxingSeatPage(loginCheck.jar, user, school);
    return jsonResp({
      ok: true,
      user: await sanitizeUserForAdmin(user, { school }),
      pageTokenCheck,
      warning: pageTokenCheck.ok
        ? ""
        : `用户已保存，但真实选座接口不可用：${pageTokenCheck.error}`,
    });
  }

  // GET /api/school/:id/user/:userId
  const userMatch = path.match(/^\/api\/school\/([^/]+)\/user\/([^/]+)$/);
  if (method === "GET" && userMatch) {
    const [school, user] = await Promise.all([
      getSchool(KV, userMatch[1]),
      getUser(KV, userMatch[1], userMatch[2]),
    ]);
    if (!user) return jsonResp({ error: "User not found" }, 404);
    const userWithSignStatus = await mergeSignStatusForUser(env, userMatch[1], user);
    return jsonResp({ user: await sanitizeUserForAdmin(userWithSignStatus, { school }) });
  }

  // GET /api/school/:id/user/:userId/renewal
  const userRenewalMatch = path.match(/^\/api\/school\/([^/]+)\/user\/([^/]+)\/renewal$/);
  if (method === "GET" && userRenewalMatch) {
    const [_, schoolId, userId] = userRenewalMatch;
    const user = await getUser(KV, schoolId, userId);
    if (!user) return jsonResp({ error: "User not found" }, 404);
    try {
      return jsonResp({ ok: true, renewal: await fetchRenewalProfile(env, schoolId, user.phone) });
    } catch (error) {
      return jsonResp({ error: error.message || String(error) }, 502);
    }
  }

  // GET /api/school/:id/user/:userId/password
  const userPasswordMatch = path.match(/^\/api\/school\/([^/]+)\/user\/([^/]+)\/password$/);
  if (method === "GET" && userPasswordMatch) {
    const user = await getUser(KV, userPasswordMatch[1], userPasswordMatch[2]);
    if (!user) return jsonResp({ error: "User not found" }, 404);
    return jsonResp({
      ok: true,
      passwordPlain: user.password ? await aesDecrypt(user.password) : "",
    });
  }

  // PUT /api/school/:id/user/:userId
  if (method === "PUT" && userMatch) {
    const [_, schoolId, userId] = userMatch;
    const school = await getSchool(KV, schoolId);
    if (!school) return jsonResp({ error: "School not found" }, 404);
    const user = await getUser(KV, schoolId, userId);
    if (!user) return jsonResp({ error: "User not found" }, 404);
    const body = await request.json();
    user.schoolId = schoolId;
    const schoolUsers = await getConflictScopeUsers(KV, schoolId, school);
    const oldLoginAccount = normalizeSecretText(user.phone || user.username);
    const nextLoginAccount = normalizeSecretText(
      body.phone !== undefined
        ? body.phone
        : (user.phone || (body.username !== undefined ? body.username : user.username))
    );
    const accountChanged = didLoginAccountChange(oldLoginAccount, nextLoginAccount);
    const passwordChanged = !!body.password && body.password !== "******";
    const accountPasswordChanged = accountChanged || passwordChanged;

    const nextSchedule = body.schedule
      ? scheduleForStorage(school, body.schedule)
      : (user.schedule || {});
    const conflicts = await findSeatConflicts(
      KV,
      schoolId,
      scheduleForConflict(school, nextSchedule),
      { userId, phone: body.phone !== undefined ? body.phone : user.phone },
      schoolUsers,
    );
    if (conflicts.length > 0) {
      return jsonResp({
        error: buildSeatConflictError(conflicts),
        conflicts,
      }, 409);
    }

    let loginCheck = null;
    if (accountPasswordChanged) {
      const effectivePassword = passwordChanged ? body.password : await aesDecrypt(user.password);
      if (!effectivePassword) {
        return jsonResp({ error: "换账号时需要填写密码" }, 400);
      }
      loginCheck = await validateChaoxingLogin(nextLoginAccount, effectivePassword);
      if (!loginCheck.ok) {
        return jsonResp({ error: `超星登录校验未通过：${loginCheck.error}` }, 400);
      }
    }
    if (body.phone !== undefined) user.phone = body.phone;
    if (body.username !== undefined) user.username = body.username;
    if (passwordChanged) {
      user.password = await aesEncrypt(body.password);
    }
    if (body.remark !== undefined) user.remark = body.remark;
    const statusChanged = body.status !== undefined && body.status !== user.status;
    if (body.status !== undefined) {
      user.status = body.status;
      delete user.pause_until;
      delete user.pause_days;
    }
    if (body.sign_feature_visible !== undefined) {
      user.sign_feature_visible = body.sign_feature_visible === true;
    }
    if (body.auto_sign_enabled !== undefined) {
      user.auto_sign_enabled = user.sign_feature_visible === true && body.auto_sign_enabled === true;
    }
    if (body.schedule) user.schedule = nextSchedule;
    if (body.user_top_config_enabled !== undefined) {
      user.user_top_config_enabled = body.user_top_config_enabled === true;
    }
    if (body.user_top_config !== undefined) {
      const normalizedTopConfig = normalizeUserTopConfig(body.user_top_config);
      if (normalizedTopConfig.error) return jsonResp({ error: normalizedTopConfig.error }, 400);
      const topConfigError = validateUserTopConfigForSchool(normalizedTopConfig.value, school);
      if (topConfigError) return jsonResp({ error: topConfigError }, 400);
      normalizedTopConfig.value.mode = resolveUserTopModeForSchool(
        school,
        normalizedTopConfig.value.endtime,
        normalizedTopConfig.value.mode,
      );
      user.user_top_config = normalizedTopConfig.value;
    }
    user.updatedAt = new Date().toISOString();
    await saveUser(KV, schoolId, user);
    scheduleUserExternalSync(ctx, env, schoolId, user, {
      renewalExpiresOn: body.renewalExpiresOn,
      purchaseChannel: body.purchaseChannel,
    });
    const pageTokenCheck = accountChanged
      ? await validateChaoxingSeatPage(loginCheck.jar, user, school)
      : null;
    if ((accountPasswordChanged || statusChanged) && ctx && typeof ctx.waitUntil === "function") {
      ctx.waitUntil(
        refreshEmergencySnapshotForChangedUser(env, school, user).catch(error => {
          console.error(
            `Emergency user refresh failed school=${schoolId} user=${userId}:`,
            error?.message || String(error),
          );
        }),
      );
    }
    return jsonResp({
      ok: true,
      user: await sanitizeUserForAdmin(user, { school }),
      ...(pageTokenCheck ? {
        pageTokenCheck,
        warning: pageTokenCheck.ok
          ? ""
          : `用户已保存，但真实选座接口不可用：${pageTokenCheck.error}`,
      } : {}),
    });
  }

  // POST /api/school/:id/user/:userId/migrate
  const migrateUserMatch = path.match(/^\/api\/school\/([^/]+)\/user\/([^/]+)\/migrate$/);
  if (method === "POST" && migrateUserMatch) {
    const [_, schoolId, userId] = migrateUserMatch;
    const body = await request.json();
    const targetSchoolId = String(body.target_school_id || body.targetSchoolId || "").trim();
    const result = await migrateUserToSchool(KV, schoolId, userId, targetSchoolId);
    if (result.error) {
      return jsonResp(result, result.status || 400);
    }
    const migratedUser = await getUser(KV, targetSchoolId, userId);
    if (migratedUser) {
      scheduleUserExternalSync(ctx, env, targetSchoolId, migratedUser, {
        sourceSchoolId: schoolId,
      });
    }
    return jsonResp(result);
  }

  // DELETE /api/school/:id/user/:userId
  if (method === "DELETE" && userMatch) {
    const schoolId = userMatch[1];
    const nextUserIds = await getSchoolUsers(KV, schoolId);
    await deleteUser(KV, schoolId, userMatch[2]);
    await setSchoolUserCountInSnapshot(KV, schoolId, Math.max(0, nextUserIds.length - 1));
    const deleteTask = syncUserDeleteToServer(env, schoolId, userMatch[2]).catch(error => {
      console.error("Post-delete user sync failed:", error?.message || String(error));
    });
    if (ctx && typeof ctx.waitUntil === "function") ctx.waitUntil(deleteTask);
    return jsonResp({ ok: true });
  }

  // POST /api/school/:id/user/:userId/pause
  const pauseMatch = path.match(/^\/api\/school\/([^/]+)\/user\/([^/]+)\/(pause|resume)$/);
  if (method === "POST" && pauseMatch) {
    const [_, schoolId, userId, action] = pauseMatch;
    const school = await getSchool(KV, schoolId);
    if (!school) return jsonResp({ error: "School not found" }, 404);
    const user = await getUser(KV, schoolId, userId);
    if (!user) return jsonResp({ error: "User not found" }, 404);
    let pauseUntil = "";
    let pauseDays = 0;
    if (action === "pause") {
      const body = await request.json().catch(() => ({}));
      if (body.days !== undefined) {
        pauseDays = Number(body.days);
        pauseUntil = pauseUntilFromDays(pauseDays);
        if (!pauseUntil) return jsonResp({ error: "暂停天数必须是 1 到 365 的整数" }, 400);
      }
    }
    if (action === "resume") {
      const schoolUsers = await getConflictScopeUsers(KV, schoolId, school);
      const conflicts = await findSeatConflicts(
        KV,
        schoolId,
        scheduleForConflict(school, user.schedule || {}),
        { userId, phone: user.phone },
        schoolUsers,
      );
      if (conflicts.length > 0) {
        return jsonResp({
          error: buildSeatConflictError(conflicts),
          conflicts,
        }, 409);
      }
    }
    user.status = action === "pause" ? "paused" : "active";
    if (pauseUntil) {
      user.pause_until = pauseUntil;
      user.pause_days = pauseDays;
    } else {
      delete user.pause_until;
      delete user.pause_days;
    }
    user.updatedAt = new Date().toISOString();
    await saveUser(KV, schoolId, user);
    await updatePausedUserIndex(KV, schoolId, userId, pauseUntil);
    scheduleUserExternalSync(ctx, env, schoolId, user);
    if (ctx && typeof ctx.waitUntil === "function") {
      ctx.waitUntil(
        refreshEmergencySnapshotForChangedUser(env, school, user).catch(error => {
          console.error(
            `Emergency status refresh failed school=${schoolId} user=${userId}:`,
            error?.message || String(error),
          );
        }),
      );
    }
    return jsonResp({ ok: true, status: user.status, pauseUntil });
  }

  // POST /api/school/:id/users/status
  const bulkUserStatusMatch = path.match(/^\/api\/school\/([^/]+)\/users\/status$/);
  if (method === "POST" && bulkUserStatusMatch) {
    const schoolId = bulkUserStatusMatch[1];
    const school = await getSchool(KV, schoolId);
    if (!school) return jsonResp({ error: "School not found" }, 404);

    const body = await request.json();
    const nextStatus = String(body.status || "").trim();
    if (nextStatus !== "active" && nextStatus !== "paused") {
      return jsonResp({ error: "status must be active or paused" }, 400);
    }

    const userIds = await getSchoolUsers(KV, schoolId);
    let updated = 0;
    let unchanged = 0;
    let missing = 0;
    const changedUsers = [];
    for (const userId of userIds) {
      const user = await getUser(KV, schoolId, userId);
      if (!user) {
        missing += 1;
        continue;
      }
      if (user.status === nextStatus) {
        if (user.pause_until || user.pause_days) {
          delete user.pause_until;
          delete user.pause_days;
          user.updatedAt = new Date().toISOString();
          await saveUser(KV, schoolId, user);
        }
        unchanged += 1;
        continue;
      }
      user.status = nextStatus;
      delete user.pause_until;
      delete user.pause_days;
      user.updatedAt = new Date().toISOString();
      await saveUser(KV, schoolId, user);
      changedUsers.push(user);
      updated += 1;
    }
    if (changedUsers.length && ctx && typeof ctx.waitUntil === "function") {
      ctx.waitUntil(Promise.all(changedUsers.map(user => (
        refreshEmergencySnapshotForChangedUser(env, school, user).catch(error => {
          console.error(
            `Emergency bulk status refresh failed school=${schoolId} user=${user.id}:`,
            error?.message || String(error),
          );
        })
      ))));
    }

    return jsonResp({
      ok: true,
      status: nextStatus,
      total: userIds.length,
      updated,
      unchanged,
      missing,
    });
  }

  // POST /api/school/:id/users/top-config/disable
  const disableUserTopConfigMatch = path.match(/^\/api\/school\/([^/]+)\/users\/top-config\/disable$/);
  if (method === "POST" && disableUserTopConfigMatch) {
    const schoolId = disableUserTopConfigMatch[1];
    const school = await getSchool(KV, schoolId);
    if (!school) return jsonResp({ error: "School not found" }, 404);

    const userIds = await getSchoolUsers(KV, schoolId);
    let updated = 0;
    let unchanged = 0;
    let missing = 0;
    const changedUsers = [];
    for (const userId of userIds) {
      const user = await getUser(KV, schoolId, userId);
      if (!user) {
        missing += 1;
        continue;
      }
      if (user.user_top_config_enabled !== true && !Object.keys(user.user_top_config || {}).length) {
        unchanged += 1;
        continue;
      }
      user.user_top_config_enabled = false;
      user.user_top_config = {};
      user.updatedAt = new Date().toISOString();
      await saveUser(KV, schoolId, user);
      changedUsers.push(user);
      updated += 1;
    }
    for (const user of changedUsers) {
      scheduleUserExternalSync(ctx, env, schoolId, user);
      if (ctx && typeof ctx.waitUntil === "function") {
        ctx.waitUntil(refreshEmergencySnapshotForChangedUser(env, school, user).catch(error => {
          console.error(`Emergency top config refresh failed school=${schoolId} user=${user.id}:`, error?.message || String(error));
        }));
      }
    }
    return jsonResp({ ok: true, total: userIds.length, updated, unchanged, missing });
  }

  // POST /api/trigger/:schoolId
  const triggerSchoolMatch = path.match(/^\/api\/trigger\/([^/]+)$/);
  if (method === "POST" && triggerSchoolMatch) {
    const schoolId = triggerSchoolMatch[1];
    const school = await getSchool(KV, schoolId);
    if (!school) return jsonResp({ error: "School not found" }, 404);
    const scheduleContext = getActiveScheduleContextForSchool(school);
    const today = scheduleContext.day;
    const todayDate = scheduleContext.date;
    const triggerSource = (request.headers.get("X-Trigger-Source") || "").trim();
    const fallbackMode = (request.headers.get("X-Fallback-Mode") || "").trim();
    const isScheduledFallback = triggerSource === "worker2" && fallbackMode === "scheduled";
    const fallbackRecordScope = formalTriggerScope(school);

    if (isScheduledFallback) {
      const existingRecord = await getFallbackTriggerRecord(KV, todayDate, schoolId, fallbackRecordScope);
      if (isScheduledTriggerRecord(existingRecord)) {
        return jsonResp({
          ok: true,
          skipped: true,
          reason: "fallback_already_triggered_today",
          schoolId,
          schoolName: school.name,
          date: todayDate,
          fallbackRecord: existingRecord,
        });
      }
      if (isFreshInProgressTriggerRecord(existingRecord)) {
        return jsonResp({
          ok: true,
          skipped: true,
          reason: "fallback_trigger_in_progress",
          schoolId,
          schoolName: school.name,
          date: todayDate,
          fallbackRecord: existingRecord,
        });
      }
    }

    const users = await buildTodayDispatchUsers(KV, schoolId, school, today, null, todayDate);
    if (users.length === 0) {
      if (isScheduledFallback) {
        await saveFallbackTriggerRecord(KV, todayDate, schoolId, {
          source: "worker2",
          mode: "scheduled",
          schedule_scope: fallbackRecordScope,
          at: new Date().toISOString(),
          beijing_time: beijingHHMM(),
          schoolId,
          schoolName: school.name,
          triggeredUsers: 0,
          okBatches: 0,
          totalBatches: 0,
        }, fallbackRecordScope);
      }
      return jsonResp({ ok: true, triggeredUsers: 0, okBatches: 0, totalBatches: 0 });
    }
    const result = await dispatchUsersInBatches(env, school, users, {
      allowTestEndtimeOverride: !isScheduledFallback,
      dispatchContext: isScheduledFallback
        ? { source: "worker2_scheduled", scope: "school" }
        : { source: "manual_school", scope: "school" },
    });
    if (result.error) {
      return jsonResp({
        ok: false,
        error: result.error,
        triggeredUsers: users.length,
        okBatches: result.okBatches,
        totalBatches: result.totalBatches,
      }, 400);
    }
    if (isScheduledFallback) {
      await saveFallbackTriggerRecord(KV, todayDate, schoolId, {
        source: "worker2",
        mode: "scheduled",
        schedule_scope: fallbackRecordScope,
        at: new Date().toISOString(),
        beijing_time: beijingHHMM(),
        schoolId,
        schoolName: school.name,
        triggeredUsers: users.length,
        okBatches: result.okBatches,
        totalBatches: result.totalBatches,
      }, fallbackRecordScope);
    }
    return jsonResp({
      ok: true,
      triggeredUsers: users.length,
      okBatches: result.okBatches,
      totalBatches: result.totalBatches,
    });
  }

  // POST /api/trigger/:schoolId/:userId
  const triggerUserMatch = path.match(/^\/api\/trigger\/([^/]+)\/([^/]+)$/);
  if (method === "POST" && triggerUserMatch) {
    const [_, schoolId, userId] = triggerUserMatch;
    const school = await getSchool(KV, schoolId);
    const user = await getUser(KV, schoolId, userId);
    if (!school || !user) return jsonResp({ error: "Not found" }, 404);
    const scheduleContext = getActiveScheduleContextForSchool(school);
    const today = scheduleContext.day;
    const todayDate = scheduleContext.date;
    const storedDay = storedScheduleDayForExecution(school, today);
    const daySchedule = user.schedule?.[storedDay];
    if (!daySchedule || !daySchedule.enabled) {
      return jsonResp({ error: "User has no schedule for today" }, 400);
    }
    const rawSlots = Array.isArray(daySchedule.slots)
      ? daySchedule.slots
      : [{ roomid: daySchedule.roomid, seatid: daySchedule.seatid, times: daySchedule.times, seatPageId: daySchedule.seatPageId || "", fidEnc: daySchedule.fidEnc || "" }];
    const activeSlots = rawSlots
      .map((slot, index) => slot && typeof slot === "object" ? { ...slot, __slotIndex: index } : slot)
      .filter(s => s.times && s.roomid);
    if (activeSlots.length === 0) return jsonResp({ error: "No active slots for today" }, 400);
    const reserveDayOffset = resolveReserveDayOffset(env, school);
    const dispatchUser = {
      username: user.phone || user.username,
      password: user.password,
      remark: user.remark || user.username || user.phone,
      nickname: user.username,
      user_top_config_enabled: !!user.user_top_config_enabled,
      user_top_config: user.user_top_config || {},
      ...(reserveDayOffset !== null ? { reserve_day_offset: reserveDayOffset } : {}),
      slots: activeSlots.map((s, slotIndex) => {
        const originalSlotIndex = Number.isInteger(s.__slotIndex) ? s.__slotIndex : slotIndex;
        return {
        roomid: s.roomid,
        seatid: parseSeatIdsRaw(s.seatid),
        times: s.times,
        seatPageId: s.seatPageId || "",
        fidEnc: school.fidEnc || s.fidEnc || "",
        backupSeats: typeof s.backupSeats === "string" ? s.backupSeats : "",
      };
      }),
    };
    const result = await dispatchUsersInBatches(env, school, [dispatchUser], {
      allowTestEndtimeOverride: true,
      dispatchContext: {
        source: "manual_user",
        scope: "user",
      },
    });
    if (result.error) {
      return jsonResp({
        ok: false,
        error: result.error,
        triggeredUsers: 1,
        okBatches: result.okBatches,
        totalBatches: result.totalBatches,
        repo: school.repo,
      }, 502);
    }
    return jsonResp({
      ok: true,
      triggeredUsers: 1,
      okBatches: result.okBatches,
      totalBatches: result.totalBatches,
      slots: activeSlots.length,
      repo: school.repo,
    });
  }

  // POST /api/encrypt
  if (method === "POST" && path === "/api/encrypt") {
    const body = await request.json();
    if (!body.password) return jsonResp({ error: "password required" }, 400);
    const encrypted = await aesEncrypt(body.password);
    return jsonResp({ encrypted });
  }

  // POST /api/init-demo (初始化演示数据)
  if (method === "POST" && path === "/api/init-demo") {
    const demoSchools = [
      { id: "001", name: "华东师范大学", repo: "BAOfuZhan/hcd" },
      { id: "002", name: "复旦大学", repo: "BAOfuZhan/fdu" },
      { id: "003", name: "上海交通大学", repo: "BAOfuZhan/sjtu" },
    ];
    const existingSchools = await getSchools(KV);
    for (const demo of demoSchools) {
      if (!existingSchools.includes(demo.id)) {
        const school = defaultSchool(demo.id, demo.name);
        school.repo = demo.repo;
        await saveSchool(KV, school);
        await saveSchoolUsersSnapshot(KV, demo.id, []);
        existingSchools.push(demo.id);
      }
    }
    await saveSchools(KV, existingSchools);
    return jsonResp({ ok: true, schools: existingSchools });
  }

  return jsonResp({ error: "Not found" }, 404);
}

// ─── Fetch Handler ───

async function handleFetch(request, env, ctx = null) {
  const url = new URL(request.url);
  const path = url.pathname;

  // CORS
  if (request.method === "OPTIONS") {
    return new Response(null, {
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type,X-API-Key",
      },
    });
  }

  // API 鉴权
  if (path.startsWith("/api/")) {
    const apiKey = request.headers.get("X-API-Key") || url.searchParams.get("key");
    if (apiKey !== env.API_KEY) {
      return jsonResp({ error: "Unauthorized" }, 401);
    }
    return handleAPI(request, env, path, ctx);
  }

  // 管理面板
  return new Response(ADMIN_HTML, {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-store, no-cache, must-revalidate",
    },
  });
}

// ─── 管理面板 HTML ───

const ADMIN_HTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>统一抢座管理系统</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/codemirror@5.65.21/lib/codemirror.css">
<script src="https://cdn.jsdelivr.net/npm/codemirror@5.65.21/lib/codemirror.js"></script>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f0f2f5;min-height:100vh}
.container{max-width:1200px;margin:0 auto;padding:20px}
.header{background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);color:#fff;padding:20px;border-radius:12px;margin-bottom:20px;display:flex;justify-content:space-between;align-items:center}
.header h1{font-size:24px}
.header .time{font-size:14px;opacity:0.9}
.login-box{max-width:400px;margin:100px auto;background:#fff;padding:40px;border-radius:12px;box-shadow:0 4px 20px rgba(0,0,0,0.1)}
.login-box h2{text-align:center;margin-bottom:30px;color:#333}
.login-box input{width:100%;padding:12px;border:1px solid #ddd;border-radius:8px;font-size:16px;margin-bottom:20px}
.login-box button{width:100%;padding:12px;background:linear-gradient(135deg,#667eea,#764ba2);color:#fff;border:none;border-radius:8px;font-size:16px;cursor:pointer}
.btn{padding:8px 16px;border:none;border-radius:6px;cursor:pointer;font-size:14px;transition:all 0.2s}
.btn-primary{background:#667eea;color:#fff}
.btn-primary:hover{background:#5a6fd6}
.btn-success{background:#52c41a;color:#fff}
.btn-danger{background:#ff4d4f;color:#fff}
.btn-secondary{background:#f0f0f0;color:#333}
.btn-sm{padding:4px 10px;font-size:12px}
.card{background:#fff;border-radius:12px;padding:20px;margin-bottom:16px;box-shadow:0 2px 8px rgba(0,0,0,0.06)}
.card-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;padding-bottom:12px;border-bottom:1px solid #f0f0f0}
.card-title{font-size:18px;font-weight:600;color:#333}
.card-actions{display:flex;flex-wrap:wrap;gap:8px;align-items:center;justify-content:flex-end}
.school-list{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px;align-items:start}
.school-section{min-width:0}
.school-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:16px}
.school-section + .school-section{border-top:0;padding-top:0}
.school-group-divider{grid-column:1/-1;border-top:1px solid #dfe3ec;height:0}
.conflict-group-add{display:grid;grid-template-columns:minmax(180px,260px) auto;gap:8px;align-items:center}
.conflict-group-add input{padding:8px;border:1px solid #ddd;border-radius:6px}
.school-card{background:#fff;border-radius:12px;padding:20px;box-shadow:0 2px 8px rgba(0,0,0,0.06);cursor:pointer;transition:all 0.2s;border:2px solid transparent}
.school-card:hover{border-color:#667eea;transform:translateY(-2px)}
.school-card h3{font-size:18px;color:#333;margin-bottom:8px}
.school-card .meta{font-size:13px;color:#888;margin-bottom:12px}
.school-card .stats{display:flex;flex-wrap:wrap;gap:16px;font-size:13px}
.school-card .stats span{color:#667eea}
.school-search{display:grid;grid-template-columns:minmax(220px,1fr) auto auto;gap:8px;align-items:center;margin-bottom:16px}
.school-search input{width:100%;padding:10px;border:1px solid #ddd;border-radius:6px;font-size:14px}
.school-search-status{font-size:13px;color:#666;margin-bottom:12px}
.school-search-matches{margin-top:10px;padding-top:10px;border-top:1px solid #f0f0f0;display:grid;gap:6px;font-size:12px;color:#555}
.school-search-match{display:flex;flex-wrap:wrap;gap:8px;align-items:center}
.school-search-match strong{color:#333}
.school-search-match span{color:#777}
.user-table{width:100%;border-collapse:collapse}
.user-table th,.user-table td{padding:12px;text-align:left;border-bottom:1px solid #f0f0f0}
.user-table th{background:#fafafa;font-weight:500;color:#666}
.user-table tr:hover{background:#fafafa}
.user-table-scroll{overflow-x:auto}
.user-table-compact{min-width:1080px;font-size:12px}
.user-table-compact th,.user-table-compact td{padding:8px 6px;white-space:nowrap}
.user-table-compact .actions{flex-wrap:nowrap;gap:4px}
.user-table-compact .btn-sm{padding:4px 7px}
.user-table-compact .pause-days-action{flex:0 0 auto}
.user-table-compact .pause-days-input{width:48px}
.user-table-compact .password-view{min-width:88px}
.school-server-link{color:#1677ff;font-weight:600;text-decoration:underline;text-underline-offset:3px}
.user-name-custom{display:inline-block;padding:2px 6px;border-radius:6px;background:#e9f8f2;color:#16775f;font-weight:800}
.password-view{display:flex;align-items:center;gap:6px;min-width:120px}
.password-view__text{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;color:#555;word-break:break-all}
.password-eye{display:inline-flex;align-items:center;justify-content:center;width:28px;height:28px;border:1px solid #ddd;border-radius:6px;background:#fff;color:#555;cursor:pointer;font-size:14px;line-height:1}
.password-eye:hover{border-color:#667eea;color:#667eea;background:#f7f8ff}
.password-input-wrap{display:grid;grid-template-columns:1fr 36px;gap:8px;align-items:center}
.status-active{color:#52c41a}
.status-paused{color:#faad14}
.test-override-panel{margin-top:16px;padding-top:16px;border-top:1px solid #f0f0f0}
.test-override-row{display:grid;grid-template-columns:1fr auto auto;gap:8px;align-items:end}
.test-override-status{display:flex;flex-wrap:wrap;gap:8px;align-items:center;font-size:13px;color:#666;margin-bottom:10px}
.test-status-pill{display:inline-flex;align-items:center;border-radius:999px;padding:2px 8px;font-size:12px;font-weight:600}
.test-status-on{background:#f6ffed;color:#389e0d}
.test-status-off{background:#f5f5f5;color:#777}
.test-override-note{font-size:12px;color:#777;line-height:1.7;margin-top:8px}
.modal{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.5);z-index:1000;overflow-y:auto}
.modal.show{display:flex;align-items:flex-start;justify-content:center;padding:40px 20px}
.modal-content{background:#fff;border-radius:12px;width:100%;max-width:800px;max-height:90vh;overflow-y:auto}
.modal-header{padding:20px;border-bottom:1px solid #f0f0f0;display:flex;justify-content:space-between;align-items:center}
.modal-header h3{font-size:18px}
.modal-close{font-size:24px;cursor:pointer;color:#999}
.modal-body{padding:20px}
.form-group{margin-bottom:16px}
.form-group label{display:block;margin-bottom:6px;font-weight:500;color:#333}
.form-group input,.form-group select,.form-group textarea{width:100%;padding:10px;border:1px solid #ddd;border-radius:6px;font-size:14px}
.form-group .CodeMirror{height:190px;border:1px solid #ddd;border-radius:6px;font-size:14px;line-height:1.6}
.form-row{display:grid;grid-template-columns:repeat(2,1fr);gap:16px}
.schedule-grid{display:grid;gap:12px}
.schedule-day{background:#fafafa;border-radius:8px;padding:12px}
.schedule-day-header{display:flex;align-items:center;gap:12px;margin-bottom:8px}
.schedule-day-header input[type="checkbox"]{width:18px;height:18px}
.schedule-day-header label{font-weight:500}
.schedule-day-fields{display:grid;grid-template-columns:repeat(3,1fr);gap:8px}
.schedule-day-fields input{padding:6px;font-size:12px}
.slot-row{border-top:1px solid #e8e8e8;padding-top:8px;margin-top:8px}
.slot-label{font-size:11px;color:#888;margin-bottom:4px}
.global-time-tools{background:#fafafa;border:1px solid #ececec;border-radius:8px;padding:12px;margin:12px 0}
.global-config-fields{display:grid;grid-template-columns:repeat(3,1fr);gap:8px}
.global-config-fields input{padding:8px;font-size:13px}
.global-config-actions{display:flex;gap:8px;align-items:center;margin-top:8px}
.global-time-note{font-size:12px;color:#777;line-height:1.7;margin-top:8px}
.user-migrate-tools{background:#fafafa;border:1px solid #ececec;border-radius:8px;padding:12px;margin:0 0 16px}
.user-migrate-row{display:grid;grid-template-columns:1fr auto;gap:8px;align-items:end}
.user-migrate-note{font-size:12px;color:#777;line-height:1.7;margin-top:8px}
.user-top-config{background:#f7f8ff;border:1px solid #dfe3ff;border-radius:8px;padding:12px;margin:4px 0 18px}
.user-top-config-toggle{display:flex;align-items:center;gap:8px;font-weight:500;color:#333;cursor:pointer}
.user-top-config-toggle input{width:18px;height:18px}
.user-top-config-fields{display:grid;grid-template-columns:repeat(2,1fr);gap:12px;margin-top:12px;padding-top:12px;border-top:1px solid #e3e6f7}
.user-top-config-note{font-size:12px;color:#777;line-height:1.7;margin-top:10px}
.sign-config{background:#f8fbf8;border:1px solid #d8ead8;border-radius:8px;padding:12px;margin:4px 0 18px}
.sign-config-toggle{display:flex;align-items:center;gap:8px;font-weight:500;color:#333;cursor:pointer}
.sign-config-toggle input{width:18px;height:18px}
.sign-status{display:inline-flex;align-items:center;border-radius:999px;padding:2px 8px;font-size:12px;font-weight:600}
.sign-status-on{background:#f6ffed;color:#389e0d}
.sign-status-off{background:#fff1f0;color:#cf1322}
.renewal-summary{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:14px}
.renewal-stat{background:#fff;border:1px solid #e3e6f0;border-radius:6px;padding:12px;min-width:0}
.renewal-stat span{display:block;color:#777;font-size:12px;margin-bottom:6px}
.renewal-stat strong{display:block;color:#222;font-size:15px;font-weight:600;overflow-wrap:anywhere}
.toast{position:fixed;top:20px;right:20px;padding:12px 20px;border-radius:8px;color:#fff;z-index:2000;animation:slideIn 0.3s}
.toast-success{background:#52c41a}
.toast-error{background:#ff4d4f}
.school-save-notice{position:fixed;top:16px;left:50%;transform:translateX(-50%);width:min(680px,calc(100vw - 32px));padding:12px 16px;border-radius:9px;background:#1677ff;color:#fff;box-shadow:0 8px 28px rgba(0,0,0,.22);z-index:3000;white-space:pre-line;line-height:1.55;font-size:14px;font-weight:500;pointer-events:none;animation:noticeDrop .2s ease-out}
@keyframes noticeDrop{from{transform:translate(-50%,-12px);opacity:0}to{transform:translate(-50%,0);opacity:1}}
@keyframes slideIn{from{transform:translateX(100%);opacity:0}to{transform:translateX(0);opacity:1}}
.breadcrumb{display:flex;align-items:center;gap:8px;margin-bottom:20px;font-size:14px;color:#666}
.breadcrumb a{color:#667eea;text-decoration:none}
.breadcrumb a:hover{text-decoration:underline}
.empty{text-align:center;padding:60px;color:#999}
.empty-icon{font-size:48px;margin-bottom:16px}
.actions{display:flex;flex-wrap:wrap;gap:8px}
.pause-days-action{display:inline-flex;gap:4px;align-items:center}
.pause-days-input{width:58px;padding:4px 6px;border:1px solid #ddd;border-radius:6px;font-size:12px}
.zone-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}
.zone-card{background:#fafafa;border:1px solid #ececec;border-radius:10px;padding:12px}
.zone-floor{font-size:13px;font-weight:600;color:#333;margin-bottom:8px}
.zone-list{display:grid;gap:6px}
.zone-item{display:flex;justify-content:space-between;align-items:center;font-size:13px;color:#555;padding:6px 8px;background:#fff;border-radius:6px}
.zone-id{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;color:#667eea;background:#eef1ff;padding:2px 6px;border-radius:999px}
.zone-right{display:flex;align-items:center;gap:6px}
.copy-btn{border:none;background:#f0f2f7;color:#4b5563;border-radius:6px;padding:2px 8px;font-size:12px;cursor:pointer}
.copy-btn:hover{background:#e5e9f3}
.mapping-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:16px}
.mapping-box{background:#fafafa;border:1px solid #ececec;border-radius:10px;padding:14px}
.mapping-box h4{font-size:14px;color:#333;margin-bottom:8px}
.mapping-box textarea,.mapping-box input{width:100%;padding:10px;border:1px solid #ddd;border-radius:6px;font-size:13px}
.mapping-box textarea{min-height:220px;resize:vertical}
.mapping-inline{display:grid;grid-template-columns:140px 1fr;gap:12px;align-items:end;margin-bottom:12px}
.mapping-user-fields{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:12px}
.mapping-actions{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}
.mapping-note{font-size:12px;color:#777;line-height:1.7;margin-top:10px}
.school-detail-container{max-width:1200px}
.school-detail-layout{display:block}
.school-detail-main{min-width:0}
.school-notes-launcher{position:fixed;top:180px;right:24px;width:280px;display:grid;justify-items:end;gap:10px;z-index:20}
.school-notes-toggle{width:64px;height:64px;justify-self:end;padding:0!important;border-radius:50%!important;font-size:14px;font-weight:700;box-shadow:0 7px 20px rgba(102,126,234,.25)!important}
.school-note-pill{width:100%;padding:11px 14px;border:1px solid #f0d477;border-radius:999px;background:linear-gradient(135deg,#fffdf2,#fff4bf);color:#72530c;font-size:13px;font-weight:600;text-align:center;line-height:1.45;cursor:pointer;box-shadow:0 5px 15px rgba(118,91,20,.1);white-space:normal;overflow-wrap:anywhere}
.school-note-pill:hover{border-color:#d9ad28;transform:translateY(-1px)}
.school-note-editor,.school-note-new,.school-notes-empty-editor{display:none;width:100%;background:#fffaf0;border:1px solid #f3df91;border-radius:12px;padding:10px;box-shadow:0 8px 24px rgba(118,91,20,.1)}
.school-note-editor.show,.school-note-new.show,.school-notes-empty-editor.show{display:block}
.school-note-editor textarea,.school-note-new textarea,.school-notes-empty-editor textarea{width:100%;min-height:62px;padding:9px;border:1px solid #eadca9;border-radius:8px;background:#fff;font:inherit;font-size:13px;line-height:1.55;resize:vertical;outline:none}
.school-note-editor textarea:focus,.school-note-new textarea:focus,.school-notes-empty-editor textarea:focus{border-color:#d6a51f;box-shadow:0 0 0 3px rgba(214,165,31,.12)}
.school-note-actions{display:flex;justify-content:flex-end;gap:6px;margin-top:7px}
.school-note-actions .btn{padding:5px 10px;font-size:12px}
@media (max-width: 768px){.mapping-inline,.mapping-user-fields{grid-template-columns:1fr}}
@media (max-width: 1500px){.school-notes-launcher{position:static;width:100%;margin:0 0 16px}.school-notes-toggle{justify-self:end}.school-note-pill{max-width:320px}}
@media (max-width: 1000px){.school-list{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media (max-width: 680px){.school-list{grid-template-columns:1fr}}
@media (max-width: 768px){.test-override-row,.global-config-fields,.user-migrate-row,.user-top-config-fields,.renewal-summary,.school-search{grid-template-columns:1fr}.actions,.global-config-actions,.card-actions{flex-wrap:wrap}}
</style>
</head>
<body>
<div id="app"></div>
<script>
const API_BASE = "";
let API_KEY = "";
try {
  API_KEY = localStorage.getItem("api_key") || "";
} catch (_e) {
  API_KEY = "";
}
let currentView = "login";
let currentSchool = null;
let currentConflictGroupKey = "";
let currentConflictGroupSchools = [];
let conflictGroupUsersLoading = false;
let userModalReturnConflictGroupKey = "";
let clearPlanMappingAfterUserSave = false;
let scheduleTextEditor = null;
let planExtractTextEditor = null;
const conflictGroupUsersCache = new Map();
let schools = [];
let users = [];
let schoolSearch = { query: "", loading: false, error: "", results: [] };
let isSavingUser = false;
let isMigratingUser = false;
let renewalCardTouched = false;
let activeTodayRefreshRunId = 0;
const ACTIVE_TODAY_CACHE_TTL_MS = 2 * 60 * 1000;
const ACTIVE_TODAY_CACHE_PREFIX = "active_today_count:";
const CONFLICT_GROUP_USERS_CACHE_TTL_MS = 30 * 1000;
const UI_SORT_VERSION = "school-save-notice-20260806-1";
function normalizeIconclickOcrProvider(value) {
  const raw = String(value ?? "").trim().toLowerCase();
  if (["tuling", "tulingcloud", "图灵", "图灵云"].includes(raw)) return "tulingcloud";
  if (["jfbym", "聚福", "聚福别样"].includes(raw)) return "jfbym";
  return "chaojiying";
}
function formatIconclickOcrProvider(value) {
  const provider = normalizeIconclickOcrProvider(value);
  if (provider === "tulingcloud") return "图灵云";
  if (provider === "jfbym") return "jfbym";
  return "超级鹰";
}
function normalizeRotateOcrProvider(value) {
  const raw = String(value ?? "").trim().toLowerCase();
  return ["geepass", "tulingcloud", "jfbym"].includes(raw) ? raw : "geepass";
}
function formatRotateOcrProvider(value) {
  const provider = normalizeRotateOcrProvider(value);
  if (provider === "jfbym") return "JFBYM → GeePass → 图灵云";
  if (provider === "tulingcloud") return "图灵云 → GeePass → JFBYM";
  return "GeePass → 图灵云 → JFBYM";
}
const DEFAULT_READING_ZONE_GROUPS = [
  { floor: "2 楼", zones: [{ id: "13474", name: "西阅览区" }, { id: "13473", name: "东阅览区" }, { id: "13476", name: "西电子阅览区" }, { id: "13472", name: "东电子阅览区" }] },
  { floor: "3 楼", zones: [{ id: "13481", name: "西阅览区" }, { id: "13484", name: "中阅览区" }, { id: "13478", name: "东阅览区" }, { id: "13480", name: "西电子阅览区" }, { id: "13475", name: "东电子阅览区" }] },
  { floor: "4 楼", zones: [{ id: "13487", name: "西阅览区" }, { id: "13490", name: "中阅览区" }, { id: "13489", name: "东阅览区" }, { id: "13485", name: "西电子阅览区" }, { id: "13486", name: "东电子阅览区" }, { id: "13492", name: "南区" }] },
  { floor: "5 楼", zones: [{ id: "13493", name: "西阅览区" }, { id: "13497", name: "中阅览区" }, { id: "13494", name: "东阅览区" }] },
  { floor: "6 楼", zones: [{ id: "13499", name: "西阅览区" }, { id: "13500", name: "中阅览区" }, { id: "13502", name: "东阅览区" }, { id: "13505", name: "北阅览区" }] },
  { floor: "7 楼", zones: [{ id: "13504", name: "西阅览区" }, { id: "13506", name: "中阅览区" }, { id: "13507", name: "东阅览区" }] },
  { floor: "8 楼", zones: [{ id: "13495", name: "西阅览区" }, { id: "13496", name: "中阅览室" }, { id: "13498", name: "东阅览区" }, { id: "13501", name: "电子西阅览区" }, { id: "13503", name: "电子东阅览区" }] },
  { floor: "9 楼", zones: [{ id: "13491", name: "西阅览室" }, { id: "13488", name: "中阅览区" }, { id: "13483", name: "东阅览区" }] },
];
const PLAN_EXTRACT_MAX_HOURS_DEFAULT = 16;
const PLAN_EXTRACT_WEEK_MAP = {
  "周一": "Monday",
  "周二": "Tuesday",
  "周三": "Wednesday",
  "周四": "Thursday",
  "周五": "Friday",
  "周六": "Saturday",
  "周日": "Sunday",
  "周天": "Sunday",
};
const PLAN_EXTRACT_ALL_DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
const PLAN_MAPPING_DRAFT_KEY_PREFIX = "plan_mapping_draft:";

function getPlanMappingDraftStorageKey() {
  return PLAN_MAPPING_DRAFT_KEY_PREFIX + String(currentSchool?.id || "default");
}

function getPlanMappingDraft() {
  try {
    const draft = JSON.parse(localStorage.getItem(getPlanMappingDraftStorageKey()) || "{}");
    return draft && typeof draft === "object" ? draft : {};
  } catch (_e) {
    return {};
  }
}

function persistPlanMappingDraft() {
  try {
    localStorage.setItem(getPlanMappingDraftStorageKey(), JSON.stringify({
      phone: document.getElementById("plan_extract_phone")?.value || "",
      password: document.getElementById("plan_extract_password")?.value || "",
      username: document.getElementById("plan_extract_username")?.value || "",
      text: getPlanExtractTextEditor()?.getValue() ?? document.getElementById("plan_extract_input")?.value ?? "",
    }));
  } catch (_e) {
    // 浏览器禁用本地存储时仍允许正常使用表单。
  }
}

function clearPlanMappingDraft() {
  for (const id of ["plan_extract_phone", "plan_extract_password", "plan_extract_username"]) {
    const input = document.getElementById(id);
    if (input) input.value = "";
  }
  const editor = getPlanExtractTextEditor();
  if (editor) editor.setValue("自习室id:");
  else {
    const textarea = document.getElementById("plan_extract_input");
    if (textarea) textarea.value = "自习室id:";
  }
  const output = document.getElementById("plan_extract_output");
  if (output) output.value = "";
  try {
    localStorage.removeItem(getPlanMappingDraftStorageKey());
  } catch (_e) {
    // ignore localStorage privacy errors
  }
  toast("已清空计划映射草稿");
}

function normalizeClientPlanExtractMaxHours(value) {
  const text = String(value ?? "").trim();
  if (!text) return null;
  const num = Number(text);
  return Number.isFinite(num) && num >= 0 ? num : null;
}

function getPlanExtractMaxHoursDefaultForCurrentSchool() {
  const saved = normalizeClientPlanExtractMaxHours(currentSchool?.plan_extract_max_hours);
  return String(saved ?? PLAN_EXTRACT_MAX_HOURS_DEFAULT);
}

function normalizeClientPlanExtractSeatPageId(value) {
  return String(value ?? "").trim().replace(/[^0-9A-Za-z_-]/g, "");
}

function getPlanExtractSeatPageIdDefaultForCurrentSchool() {
  return normalizeClientPlanExtractSeatPageId(currentSchool?.plan_extract_seat_page_id);
}

async function persistPlanExtractMaxHoursForCurrentSchool(value) {
  if (!currentSchool?.id) return false;
  const normalized = normalizeClientPlanExtractMaxHours(value);
  if (normalized === null) return false;
  currentSchool = { ...currentSchool, plan_extract_max_hours: normalized };
  schools = upsertSchoolInOrderedList(schools, currentSchool);
  const res = await api("PUT", "/api/school/" + currentSchool.id, {
    ...getCurrentSchoolFormalTimeGuard(),
    plan_extract_max_hours: normalized,
  });
  if (!res.ok) {
    toast(res.error || "最长单段小时数保存失败", "error");
    return false;
  }
  if (res.school) {
    currentSchool = res.school;
    schools = upsertSchoolInOrderedList(schools, res.school);
  }
  return true;
}

async function persistPlanExtractSeatPageIdForCurrentSchool(value) {
  if (!currentSchool?.id) return false;
  const normalized = normalizeClientPlanExtractSeatPageId(value);
  currentSchool = { ...currentSchool, plan_extract_seat_page_id: normalized };
  schools = upsertSchoolInOrderedList(schools, currentSchool);
  const res = await api("PUT", "/api/school/" + currentSchool.id, {
    ...getCurrentSchoolFormalTimeGuard(),
    plan_extract_seat_page_id: normalized,
  });
  if (!res.ok) {
    toast(res.error || "seatPageId 保存失败", "error");
    return false;
  }
  if (res.school) {
    currentSchool = res.school;
    schools = upsertSchoolInOrderedList(schools, res.school);
  }
  return true;
}

async function handlePlanExtractMaxHoursChange(el) {
  await persistPlanExtractMaxHoursForCurrentSchool(el?.value);
}

async function handlePlanExtractSeatPageIdChange(el) {
  const normalized = normalizeClientPlanExtractSeatPageId(el?.value);
  if (el) el.value = normalized;
  await persistPlanExtractSeatPageIdForCurrentSchool(normalized);
}

const CLIENT_DATE_TEXT_RE = /^\\d{4}-\\d{2}-\\d{2}$/;
const CLIENT_DATE_PAIR_TEXT_RE = /^\\s*(\\d{4}-\\d{2}-\\d{2})\\s*[,，]\\s*(\\d{4}-\\d{2}-\\d{2})\\s*$/;

function parseTimesInput(rawTimes) {
  if (Array.isArray(rawTimes) && rawTimes.length >= 2) {
    return [
      String(rawTimes[0] || "").trim(),
      String(rawTimes[1] || "").trim(),
    ];
  }
  const text = String(rawTimes || "").trim();
  if (!text) return ["", ""];

  const datePairMatch = text.match(CLIENT_DATE_PAIR_TEXT_RE);
  if (datePairMatch) {
    return [datePairMatch[1], datePairMatch[2]];
  }

  const parts = text.split(/-|~|至/).map(s => s.trim()).filter(Boolean);
  if (parts.length >= 2) {
    return [parts[0], parts[1]];
  }
  return [text, ""];
}

function isCustomDayTimes(rawTimes) {
  const [start, end] = parseTimesInput(rawTimes);
  return CLIENT_DATE_TEXT_RE.test(start) && CLIENT_DATE_TEXT_RE.test(end);
}

function normalizeTimesLabel(rawTimes) {
  const [start, end] = parseTimesInput(rawTimes);
  if (start && end) {
    return isCustomDayTimes([start, end]) ? \`\${start}，\${end}\` : \`\${start}-\${end}\`;
  }
  return String(rawTimes || "").trim();
}

function isServerRelayTarget(value) {
  const target = String(value || "").trim().toLowerCase();
  return target === "server_relay";
}

function normalizeReserveDayOffsetInput(value) {
  const text = String(value ?? "").trim();
  if (!text) return null;
  if (!/^\\d+$/.test(text)) return null;
  return Math.max(0, parseInt(text, 10));
}

function parseTestReserveDayOffsetClient(value) {
  const offset = normalizeReserveDayOffsetInput(value);
  return offset === null ? 1 : offset;
}

function normalizeClientTriggerTimeInput(value) {
  const seconds = parseClientTriggerSeconds(value);
  if (seconds === null) return "";
  const hour = Math.floor(seconds / 3600);
  const minute = Math.floor((seconds % 3600) / 60);
  return \`\${String(hour).padStart(2, "0")}:\${String(minute).padStart(2, "0")}\`;
}

function getCurrentSchoolFormalTimeGuard() {
  return {
    formal_trigger_time: normalizeClientTriggerTimeInput(currentSchool?.trigger_time),
    formal_endtime: normalizeClientEndtimeInput(currentSchool?.endtime),
  };
}

function validateTestTimeWindowAgainstFormalClient(testTriggerTime, testEndtime) {
  if (!currentSchool || !testTriggerTime || !testEndtime) return "";
  const normalizedTestTrigger = normalizeClientTriggerTimeInput(testTriggerTime);
  const normalizedFormalTrigger = normalizeClientTriggerTimeInput(currentSchool.trigger_time);
  const normalizedFormalEndtime = normalizeClientEndtimeInput(currentSchool.endtime);
  if (normalizedTestTrigger === normalizedFormalTrigger && testEndtime === normalizedFormalEndtime) {
    return "测试时间不能和正式时间完全一致";
  }
  return "";
}

function formatReserveDayLabel(s) {
  const offset = isServerRelayTarget(s?.dispatch_target)
    ? normalizeReserveDayOffsetInput(s?.reserve_day_offset)
    : null;
  if (offset !== null) {
    if (offset === 0) return "今天（服务器中转 day+0）";
    if (offset === 1) return "明天（服务器中转 day+1）";
    if (offset === 2) return "后天（服务器中转 day+2）";
    return \`北京时间 +\${offset} 天（服务器中转）\`;
  }
  return s?.reserve_next_day === false ? "今天" : "明天";
}

function normalizeClientEndtimeInput(value) {
  const text = String(value || "").trim().replace(/[：.]/g, ":");
  const match = text.match(/^(\\d{1,2}):(\\d{2})(?::(\\d{2}))?$/);
  if (!match) return "";
  const hour = parseInt(match[1], 10);
  const minute = parseInt(match[2], 10);
  const second = parseInt(match[3] || "0", 10);
  if (hour < 0 || hour > 23 || minute < 0 || minute > 59 || second < 0 || second > 59) {
    return "";
  }
  return [
    String(hour).padStart(2, "0"),
    String(minute).padStart(2, "0"),
    String(second).padStart(2, "0"),
  ].join(":");
}

function parseClientTriggerSeconds(value) {
  const text = String(value || "").trim().replace(/[：.]/g, ":");
  const match = text.match(/^(\\d{1,2}):(\\d{2})$/);
  if (!match) return null;
  const hour = parseInt(match[1], 10);
  const minute = parseInt(match[2], 10);
  if (hour < 0 || hour > 23 || minute < 0 || minute > 59) return null;
  return hour * 3600 + minute * 60;
}

function parseClientEndtimeSeconds(value) {
  const normalized = normalizeClientEndtimeInput(value);
  if (!normalized) return null;
  const [hour, minute, second] = normalized.split(":").map(v => parseInt(v, 10));
  return hour * 3600 + minute * 60 + second;
}

function getClientFormalWindowDurationSeconds(startSeconds, endSeconds) {
  if (startSeconds === null || endSeconds === null) return null;
  if (endSeconds === startSeconds) return 0;
  return endSeconds > startSeconds
    ? endSeconds - startSeconds
    : endSeconds + 24 * 60 * 60 - startSeconds;
}

function validateFormalTimeWindowInput(triggerTime, endtime) {
  const startSeconds = parseClientTriggerSeconds(triggerTime);
  if (startSeconds === null) return "正式开始时间格式应为 HH:MM";
  const endSeconds = parseClientEndtimeSeconds(endtime);
  if (endSeconds === null) return "正式截止时间格式应为 HH:MM:SS";
  const durationSeconds = getClientFormalWindowDurationSeconds(startSeconds, endSeconds);
  if (durationSeconds <= 0) return "正式截止时间必须晚于正式开始时间";
  if (durationSeconds > 30 * 60) return "正式开始时间和截止时间间隔不能超过 30 分钟";
  return "";
}

function confirmFormalEndtimeUnder40(endtime) {
  const seconds = parseClientEndtimeSeconds(endtime);
  if (seconds === null || seconds % 60 >= 40) return true;
  const normalized = normalizeClientEndtimeInput(endtime);
  if (!window.confirm("正式截止时间 " + normalized + " 的秒数小于 40，可能影响执行，确定继续吗？")) {
    return false;
  }
  return window.confirm("请再次确认：仍要保存正式截止时间 " + normalized + " 吗？");
}

function getTestEndtimeState(s) {
  const overrideTriggerTime = String(s?.test_endtime_override_trigger_time || "").trim();
  const overrideEndtime = String(s?.test_endtime_override_endtime || "").trim();
  const overrideReserveDayOffset = Number.isInteger(s?.test_endtime_override_reserve_day_offset)
    ? s.test_endtime_override_reserve_day_offset
    : null;
  const expiresMs = Date.parse(s?.test_endtime_override_expires_at || "");
  const active = !!overrideEndtime && Number.isFinite(expiresMs) && expiresMs > Date.now();
  const remainingSeconds = active ? Math.max(0, Math.ceil((expiresMs - Date.now()) / 1000)) : 0;
  return {
    active,
    remainingSeconds,
    overrideTriggerTime,
    overrideEndtime,
    overrideReserveDayOffset,
    effectiveTriggerTime: active ? (overrideTriggerTime || s?.trigger_time || "-") : (s?.trigger_time || "-"),
    effectiveEndtime: active ? overrideEndtime : (s?.endtime || "-"),
    effectiveReserveDayOffset: active && overrideReserveDayOffset !== null
      ? overrideReserveDayOffset
      : parseTestReserveDayOffsetClient(s?.test_reserve_day_offset),
  };
}

function formatRemainingSeconds(seconds) {
  const total = Math.max(0, parseInt(seconds, 10) || 0);
  const min = Math.floor(total / 60);
  const sec = total % 60;
  return \`\${min}分\${String(sec).padStart(2, "0")}秒\`;
}

function renderTestEndtimePanel(s) {
  const state = getTestEndtimeState(s);
  const triggerInputValue = escapeHtml(s?.test_trigger_time || state.overrideTriggerTime || s?.trigger_time || "");
  const endtimeInputValue = escapeHtml(s?.test_endtime || state.overrideEndtime || "");
  const testReserveDayOffset = parseTestReserveDayOffsetClient(s?.test_reserve_day_offset);
  const testDayText = state.effectiveReserveDayOffset === 0 ? "今天" : "明天";
  return \`
    <div class="test-override-panel">
      <div class="test-override-status">
        <strong>测试覆盖:</strong>
        <span id="test_endtime_status_pill" class="test-status-pill \${state.active ? "test-status-on" : "test-status-off"}">\${state.active ? "开" : "关"}</span>
        <span id="test_endtime_status_text">\${state.active ? \`当前使用测试开始时间 \${state.effectiveTriggerTime}，测试截止时间 \${state.overrideEndtime}，预约\${testDayText}，剩余 \${formatRemainingSeconds(state.remainingSeconds)}\` : \`当前使用正式开始时间 \${s?.trigger_time || "-"}，正式截止时间 \${s?.endtime || "-"}\`}</span>
      </div>
      <div class="test-override-row">
        <div class="form-group" style="margin-bottom:0">
          <label>测试开始时间 (HH:MM)</label>
          <input type="text" id="school_test_trigger_time" value="\${triggerInputValue}" placeholder="例如: 19:57">
        </div>
        <div class="form-group" style="margin-bottom:0">
          <label>测试截止时间 (HH:MM:SS)</label>
          <input type="text" id="school_test_endtime" value="\${endtimeInputValue}" placeholder="例如: 20:00:40">
        </div>
        <button type="button" class="btn btn-success" onclick="startTestEndtimeOverride()">测试启动</button>
        <button type="button" class="btn btn-secondary" onclick="stopTestEndtimeOverride()">关闭测试</button>
      </div>
      <div class="test-override-day-row">
        <label><input type="radio" name="school_test_reserve_day" value="0" \${testReserveDayOffset === 0 ? "checked" : ""}> 预约今天</label>
        <label><input type="radio" name="school_test_reserve_day" value="1" \${testReserveDayOffset !== 0 ? "checked" : ""}> 预约明天</label>
      </div>
      <div class="test-override-note">
        测试启动后 3 分钟内覆盖当前学校/组的开始时间和截止时间；手动触发使用测试时间，Worker 定时触发在正式窗口未命中时使用测试时间，到期后自动回到正式时间。
      </div>
    </div>
  \`;
}

function getReadingZoneGroups() {
  const groups = currentSchool && Array.isArray(currentSchool.reading_zone_groups)
    ? currentSchool.reading_zone_groups
    : [];
  const normalized = normalizeReadingZoneGroups(groups);
  return normalized.length ? normalized : DEFAULT_READING_ZONE_GROUPS;
}

function normalizeReadingZoneGroups(raw) {
  if (!Array.isArray(raw) || raw.length === 0) return [];

  const normalizedGroups = [];
  const flatZones = [];

  for (const item of raw) {
    if (!item || typeof item !== "object") continue;

    // 结构1: [{ floor, zones: [{id,name}] }]
    if (Array.isArray(item.zones)) {
      const floor = String(item.floor || "未分层").trim() || "未分层";
      const zones = item.zones
        .map((z) => {
          if (!z || typeof z !== "object") return null;
          const id = String(z.id || z.roomid || "").trim();
          if (!id) return null;
          const name = String(z.name || z.roomName || z.title || id).trim() || id;
          return { id, name };
        })
        .filter(Boolean);

      if (zones.length) normalizedGroups.push({ floor, zones });
      continue;
    }

    // 结构2: [{ roomid, name, ... }] （extract_room_ids.py --json 输出）
    const id = String(item.roomid || item.id || "").trim();
    if (id) {
      const name = String(item.name || item.roomName || id).trim() || id;
      flatZones.push({ id, name });
    }
  }

  if (flatZones.length) normalizedGroups.push({ floor: "未分层", zones: flatZones });
  return normalizedGroups;
}

function _emptySlot() {
  return { roomid: "", seatid: "", times: "", seatPageId: "", fidEnc: "", backupSeats: "" };
}

function normalizePlanExtractTime(value) {
  const text = String(value || "").trim().replace(/[：∶.．。]/g, ":");
  const match = text.match(/^(\\d{1,2}):(\\d{2})$/);
  if (!match) return text;
  return \`\${match[1].padStart(2, "0")}:\${match[2].padStart(2, "0")}\`;
}

function planExtractTimeToMinutes(value) {
  const normalized = normalizePlanExtractTime(value);
  const match = normalized.match(/^(\\d{2}):(\\d{2})$/);
  if (!match) return null;
  const hour = parseInt(match[1], 10);
  const minute = parseInt(match[2], 10);
  if (Number.isNaN(hour) || Number.isNaN(minute)) return null;
  return hour * 60 + minute;
}

function planExtractMinutesToTime(totalMinutes) {
  const hour = Math.floor(totalMinutes / 60);
  const minute = totalMinutes % 60;
  return \`\${String(hour).padStart(2, "0")}:\${String(minute).padStart(2, "0")}\`;
}

function splitPlanExtractTimeRange(start, end, maxHoursPerObject = PLAN_EXTRACT_MAX_HOURS_DEFAULT) {
  const normalizedStart = normalizePlanExtractTime(start);
  const normalizedEnd = normalizePlanExtractTime(end);
  const startMinutes = planExtractTimeToMinutes(normalizedStart);
  const endMinutes = planExtractTimeToMinutes(normalizedEnd);

  if (startMinutes === null || endMinutes === null || endMinutes <= startMinutes) {
    return [[normalizedStart, normalizedEnd]];
  }

  const maxHours = Number(maxHoursPerObject);
  if (!Number.isFinite(maxHours) || maxHours <= 0) {
    return [[normalizedStart, normalizedEnd]];
  }

  const maxMinutes = Math.floor(maxHours * 60);
  if (maxMinutes <= 0) {
    return [[normalizedStart, normalizedEnd]];
  }

  const segments = [];
  let current = startMinutes;
  while (current < endMinutes) {
    const nextEnd = Math.min(current + maxMinutes, endMinutes);
    segments.push([planExtractMinutesToTime(current), planExtractMinutesToTime(nextEnd)]);
    current = nextEnd;
  }
  return segments;
}

function extractPlanTextMapping(rawText, options = {}) {
  const text = String(rawText || "")
    .replace(/(\\d{1,2})\\s*点\\s*半/g, "$1:30")
    .replace(/(\\d{1,2})\\s*点(?:整)?/g, "$1:00");
  if (!text.trim()) {
    throw new Error("请先粘贴计划文本");
  }

  let roomid = "";
  let seatid = [];
  let seatPageId = String(options.seatPageId || "").trim();
  const fidEnc = String(options.fidEnc || "").trim();
  const lines = text.split(/\\r?\\n/);
  const roomPatterns = [
    /(?:自习室|阅览室|阅览区|房间)\\s*(?:id)?\\s*[：:=]?\\s*(\\d{3,})/i,
    /(?:roomid|room_id|room-id)\\s*[：:=]?\\s*(\\d{3,})/i,
    /(?:自习室|阅览室|阅览区|房间)\\D*(\\d{3,})/i,
  ];
  const seatPatterns = [
    /(?:座位号|座位|seatid|seat)\\s*[：:=]?\\s*([^\\n\\r]+)/i,
  ];

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line) continue;

    if (!roomid) {
      for (const pattern of roomPatterns) {
        const roomMatch = line.match(pattern);
        if (roomMatch) {
          roomid = roomMatch[1];
          break;
        }
      }
    }

    if (!seatPageId) {
      const seatPageMatch = line.match(/(?:seatpageid|seatPageId|页面id|页id)\\s*[：:=]?\\s*(\\d{3,})/i);
      if (seatPageMatch) {
        seatPageId = seatPageMatch[1];
      }
    }

    if (!seatid.length) {
      for (const pattern of seatPatterns) {
        const seatMatch = line.match(pattern);
        if (!seatMatch) continue;
        const nextSeats = String(seatMatch[1] || "").match(/\\d+/g);
        if (nextSeats && nextSeats.length) {
          seatid = nextSeats.map(v => String(v).padStart(3, "0"));
          break;
        }
      }
    }
  }

  if (!roomid) {
    for (const pattern of roomPatterns) {
      const roomMatch = text.match(pattern);
      if (roomMatch) {
        roomid = roomMatch[1];
        break;
      }
    }
  }
  if (!seatPageId) {
    const seatPageMatch = text.match(/(?:seatpageid|seatPageId|页面id|页id)\\s*[：:=]?\\s*(\\d{3,})/i);
    if (seatPageMatch) {
      seatPageId = seatPageMatch[1];
    }
  }
  if (!seatid.length) {
    for (const pattern of seatPatterns) {
      const seatMatch = text.match(pattern);
      if (!seatMatch) continue;
      const nextSeats = String(seatMatch[1] || "").match(/\\d+/g);
      if (nextSeats && nextSeats.length) {
        seatid = nextSeats.map(v => String(v).padStart(3, "0"));
        break;
      }
    }
  }

  if (!roomid) {
    throw new Error("未识别到自习室/阅览区/房间 ID");
  }
  if (!seatid.length) {
    throw new Error("未识别到座位号");
  }
  if (!seatPageId) {
    seatPageId = roomid;
  }

  const plans = [];
  const dayPrefixPattern = /^(周[一二三四五六日天])\\s*[:：∶]?\\s*(.*)$/;
  const everydayPrefixPattern = /^每天\\s*[:：=∶]?\\s*(.*)$/;
  const timeBlockPrefixPattern = /^时间段\\s*[:：=∶]?\\s*(.*)$/;
  const timeRangePattern = /(\\d{1,2}[:：∶.．。]\\d{2})\\s*[-~—–至到]\\s*(\\d{1,2}[:：∶.．。]\\d{2})/g;

  const appendPlan = (daysofweek, start, end) => {
    const segments = splitPlanExtractTimeRange(start, end, options.maxHoursPerObject);
    for (const [segmentStart, segmentEnd] of segments) {
      plans.push({
        times: [segmentStart, segmentEnd],
        roomid,
        seatid: seatid.slice(),
        seatPageId,
        fidEnc,
        daysofweek,
      });
    }
  };

  let activeDaysofweek = null;
  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line) continue;

    const dayMatch = line.match(dayPrefixPattern);
    if (dayMatch) {
      const dayEn = PLAN_EXTRACT_WEEK_MAP[dayMatch[1]];
      if (!dayEn) continue;
      activeDaysofweek = [dayEn];
      for (const match of dayMatch[2].matchAll(timeRangePattern)) {
        appendPlan([dayEn], match[1], match[2]);
      }
      continue;
    }

    const everydayMatch = line.match(everydayPrefixPattern);
    if (everydayMatch) {
      activeDaysofweek = PLAN_EXTRACT_ALL_DAYS.slice();
      for (const match of everydayMatch[1].matchAll(timeRangePattern)) {
        appendPlan(PLAN_EXTRACT_ALL_DAYS.slice(), match[1], match[2]);
      }
      continue;
    }

    const timeBlockMatch = line.match(timeBlockPrefixPattern);
    if (timeBlockMatch) {
      activeDaysofweek = activeDaysofweek || PLAN_EXTRACT_ALL_DAYS.slice();
      for (const match of timeBlockMatch[1].matchAll(timeRangePattern)) {
        appendPlan(activeDaysofweek.slice(), match[1], match[2]);
      }
      continue;
    }

    if (activeDaysofweek) {
      for (const match of line.matchAll(timeRangePattern)) {
        appendPlan(activeDaysofweek.slice(), match[1], match[2]);
      }
    }
  }

  if (!plans.length) {
    throw new Error("未识别到有效的周计划时间段");
  }
  return plans;
}

function createEmptyWeeklySchedule() {
  const days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
  const schedule = {};
  for (const d of days) {
    schedule[d] = { enabled: false, slots: [_emptySlot(), _emptySlot(), _emptySlot(), _emptySlot()] };
  }
  return schedule;
}

function parseScheduleJsonMapping(rawText) {
  const parsed = JSON.parse(rawText);
  const items = Array.isArray(parsed) ? parsed : (parsed && typeof parsed === "object" ? [parsed] : []);
  if (!items.length) {
    throw new Error("周计划 JSON 必须是对象或数组");
  }

  const schedule = createEmptyWeeklySchedule();
  for (const item of items) {
    if (!item || typeof item !== "object") continue;

    const roomid = String(item.roomid || "").trim();
    const seatPageId = String(item.seatPageId || item.roomid || "").trim();
    const fidEnc = String(item.fidEnc || "").trim();
    const backupSeats = String(item.backupSeats || "").trim();

    const times = normalizeTimesLabel(item.times);

    let seatid = item.seatid;
    if (Array.isArray(seatid)) {
      seatid = seatid.map(v => String(v).trim()).filter(Boolean).join(",");
    } else {
      seatid = String(seatid || "").trim();
    }

    const daysofweek = Array.isArray(item.daysofweek) ? item.daysofweek : [];
    for (const day of daysofweek) {
      if (!schedule[day]) continue;
      schedule[day].enabled = true;
      schedule[day].slots.push({ roomid, seatid, times, seatPageId, fidEnc, backupSeats });
    }
  }

  for (const day of Object.keys(schedule)) {
    const slots = (schedule[day].slots || []).filter(s => s && (s.roomid || s.times));
    if (slots.length === 0) {
      schedule[day].enabled = false;
      schedule[day].slots = [_emptySlot(), _emptySlot(), _emptySlot(), _emptySlot()];
      continue;
    }
    schedule[day].slots = slots;
  }

  return schedule;
}

function scheduleToJsonMapping(schedule) {
  const result = [];
  const days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
  for (const day of days) {
    const dayCfg = schedule?.[day];
    if (!dayCfg || !dayCfg.enabled) continue;
    const slots = Array.isArray(dayCfg.slots)
      ? dayCfg.slots
      : [{ roomid: dayCfg.roomid, seatid: dayCfg.seatid, times: dayCfg.times, seatPageId: dayCfg.seatPageId, fidEnc: dayCfg.fidEnc, backupSeats: dayCfg.backupSeats }];
    for (const s of slots) {
      if (!s || !s.roomid || !s.times) continue;
      const times = parseTimesInput(s.times);
      const seatid = String(s.seatid || "").split(",").map(x => x.trim()).filter(Boolean);
      result.push({
        times,
        roomid: String(s.roomid || ""),
        seatid,
        seatPageId: String(s.seatPageId || s.roomid || ""),
        fidEnc: String(s.fidEnc || ""),
        backupSeats: String(s.backupSeats || ""),
        daysofweek: [day],
      });
    }
  }
  return result;
}

function scheduleToStandardText(schedule) {
  const dayNames = {
    Monday: "周一",
    Tuesday: "周二",
    Wednesday: "周三",
    Thursday: "周四",
    Friday: "周五",
    Saturday: "周六",
    Sunday: "周日",
  };
  const items = scheduleToJsonMapping(schedule);
  const first = items[0];
  if (!first) return "";

  const lines = [
    "自习室id:" + first.roomid,
    "座位号:" + first.seatid.join(","),
    "时间段:",
  ];
  for (const day of Object.keys(dayNames)) {
    const ranges = items
      .filter(item => item.daysofweek.includes(day))
      .map(item => item.times.join("-"));
    if (ranges.length) lines.push(dayNames[day] + ":" + ranges.join(","));
  }
  return lines.join("\\n");
}

function fillScheduleFormFromSchedule(schedule) {
  const days = ["Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday"];
  days.forEach(d => {
    const sch = schedule?.[d] || {};
    document.getElementById("sch_" + d + "_enabled").checked = !!sch.enabled;
    const slots = sch.slots || [{ roomid: sch.roomid, seatid: sch.seatid, times: sch.times, seatPageId: sch.seatPageId, fidEnc: sch.fidEnc, backupSeats: sch.backupSeats }];
    const activeCount = slots.filter(s => s && (s.roomid || s.seatid || s.times || s.seatPageId || s.fidEnc || s.backupSeats)).length;
    const visibleCount = Math.max(1, Math.min(4, activeCount || 1));
    setVisibleSlotsForDay(d, visibleCount);
    [0,1,2,3].forEach(i => {
      const s = slots[i] || {};
      document.getElementById("sch_" + d + "_s" + i + "_roomid").value = s.roomid || "";
      document.getElementById("sch_" + d + "_s" + i + "_seatid").value = s.seatid || "";
      document.getElementById("sch_" + d + "_s" + i + "_times").value = s.times || "";
      document.getElementById("sch_" + d + "_s" + i + "_seatPageId").value = s.seatPageId || "";
      document.getElementById("sch_" + d + "_s" + i + "_fidEnc").value = s.fidEnc || "";
      const backupSeats = String(s.backupSeats || "");
      document.getElementById("sch_" + d + "_s" + i + "_backupSeats").value = backupSeats;
    });
  });
}

function buildScheduleFromForm() {
  const days = ["Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday"];
  const schedule = {};
  days.forEach(d => {
    const visibleCount = getVisibleSlotsForDay(d);
    const slotIndexes = Array.from({ length: visibleCount }, (_, i) => i);
    const slots = slotIndexes.map(i => ({
      roomid: document.getElementById("sch_" + d + "_s" + i + "_roomid").value.trim(),
      seatid: document.getElementById("sch_" + d + "_s" + i + "_seatid").value.trim(),
      times: document.getElementById("sch_" + d + "_s" + i + "_times").value.trim(),
      seatPageId: document.getElementById("sch_" + d + "_s" + i + "_seatPageId").value.trim(),
      fidEnc: document.getElementById("sch_" + d + "_s" + i + "_fidEnc").value.trim(),
      backupSeats: document.getElementById("sch_" + d + "_s" + i + "_backupSeats").value.trim(),
    }));
    schedule[d] = {
      enabled: document.getElementById("sch_" + d + "_enabled").checked,
      slots,
    };
  });
  return schedule;
}

function createRectangleTextEditor(textarea) {
  if (typeof CodeMirror !== "function") return null;
  const editor = CodeMirror.fromTextArea(textarea, {
    lineNumbers: false,
    lineWrapping: true,
  });
  editor.getWrapperElement().addEventListener("mousedown", event => {
    if (event.button !== 1) return;
    event.preventDefault();
    event.stopPropagation();
    const cm = editor;
    const start = cm.coordsChar({ left: event.clientX, top: event.clientY }, "window");
    const selectRectangle = moveEvent => {
      const end = cm.coordsChar({ left: moveEvent.clientX, top: moveEvent.clientY }, "window");
      const firstLine = Math.min(start.line, end.line);
      const lastLine = Math.max(start.line, end.line);
      cm.getDoc().setSelections(Array.from(
        { length: lastLine - firstLine + 1 },
        (_, index) => ({
          anchor: { line: firstLine + index, ch: start.ch },
          head: { line: firstLine + index, ch: end.ch },
        }),
      ));
    };
    const finish = upEvent => {
      selectRectangle(upEvent);
      window.removeEventListener("mousemove", selectRectangle);
      window.removeEventListener("mouseup", finish);
      cm.focus();
    };
    window.addEventListener("mousemove", selectRectangle);
    window.addEventListener("mouseup", finish);
    selectRectangle(event);
  }, true);
  editor.on("change", cm => {
    textarea.value = cm.getValue();
    if (textarea.id === "plan_extract_input") persistPlanMappingDraft();
  });
  return editor;
}

function getScheduleTextEditor() {
  const textarea = document.getElementById("edit_user_schedule_json");
  if (!textarea) return null;
  if (scheduleTextEditor?.getTextArea() === textarea) return scheduleTextEditor;
  scheduleTextEditor = createRectangleTextEditor(textarea);
  return scheduleTextEditor;
}

function getPlanExtractTextEditor() {
  const textarea = document.getElementById("plan_extract_input");
  if (!textarea) return null;
  if (planExtractTextEditor?.getTextArea() === textarea) return planExtractTextEditor;
  planExtractTextEditor = createRectangleTextEditor(textarea);
  return planExtractTextEditor;
}

function getScheduleText() {
  const textarea = document.getElementById("edit_user_schedule_json");
  return getScheduleTextEditor()?.getValue() ?? textarea?.value ?? "";
}

function setScheduleText(value) {
  const nextValue = value || "";
  const textarea = document.getElementById("edit_user_schedule_json");
  const editor = getScheduleTextEditor();
  if (editor) {
    if (editor.getValue() !== nextValue) editor.setValue(nextValue);
  } else if (textarea) {
    textarea.value = nextValue;
  }
}

const USER_GLOBAL_SYNC_FIELDS = [
  { key: "roomid", label: "房间ID", inputId: "global_sync_roomid", normalize: value => String(value || "").trim() },
  { key: "seatid", label: "座位号", inputId: "global_sync_seatid", normalize: value => String(value || "").trim() },
  { key: "times", label: "时间段", inputId: "global_sync_times", normalize: value => normalizeTimesLabel(value) },
  { key: "seatPageId", label: "页面ID", inputId: "global_sync_seatPageId", normalize: value => String(value || "").trim() },
  { key: "fidEnc", label: "fidEnc", inputId: "global_sync_fidEnc", normalize: value => String(value || "").trim() },
  { key: "backupSeats", label: "备选座位", inputId: "global_sync_backupSeats", normalize: value => String(value || "").trim() },
];

function resetUserGlobalSyncInputs() {
  USER_GLOBAL_SYNC_FIELDS.forEach(field => {
    const el = document.getElementById(field.inputId);
    if (el) el.value = "";
  });
}

function syncScheduleJsonFromCurrentForm() {
  setScheduleText(scheduleToStandardText(buildScheduleFromForm()));
}

function applyUserGlobalConfigSync() {
  const syncValues = USER_GLOBAL_SYNC_FIELDS
    .map(field => {
      const el = document.getElementById(field.inputId);
      const value = field.normalize(el && el.value);
      return value ? { ...field, value } : null;
    })
    .filter(Boolean);
  if (!syncValues.length) {
    return toast("请至少填写一个要同步的字段", "error");
  }

  const days = ["Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday"];
  let changed = 0;
  days.forEach(d => {
    const visibleCount = getVisibleSlotsForDay(d);
    Array.from({ length: visibleCount }, (_, i) => i).forEach(i => {
      const slotFields = ["roomid", "seatid", "times", "seatPageId", "fidEnc", "backupSeats"].map(key => (
        document.getElementById("sch_" + d + "_s" + i + "_" + key)
      ));
      const hasExistingConfig = slotFields.some(el => el && String(el.value || "").trim());
      if (!hasExistingConfig) return;

      let slotChanged = false;
      syncValues.forEach(field => {
        const el = document.getElementById("sch_" + d + "_s" + i + "_" + field.key);
        if (!el || el.value === field.value) return;
        el.value = field.value;
        slotChanged = true;
      });
      if (slotChanged) changed += 1;
    });
  });

  if (!changed) return toast("当前没有已有配置需要同步", "error");
  syncScheduleJsonFromCurrentForm();
  toast("已同步 " + changed + " 条配置");
}

function setVisibleSlotsForDay(day, count) {
  const visibleCount = Math.max(1, Math.min(4, parseInt(count, 10) || 1));
  [0,1,2,3].forEach(i => {
    const row = document.getElementById("sch_" + day + "_row_" + i);
    if (!row) return;
    row.style.display = i < visibleCount ? "" : "none";
  });
}

function getVisibleSlotsForDay(day) {
  let count = 0;
  [0,1,2,3].forEach(i => {
    const row = document.getElementById("sch_" + day + "_row_" + i);
    if (row && row.style.display !== "none") count++;
  });
  return Math.max(1, count);
}

function addSlotForDay(day) {
  const current = getVisibleSlotsForDay(day);
  setVisibleSlotsForDay(day, current + 1);
}

function inheritMappedUserScheduleConfig(mappedSchedule, existingSchedule) {
  const fallback = Object.values(existingSchedule || {})
    .flatMap(day => Array.isArray(day?.slots) ? day.slots : [])
    .find(slot => slot && (slot.roomid || slot.seatPageId || slot.fidEnc));
  for (const day of Object.keys(mappedSchedule || {})) {
    const mappedSlots = mappedSchedule[day]?.slots || [];
    const existingSlots = existingSchedule?.[day]?.slots || [];
    mappedSchedule[day].slots = mappedSlots.map((slot, index) => {
      const inherited = existingSlots[index] || fallback || {};
      return {
        ...slot,
        roomid: inherited.roomid || slot.roomid,
        seatPageId: inherited.seatPageId || inherited.roomid || slot.seatPageId,
        fidEnc: inherited.fidEnc || currentSchool?.fidEnc || slot.fidEnc,
        backupSeats: inherited.backupSeats || "",
      };
    });
  }
  return mappedSchedule;
}

function applyScheduleJsonToForm() {
  const scheduleJsonText = getScheduleText().trim();
  if (!scheduleJsonText) return toast("请先填写周计划文字或 JSON", "error");
  try {
    let schedule = /^[{[]/.test(scheduleJsonText)
      ? parseScheduleJsonMapping(scheduleJsonText)
      : parseScheduleJsonMapping(JSON.stringify(extractPlanTextMapping(scheduleJsonText, {
          maxHoursPerObject: 0,
          seatPageId: getPlanExtractSeatPageIdDefaultForCurrentSchool(),
          fidEnc: currentSchool?.fidEnc || "",
        })));
    if (document.getElementById("edit_user_id")?.value) {
      schedule = inheritMappedUserScheduleConfig(schedule, buildScheduleFromForm());
    }
    fillScheduleFormFromSchedule(schedule);
    toast("已映射到周计划配置");
  } catch (e) {
    toast("周计划映射失败: " + (e.message || String(e)), "error");
  }
}

function buildPlanMappingFromPanel() {
  const inputEl = document.getElementById("plan_extract_input");
  const outputEl = document.getElementById("plan_extract_output");
  const maxHoursEl = document.getElementById("plan_extract_max_hours");
  const seatPageIdEl = document.getElementById("plan_extract_seat_page_id");
  if (!inputEl || !outputEl || !maxHoursEl) {
    throw new Error("映射面板尚未加载完成");
  }

  const maxHoursText = String(maxHoursEl.value || "").trim();
  const seatPageIdText = normalizeClientPlanExtractSeatPageId(seatPageIdEl?.value || "");
  if (seatPageIdEl) seatPageIdEl.value = seatPageIdText;
  let maxHours = Number(getPlanExtractMaxHoursDefaultForCurrentSchool());
  if (maxHoursText !== "") {
    maxHours = Number(maxHoursText);
    if (!Number.isFinite(maxHours) || maxHours < 0) {
      throw new Error("最长时段小时数必须是大于等于 0 的数字");
    }
    persistPlanExtractMaxHoursForCurrentSchool(maxHoursText);
  }
  persistPlanExtractSeatPageIdForCurrentSchool(seatPageIdText);

  const plans = extractPlanTextMapping(getPlanExtractTextEditor()?.getValue() ?? inputEl.value, {
    maxHoursPerObject: maxHours,
    seatPageId: seatPageIdText,
    fidEnc: currentSchool?.fidEnc || "",
  });
  const jsonText = JSON.stringify(plans, null, 2);
  outputEl.value = jsonText;
  return { plans, jsonText };
}

function generatePlanMappingJson() {
  try {
    buildPlanMappingFromPanel();
    toast("已生成周计划 JSON");
  } catch (e) {
    toast("计划文本映射失败: " + (e.message || String(e)), "error");
  }
}

async function copyPlanMappingJson() {
  const outputEl = document.getElementById("plan_extract_output");
  if (!outputEl || !String(outputEl.value || "").trim()) {
    return toast("请先生成周计划 JSON", "error");
  }
  await copyTextToClipboard(outputEl.value, "已复制周计划 JSON");
}

function createMappedUserDraft() {
  try {
    const { plans, jsonText } = buildPlanMappingFromPanel();
    const first = plans[0] || {};
    const firstSeat = Array.isArray(first.seatid) ? first.seatid.join(",") : "";
    const phone = String(document.getElementById("plan_extract_phone")?.value || "").trim();
    const password = String(document.getElementById("plan_extract_password")?.value || "");
    const username = String(document.getElementById("plan_extract_username")?.value || "").trim();
    showAddUser({
      phone,
      password,
      username,
      remark: first.roomid && firstSeat ? \`自动映射 \${first.roomid}/\${firstSeat}\` : "自动映射",
      scheduleJsonText: jsonText,
      schedule: parseScheduleJsonMapping(jsonText),
    }, { clearPlanMappingAfterSave: true });
    toast("已生成新用户草稿");
  } catch (e) {
    toast("生成新用户草稿失败: " + (e.message || String(e)), "error");
  }
}

async function api(method, path, body = null) {
  const opts = {
    method,
    headers: { "Content-Type": "application/json", "X-API-Key": API_KEY },
  };
  if (body) opts.body = JSON.stringify(body);
  let res;
  try {
    res = await fetch(API_BASE + path, opts);
  } catch (e) {
    return { ok: false, error: "网络请求失败", detail: e.message || String(e), status: 0 };
  }

  const raw = await res.text();
  let data;
  try {
    data = raw ? JSON.parse(raw) : {};
  } catch (_e) {
    data = { ok: res.ok };
    if (!res.ok) {
      data.error = "HTTP " + res.status;
      data.detail = raw;
    }
  }

  if (!data || typeof data !== "object") data = { ok: res.ok };
  if (data.status === undefined) data.status = res.status;
  if (!res.ok && !data.error) data.error = "HTTP " + res.status;
  return data;
}

function toast(msg, type = "success") {
  const t = document.createElement("div");
  t.className = "toast toast-" + type;
  t.textContent = msg;
  document.body.appendChild(t);
  setTimeout(() => t.remove(), 3000);
}

let schoolSaveNotice = null;
let dismissSchoolSaveNotice = null;

function showSchoolSaveNotice(message) {
  if (schoolSaveNotice) schoolSaveNotice.remove();
  if (dismissSchoolSaveNotice) document.removeEventListener("click", dismissSchoolSaveNotice, true);
  const notice = document.createElement("div");
  notice.className = "school-save-notice";
  notice.textContent = message;
  document.body.appendChild(notice);
  schoolSaveNotice = notice;
  dismissSchoolSaveNotice = () => {
    notice.remove();
    if (schoolSaveNotice === notice) schoolSaveNotice = null;
    document.removeEventListener("click", dismissSchoolSaveNotice, true);
    dismissSchoolSaveNotice = null;
  };
  setTimeout(() => document.addEventListener("click", dismissSchoolSaveNotice, true), 0);
}

function schoolNoticeValue(value) {
  if (typeof value === "boolean") return value ? "开启" : "关闭";
  if (value === null || value === undefined || value === "") return "未设置";
  if (Array.isArray(value)) return value.length ? value.join(",") : "未设置";
  return String(value);
}

function buildSchoolSaveNotice(before, after, changedServerApiKey = false) {
  const fields = [
    ["name", "学校名称"], ["repo", "仓库"], ["dispatch_target", "分发方式"],
    ["conflict_group", "冲突组"], ["ignore_seat_conflicts", "忽略冲突"],
    ["github_token_key", "GitHub 密钥名"], ["trigger_time", "开始时间"],
    ["endtime", "截止时间"], ["fidEnc", "fidEnc"], ["seat_api_mode", "选座接口"],
    ["reserve_next_day", "预约明天"], ["reserve_day_offset", "日期偏移"],
    ["schedule_store_by_reserve_date", "按预约日存计划"], ["enable_slider", "滑块验证码"],
    ["enable_textclick", "文字验证码"], ["enable_iconclick", "图标验证码"],
    ["iconclick_ocr_provider", "图标识别服务"], ["enable_rotate", "旋转验证码"],
    ["rotate_ocr_provider", "旋转识别服务"],
    ["server_url", "服务器地址"], ["server_max_concurrency", "服务器并发数"],
    ["plan_extract_max_hours", "最长时间段"], ["plan_extract_seat_page_id", "计划 seatPageId"],
  ];
  const strategyFields = [
    ["mode", "策略模式"], ["submit_mode", "提交方式"],
    ["login_lead_seconds_range", "登录提前范围"], ["slider_lead_seconds_range", "滑块提前范围"],
    ["warm_connection_lead_ms", "连接预热"], ["fast_probe_start_range_ms", "快速探测范围"],
    ["pre_fetch_token_range_ms", "Token 预取范围"], ["first_submit_offset_range_ms", "首次提交范围"],
    ["token_fetch_delay_ms", "Token 延迟"], ["token_fetch_timeout_ms", "Token 超时"],
    ["fast_probe_timeout_ms", "快速探测超时"], ["first_token_date_mode", "Token 日期"],
    ["skip_first_seat_query", "跳过首次查座"],
  ];
  const lines = [];
  const append = (label, oldValue, newValue) => {
    if (JSON.stringify(oldValue) === JSON.stringify(newValue)) return;
    lines.push(label + "：" + schoolNoticeValue(oldValue) + " → " + schoolNoticeValue(newValue));
  };
  fields.forEach(([key, label]) => append(label, before?.[key], after?.[key]));
  strategyFields.forEach(([key, label]) => append(label, before?.strategy?.[key], after?.strategy?.[key]));
  if (JSON.stringify(before?.reading_zone_groups || []) !== JSON.stringify(after?.reading_zone_groups || [])) {
    lines.push("阅览区映射：已更新");
  }
  if (changedServerApiKey) lines.push("服务器密钥：已更新");
  return lines.length
    ? "学校配置已生效（版本 " + (after?.config_revision || 1) + "）\\n" + lines.join("\\n")
    : "学校配置未修改";
}

function setUserSavePending(pending) {
  isSavingUser = pending;
  const btn = document.getElementById("saveUserButton");
  if (!btn) return;
  btn.disabled = pending;
  btn.textContent = pending ? "保存中..." : "保存用户";
}

function setUserMigratePending(pending) {
  isMigratingUser = pending;
  const btn = document.getElementById("migrateUserButton");
  if (!btn) return;
  btn.disabled = pending;
  btn.textContent = pending ? "迁移中..." : "迁移用户";
}

function toggleUserTopConfigFields() {
  const enabled = document.getElementById("edit_user_top_config_enabled");
  const fields = document.getElementById("edit_user_top_config_fields");
  if (enabled && fields) fields.style.display = enabled.checked ? "" : "none";
}

function toggleAutoSignFields() {
  const visible = document.getElementById("edit_user_sign_feature_visible");
  const fields = document.getElementById("edit_user_auto_sign_fields");
  const enabled = document.getElementById("edit_user_auto_sign_enabled");
  const allowed = !!visible?.checked;
  if (fields) fields.style.display = allowed ? "" : "none";
  if (enabled) {
    enabled.disabled = !allowed;
    if (!allowed) enabled.checked = false;
  }
}

function normalizeSliderLeadRangeValueMs(value) {
  const parsed = parseInt(value, 10);
  const milliseconds = parsed >= 0 && parsed < 30 ? parsed * 1000 : parsed;
  return Math.max(5000, Number.isNaN(milliseconds) ? 10000 : milliseconds);
}

function fillUserTopConfigForm(enabled, config = {}) {
  document.getElementById("edit_user_top_config_enabled").checked = !!enabled;
  document.getElementById("edit_user_top_prefetch_range").value = Array.isArray(config.pre_fetch_token_range_ms)
    ? config.pre_fetch_token_range_ms.join(",")
    : "";
  document.getElementById("edit_user_top_first_submit_range").value = Array.isArray(config.first_submit_offset_range_ms)
    ? config.first_submit_offset_range_ms.join(",")
    : "";
  document.getElementById("edit_user_top_probe_start_range").value = Array.isArray(config.fast_probe_start_range_ms)
    ? config.fast_probe_start_range_ms.join(",")
    : "";
  document.getElementById("edit_user_top_mode").value = config.mode || "";
  document.getElementById("edit_user_top_endtime").value = config.endtime || "";
  document.getElementById("edit_user_top_first_token_date_mode").value = config.first_token_date_mode || "";
  document.getElementById("edit_user_top_slider_range").value = Array.isArray(config.slider_lead_seconds_range)
    ? config.slider_lead_seconds_range.map(normalizeSliderLeadRangeValueMs).join(",")
    : "";
  toggleUserTopConfigFields();
}

function buildUserTopConfigFromForm() {
  const config = {};
  const parseOptionalRange = (id, label) => {
    const text = document.getElementById(id).value.trim();
    if (!text) return null;
    const parts = text.split(",").map(value => Number(value.trim()));
    if (parts.length !== 2 || parts.some(value => !Number.isInteger(value))) {
      throw new Error(label + "应填写两个用逗号分隔的整数");
    }
    return parts;
  };
  const prefetchRange = parseOptionalRange("edit_user_top_prefetch_range", "预取 token 随机范围");
  const firstSubmitRange = parseOptionalRange("edit_user_top_first_submit_range", "首枪偏移随机范围");
  const probeStartRange = parseOptionalRange("edit_user_top_probe_start_range", "轻探测随机范围");
  const sliderRange = parseOptionalRange("edit_user_top_slider_range", "验证码预热提前随机范围");
  if (prefetchRange) config.pre_fetch_token_range_ms = prefetchRange;
  if (firstSubmitRange) config.first_submit_offset_range_ms = firstSubmitRange;
  if (probeStartRange) config.fast_probe_start_range_ms = probeStartRange;
  if (sliderRange) config.slider_lead_seconds_range = sliderRange.map(normalizeSliderLeadRangeValueMs);

  const mode = document.getElementById("edit_user_top_mode").value;
  if (mode) config.mode = mode;
  const endtime = document.getElementById("edit_user_top_endtime").value.trim();
  if (endtime) {
    const normalizedEndtime = normalizeClientEndtimeInput(endtime);
    if (!normalizedEndtime) throw new Error("用户级正式截止时间格式应为 HH:MM:SS");
    const timeWindowError = validateFormalTimeWindowInput(currentSchool?.trigger_time, normalizedEndtime);
    if (timeWindowError) throw new Error("用户级" + timeWindowError);
    config.endtime = normalizedEndtime;
  }
  const firstTokenDateMode = document.getElementById("edit_user_top_first_token_date_mode").value;
  if (firstTokenDateMode) config.first_token_date_mode = firstTokenDateMode;
  return config;
}

function userHasCustomTopConfig(user) {
  if (!user || user.user_top_config_enabled !== true) return false;
  const config = user.user_top_config;
  if (!config || typeof config !== "object" || Array.isArray(config)) return false;
  return Object.values(config).some(value => {
    if (Array.isArray(value)) return value.length > 0;
    if (value && typeof value === "object") return Object.keys(value).length > 0;
    return String(value ?? "").trim() !== "";
  });
}

function escapeHtml(text) {
  return String(text || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

async function toggleUserPasswordDisplay(userId, button, schoolId = "", domKey = "") {
  const el = document.getElementById("user_password_" + (domKey || userId));
  if (!el) return;
  if (el.dataset.loaded !== "true") {
    const targetSchoolId = schoolId || currentSchool?.id;
    if (!targetSchoolId) return;
    const oldText = button ? button.textContent : "";
    if (button) {
      button.disabled = true;
      button.textContent = "...";
    }
    try {
      const res = await api("GET", "/api/school/" + targetSchoolId + "/user/" + userId + "/password");
      if (res.error) return toast(res.error || "密码解密失败", "error");
      el.dataset.passwordPlain = res.passwordPlain || "";
      el.dataset.loaded = "true";
    } finally {
      if (button) {
        button.disabled = false;
        button.textContent = oldText || "◉";
      }
    }
  }
  const plain = el.dataset.passwordPlain || "";
  if (!plain) return;
  const visible = el.dataset.visible === "true";
  el.dataset.visible = visible ? "false" : "true";
  el.textContent = visible ? "******" : plain;
  if (button) {
    const label = visible ? "显示明文密码" : "隐藏明文密码";
    button.title = label;
    button.setAttribute("aria-label", label);
    button.textContent = visible ? "◉" : "◎";
  }
}

function setEditUserPasswordVisible(visible) {
  const input = document.getElementById("edit_user_password");
  const button = document.getElementById("edit_user_password_eye");
  if (!input) return;
  input.type = visible ? "text" : "password";
  if (button) {
    const label = visible ? "隐藏明文密码" : "显示明文密码";
    button.title = label;
    button.setAttribute("aria-label", label);
    button.textContent = visible ? "◎" : "◉";
  }
}

function toggleEditUserPasswordVisibility() {
  const input = document.getElementById("edit_user_password");
  if (!input) return;
  setEditUserPasswordVisible(input.type === "password");
}

function renderFatalError(error, source = "runtime") {
  const app = document.getElementById("app");
  if (!app) return;
  const message = error && (error.stack || error.message || String(error)) || "Unknown error";
  app.innerHTML = \`
    <div class="container">
      <div class="card" style="margin-top:32px;border:1px solid #ffd6d6">
        <div class="card-header">
          <span class="card-title" style="color:#d4380d">页面加载失败</span>
        </div>
        <div style="font-size:14px;color:#666;line-height:1.7">
          <p>前端脚本遇到了异常，已停止渲染。</p>
          <p><strong>source:</strong> \${escapeHtml(source)}</p>
          <pre style="margin-top:12px;white-space:pre-wrap;word-break:break-word;background:#fff7f7;border-radius:8px;padding:12px;color:#a61d24">\${escapeHtml(message)}</pre>
        </div>
      </div>
    </div>
  \`;
}

async function copyTextToClipboard(text, successMessage = "已复制") {
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
    } else {
      const input = document.createElement("input");
      input.value = text;
      document.body.appendChild(input);
      input.select();
      document.execCommand("copy");
      input.remove();
    }
    toast(successMessage);
  } catch (e) {
    toast("复制失败，请手动复制", "error");
  }
}

async function copyRoomId(id) {
  await copyTextToClipboard(id, "已复制 ID: " + id);
}

function render() {
  const app = document.getElementById("app");
  if (currentView === "login") {
    app.innerHTML = renderLogin();
  } else if (currentView === "schools") {
    app.innerHTML = renderSchools();
  } else if (currentView === "school") {
    app.innerHTML = renderSchoolDetail();
  } else if (currentView === "conflict-group") {
    app.innerHTML = renderConflictGroupDetail();
  }
  bindEvents();
  if (currentView === "school") getPlanExtractTextEditor();
  updateTestEndtimeStatusView();
}

function updateTestEndtimeStatusView() {
  if (currentView !== "school" || !currentSchool) return;
  const pill = document.getElementById("test_endtime_status_pill");
  const text = document.getElementById("test_endtime_status_text");
  if (!pill || !text) return;

  const state = getTestEndtimeState(currentSchool);
  const testDayText = state.effectiveReserveDayOffset === 0 ? "今天" : "明天";
  pill.className = "test-status-pill " + (state.active ? "test-status-on" : "test-status-off");
  pill.textContent = state.active ? "开" : "关";
  text.textContent = state.active
    ? \`当前使用测试开始时间 \${state.effectiveTriggerTime}，测试截止时间 \${state.overrideEndtime}，预约\${testDayText}，剩余 \${formatRemainingSeconds(state.remainingSeconds)}\`
    : \`当前使用正式开始时间 \${currentSchool.trigger_time || "-"}，正式截止时间 \${currentSchool.endtime || "-"}\`;
}

function renderLogin() {
  return \`
    <div class="login-box">
      <h2>统一抢座管理系统</h2>
      <input type="password" id="apiKey" placeholder="请输入管理密钥">
      <button onclick="doLogin()">登 录</button>
    </div>
  \`;
}

function browserBeijingDayOfWeek() {
  const d = new Date(Date.now() + 8 * 3600 * 1000);
  const days = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
  return days[d.getUTCDay()];
}

function browserTodayTaskScheduleDay(school) {
  const today = browserBeijingDayOfWeek();
  if (school?.schedule_store_by_reserve_date !== true) return today;
  const days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
  const todayIndex = days.indexOf(today);
  if (todayIndex < 0) return today;
  const rawOffset = String(school?.reserve_day_offset ?? "").trim();
  const parsedOffset = /^-?\d+$/.test(rawOffset) ? parseInt(rawOffset, 10) : null;
  const offset = parsedOffset === null
    ? (school?.reserve_next_day === false ? 0 : 1)
    : Math.max(0, parsedOffset);
  return days[(todayIndex + offset) % days.length];
}

function browserTodayTaskScheduleLabel(school) {
  const dayLabels = {
    Monday: "周一",
    Tuesday: "周二",
    Wednesday: "周三",
    Thursday: "周四",
    Friday: "周五",
    Saturday: "周六",
    Sunday: "周日",
  };
  return dayLabels[browserTodayTaskScheduleDay(school)] || "今日";
}

function formatUserStatus(user) {
  if (user?.status === "active") return "活跃";
  if (!user?.pause_until) return "暂停";
  const configuredDays = Number(user.pause_days);
  if (Number.isInteger(configuredDays) && configuredDays > 0) {
    return "暂停" + configuredDays + "天";
  }
  const remainingDays = Math.max(1, Math.ceil((Date.parse(user.pause_until) - Date.now()) / 86400000));
  return "暂停" + remainingDays + "天";
}

function getEnabledScheduleSlotsClient(daySchedule) {
  if (!daySchedule || !daySchedule.enabled) return [];
  const rawSlots = Array.isArray(daySchedule.slots)
    ? daySchedule.slots
    : [{
        roomid: daySchedule.roomid,
        seatid: daySchedule.seatid,
        times: daySchedule.times,
        seatPageId: daySchedule.seatPageId || "",
        fidEnc: daySchedule.fidEnc || "",
      }];
  return rawSlots.filter(slot => slot && slot.times && slot.roomid);
}

function countActiveUsersForTodayClient(userList, school = null) {
  const today = browserTodayTaskScheduleDay(school);
  return (Array.isArray(userList) ? userList : []).filter(user => {
    if (!user || user.status !== "active") return false;
    return getEnabledScheduleSlotsClient(user.schedule && user.schedule[today]).length > 0;
  }).length;
}

function getCachedActiveTodayCount(schoolId) {
  try {
    const raw = localStorage.getItem(ACTIVE_TODAY_CACHE_PREFIX + schoolId);
    if (!raw) return null;
    const cached = JSON.parse(raw);
    if (!cached || cached.expiresAt <= Date.now()) {
      localStorage.removeItem(ACTIVE_TODAY_CACHE_PREFIX + schoolId);
      return null;
    }
    return cached;
  } catch (_e) {
    return null;
  }
}

function setCachedActiveTodayCount(schoolId, payload) {
  try {
    localStorage.setItem(
      ACTIVE_TODAY_CACHE_PREFIX + schoolId,
      JSON.stringify(payload)
    );
  } catch (_e) {
    // ignore localStorage quota or privacy errors
  }
}

function formatActiveTodayMeta(schoolId) {
  const cached = getCachedActiveTodayCount(schoolId);
  if (!cached) return "今日活跃: 统计中";
  if (cached.error) return "今日活跃: 统计失败";
  return "今日活跃: " + cached.count + " 人";
}

function formatUserCountMeta(school) {
  const cached = getCachedActiveTodayCount(school?.id);
  if (cached && !cached.error && Number.isFinite(Number(cached.totalCount))) {
    return cached.totalCount + " 名用户";
  }
  return (school?.userCount || 0) + " 名用户";
}

async function ensureActiveTodayCount(schoolId, force = false) {
  const cached = getCachedActiveTodayCount(schoolId);
  if (!force && cached) return cached;

  try {
    const res = await api("GET", "/api/school/" + schoolId + "/counts");
    if (res.error) throw new Error(res.error);
    const next = {
      count: parseInt(res.activeTodayCount ?? res.count, 10) || 0,
      totalCount: parseInt(res.totalCount, 10) || 0,
      expiresAt: Date.now() + ACTIVE_TODAY_CACHE_TTL_MS,
      error: "",
    };
    setCachedActiveTodayCount(schoolId, next);
    return next;
  } catch (e) {
    const next = {
      count: 0,
      expiresAt: Date.now() + ACTIVE_TODAY_CACHE_TTL_MS,
      error: e.message || String(e),
    };
    setCachedActiveTodayCount(schoolId, next);
    return next;
  }
}

async function refreshSchoolActiveTodayCounts(force = false) {
  if (currentView !== "schools" || !API_KEY || !Array.isArray(schools) || schools.length === 0) return;
  const runId = ++activeTodayRefreshRunId;
  const targets = schools.filter(s => s && s.id);
  const concurrency = 3;
  let nextIndex = 0;
  const workers = Array.from({ length: Math.min(concurrency, targets.length) }, async () => {
    while (nextIndex < targets.length && runId === activeTodayRefreshRunId && currentView === "schools") {
      const school = targets[nextIndex++];
      await ensureActiveTodayCount(school.id, force);
    }
  });
  await Promise.all(workers);
  if (runId !== activeTodayRefreshRunId || currentView !== "schools") return;
  if (currentView === "schools") render();
}

function parseTriggerTimeMinutes(value) {
  const text = String(value || "").trim();
  const parts = text.match(/\\d{1,2}/g);
  if (!parts || parts.length < 2) return Number.MAX_SAFE_INTEGER;
  const hour = parseInt(parts[0], 10);
  const minute = parseInt(parts[1], 10);
  if (Number.isNaN(hour) || Number.isNaN(minute)) return Number.MAX_SAFE_INTEGER;
  if (hour < 0 || hour > 23 || minute < 0 || minute > 59) return Number.MAX_SAFE_INTEGER;
  return hour * 60 + minute;
}

function getSortedSchoolsForDisplay(items) {
  return (Array.isArray(items) ? items : [])
    .filter(Boolean)
    .slice()
    .sort((a, b) => {
      const timeDiff = parseTriggerTimeMinutes(a?.trigger_time) - parseTriggerTimeMinutes(b?.trigger_time);
      if (timeDiff !== 0) return timeDiff;
      return String(a?.id || "").localeCompare(String(b?.id || ""));
    });
}

function normalizeClientConflictGroup(value) {
  return String(value || "").trim().toLowerCase();
}

function getClientSchoolConflictGroup(school) {
  const explicitGroup = normalizeClientConflictGroup(school?.conflict_group);
  if (explicitGroup) return "group:" + explicitGroup;

  const fidEnc = normalizeClientConflictGroup(school?.fidEnc);
  if (fidEnc) return "fid:" + fidEnc;

  return normalizeClientConflictGroup(school?.name);
}

function compareSchoolForDisplay(a, b) {
  const timeDiff = parseTriggerTimeMinutes(a?.trigger_time) - parseTriggerTimeMinutes(b?.trigger_time);
  if (timeDiff !== 0) return timeDiff;
  return String(a?.id || "").localeCompare(String(b?.id || ""));
}

function compareSchoolByTriggerTime(a, b) {
  return parseTriggerTimeMinutes(a?.trigger_time) - parseTriggerTimeMinutes(b?.trigger_time);
}

function buildSchoolDisplaySections(schoolItems) {
  const sourceSchools = (Array.isArray(schoolItems) ? schoolItems : []).filter(Boolean);
  const groupCounts = new Map();
  const largeGroupMap = new Map();
  const otherSchools = [];
  for (const school of sourceSchools) {
    const group = getClientSchoolConflictGroup(school);
    if (!group) continue;
    groupCounts.set(group, (groupCounts.get(group) || 0) + 1);
  }

  for (const school of sourceSchools) {
    const group = getClientSchoolConflictGroup(school);
    const isLargeConflictGroup = group && groupCounts.get(group) >= 2;
    if (isLargeConflictGroup) {
      if (!largeGroupMap.has(group)) {
        largeGroupMap.set(group, []);
      }
      largeGroupMap.get(group).push(school);
    } else {
      otherSchools.push(school);
    }
  }

  const sections = Array.from(largeGroupMap.entries()).map(([key, schools]) => ({
    key,
    schools: schools.slice().sort(compareSchoolByTriggerTime),
  }));
  if (otherSchools.length) {
    sections.push({
      key: "other",
      schools: otherSchools.slice().sort(compareSchoolByTriggerTime),
    });
  }
  return sections;
}

function renderSchoolSearchMatches(s) {
  const matches = Array.isArray(s.__matchedUsers) ? s.__matchedUsers : [];
  if (!matches.length) return "";
  return \`
    <div class="school-search-matches">
      \${matches.map(user => \`
        <div class="school-search-match">
          <strong>\${escapeHtml(user.username || user.remark || user.phone || user.id || "-")}</strong>
          <span>\${escapeHtml(user.phone || "-")}</span>
          <span>\${escapeHtml(user.status || "-")}</span>
        </div>
      \`).join("")}
      <div class="inline-actions">
        <button type="button" class="btn btn-sm btn-primary" onclick="event.stopPropagation(); openSchool('\${escapeHtml(s.id)}')">进入学校</button>
      </div>
    </div>
  \`;
}

function renderSchoolCard(s) {
  return \`
    <div class="school-card" onclick="openSchool('\${s.id}')">
      <h3>\${s.name}</h3>
      <div class="meta">ID: \${s.id} | 仓库: \${s.repo}</div>
      <div class="stats">
        <span>\${formatUserCountMeta(s)}</span>
        <span>\${formatActiveTodayMeta(s.id)}</span>
        <span>正式开始: \${s.trigger_time}</span>
      </div>
      \${renderSchoolSearchMatches(s)}
    </div>
  \`;
}

function conflictGroupLabel(section) {
  const first = section?.schools?.[0] || {};
  return first.conflict_group || first.fidEnc || first.name || section?.key || "未命名冲突组";
}

function renderConflictGroupCards(section) {
  const totalUsers = section.schools.reduce((sum, school) => {
    const cached = getCachedActiveTodayCount(school.id);
    return sum + Number(cached?.totalCount ?? school.userCount ?? 0);
  }, 0);
  const activeCounts = section.schools.map(school => getCachedActiveTodayCount(school.id));
  const activeTodayText = activeCounts.every(item => item && !item.error)
    ? activeCounts.reduce((sum, item) => sum + Number(item.count || 0), 0) + " 人"
    : "统计中";
  const encodedKey = encodeURIComponent(section.key);
  return \`
    <div class="school-section">
      <div class="school-card conflict-group-total-card" onclick="openConflictGroup(decodeURIComponent('\${encodedKey}'))">
        <h3>\${escapeHtml(conflictGroupLabel(section))}（总卡片）</h3>
        <div class="meta">冲突组: \${escapeHtml(conflictGroupLabel(section))} | 包含 \${section.schools.length} 所学校</div>
        <div class="stats">
          <span>\${totalUsers} 名用户</span>
          <span>今日活跃: \${activeTodayText}</span>
        </div>
      </div>
    </div>
    \${section.schools.map(s => \`<div class="school-section">\${renderSchoolCard(s)}</div>\`).join("")}
  \`;
}

function renderSchoolList() {
  const sourceSchools = schoolSearch.query && !schoolSearch.loading && !schoolSearch.error
    ? schoolSearch.results.map(item => ({
        ...item.school,
        __matchedUsers: item.users || [],
      }))
    : schools;

  if (!sourceSchools.length) {
    if (schoolSearch.query && !schoolSearch.loading && !schoolSearch.error) {
      return '<div class="empty"><div class="empty-icon">🔎</div><p>无用户</p></div>';
    }
    return '<div class="empty"><div class="empty-icon">📚</div><p>暂无学校，点击上方按钮添加</p></div>';
  }

  const sections = buildSchoolDisplaySections(sourceSchools);
  window.__tongyiSortDebug = sections.map(section => ({
    key: section.key,
    schools: section.schools.map(s => ({
      id: s.id,
      name: s.name,
      trigger_time: s.trigger_time,
      sort_minutes: parseTriggerTimeMinutes(s.trigger_time),
      conflict_group: getClientSchoolConflictGroup(s),
    })),
  }));

  return sections.map((section, index) => {
    const cards = section.key === "other"
      ? section.schools.map(s => \`<div class="school-section">\${renderSchoolCard(s)}</div>\`).join("")
      : renderConflictGroupCards(section);
    const divider = section.key !== "other" && index < sections.length - 1
      ? '<div class="school-group-divider" aria-hidden="true"></div>'
      : "";
    return cards + divider;
  }).join("");
}

function renderSchoolSearchPanel() {
  const resultCount = schoolSearch.results.reduce((sum, item) => sum + Number(item.matchCount || (item.users || []).length || 0), 0);
  const status = schoolSearch.loading
    ? "正在查询..."
      : schoolSearch.error
        ? schoolSearch.error
      : schoolSearch.query
        ? (schoolSearch.results.length > 1
            ? "有重复卡片：找到 " + schoolSearch.results.length + " 个学校，" + resultCount + " 个匹配用户"
            : schoolSearch.results.length === 1
              ? "找到 1 个学校，" + resultCount + " 个匹配用户"
              : "无用户")
        : "输入手机号或 username，可快速定位用户所在学校";
  return \`
    <div class="school-search">
      <input id="school_user_search_input" type="search" value="\${escapeHtml(schoolSearch.query)}" placeholder="按手机号或 username 查询学校" onkeydown="handleSchoolSearchKeydown(event)">
      <button class="btn btn-primary" onclick="searchSchoolsByUser()">查询</button>
      <button class="btn btn-secondary" onclick="searchSchoolsByUserAndJump()">查询并跳转</button>
    </div>
    <div class="school-search-status">\${escapeHtml(status)}</div>
  \`;
}

function upsertSchoolInOrderedList(items, school, options = {}) {
  const list = (Array.isArray(items) ? items : []).filter(Boolean).slice();
  const existingIndex = list.findIndex(item => item && item.id === school?.id);
  const previous = existingIndex >= 0 ? list[existingIndex] : null;
  const shouldResort = options.forceResort || !previous || previous.trigger_time !== school?.trigger_time;

  if (existingIndex >= 0) {
    list[existingIndex] = school;
  } else {
    list.push(school);
  }

  return shouldResort ? getSortedSchoolsForDisplay(list) : list;
}

function renderSchools() {
  const now = new Date().toLocaleString("zh-CN", { timeZone: "Asia/Shanghai" });
  return \`
    <div class="container">
      <div class="header">
        <h1>统一抢座管理系统</h1>
        <div class="time">\${now}</div>
      </div>
      <div class="card">
        <div class="card-header">
          <span class="card-title">学校列表 <span class="small">排序版: \${UI_SORT_VERSION}</span></span>
          <button class="btn btn-primary" onclick="showAddSchool()">+ 添加学校</button>
        </div>
        \${renderSchoolSearchPanel()}
        <div class="school-list">
          \${renderSchoolList()}
        </div>
      </div>
    </div>
    \${renderAddSchoolModal()}
  \`;
}

function renderAddSchoolModal() {
  return \`
    <div class="modal" id="addSchoolModal">
      <div class="modal-content">
        <div class="modal-header">
          <h3>添加学校</h3>
          <span class="modal-close" onclick="closeModal('addSchoolModal')">&times;</span>
        </div>
        <div class="modal-body">
          <div class="form-row">
            <div class="form-group">
              <label>学校 ID（如 001）</label>
              <input type="text" id="new_school_id" placeholder="001">
            </div>
            <div class="form-group">
              <label>学校名称</label>
              <input type="text" id="new_school_name" placeholder="华东师范大学">
            </div>
          </div>
          <div class="form-group">
            <label>GitHub 仓库</label>
            <input type="text" id="new_school_repo" placeholder="BAOfuZhan/hcd">
          </div>
          <div class="form-group">
            <label>分发目标</label>
            <select id="new_school_dispatch_target">
              <option value="github">github - 仅 GitHub Actions</option>
              <option value="server_relay">server_relay - GitHub 中转到服务器</option>
            </select>
          </div>
          <div id="new_school_server_only_fields">
            <div class="form-group">
              <label>选座接口模式</label>
              <select id="new_school_seat_api_mode">
                <option value="auto">auto - 固定 seatengine，不跨接口回退</option>
                <option value="seatengine">seatengine - 强制新版接口</option>
                <option value="seat" selected>seat - 强制旧版接口</option>
                <option value="seatengine_code">seatengine_code - seatengine code 页面</option>
                <option value="seat_code">seat_code - seat code 页面</option>
              </select>
            </div>
            <div class="form-row">
              <div class="form-group">
                <label><input type="checkbox" id="new_school_reserve_next_day" checked> 预约明天</label>
              </div>
              <div class="form-group">
                <label><input type="checkbox" id="new_school_enable_slider"> 启用滑块验证码</label>
              </div>
            </div>
            <div class="form-row">
              <div class="form-group">
                <label><input type="checkbox" id="new_school_enable_textclick"> 启用选字验证码</label>
              </div>
              <div class="form-group">
                <label><input type="checkbox" id="new_school_enable_iconclick"> 启用图标验证码</label>
              </div>
              <div class="form-group">
                <label>图标验证码识别平台</label>
                <select id="new_school_iconclick_ocr_provider">
	                  <option value="chaojiying" selected>超级鹰 9103（默认）</option>
	                  <option value="tulingcloud">图灵云（图标模型）</option>
	                  <option value="jfbym">jfbym（图标模型）</option>
                </select>
              </div>
              <div class="form-group">
                <label><input type="checkbox" id="new_school_enable_rotate"> 启用旋转滑块验证码</label>
              </div>
              <div class="form-group">
                <label>旋转滑块识别平台</label>
                <select id="new_school_rotate_ocr_provider">
                  <option value="geepass" selected>GeePass → 图灵云 → JFBYM</option>
                  <option value="tulingcloud">图灵云 → GeePass → JFBYM</option>
                  <option value="jfbym">JFBYM → GeePass → 图灵云</option>
                </select>
              </div>
            </div>
          </div>
          <div class="form-group">
            <label>冲突分组</label>
            <input type="text" id="new_school_conflict_group" placeholder="可留空；留空时优先按学校 fidEnc 自动归并">
          </div>
          <div class="form-group">
            <label><input type="checkbox" id="new_school_ignore_seat_conflicts"> 不检测相同座位冲突</label>
          </div>
          <div class="form-group">
            <label>GitHub 密匙槽位</label>
            <select id="new_school_github_token_key">
              <option value="">默认 GH_TOKEN</option>
              <option value="a">A -> GH_TOKEN_A</option>
              <option value="b">B -> GH_TOKEN_B</option>
              <option value="c">C -> GH_TOKEN_C</option>
              <option value="d">D -> GH_TOKEN_D</option>
              <option value="e">E -> GH_TOKEN_E</option>
            </select>
          </div>
          <div id="new_school_relay_fields">
            <div class="form-row">
              <div class="form-group">
                <label>服务器分发地址</label>
                <input type="text" id="new_school_server_url" placeholder="例如: https://your-server.example.com/dispatch">
              </div>
              <div class="form-group">
                <label>服务器最大并发</label>
                <input type="number" id="new_school_server_max_concurrency" value="13" min="1">
              </div>
            </div>
            <div class="form-group">
              <label>提交 day 日期偏移（仅服务器中转）</label>
              <input type="number" id="new_school_reserve_day_offset" min="0" step="1" placeholder="留空沿用预约明天；0 今天，1 明天，2 后天">
            </div>
          </div>
          <div class="form-group">
            <label>服务器 API Key（GitHub 验证码兜底及服务器中转共用）</label>
            <input type="text" id="new_school_server_api_key" placeholder="留空则回退到 Worker 环境变量 SERVER_DISPATCH_API_KEY">
          </div>
          <div class="form-group">
            <label>GitHub 验证码备用服务器（默认）</label>
            <input type="text" value="http://62.234.222.77" readonly>
            <div class="user-top-config-note">自动使用 /rotate 或 /recognize 接口，无需填写。</div>
          </div>
          <div class="form-group">
            <label><input type="checkbox" id="new_school_schedule_store_by_reserve_date"> KV 周计划按预约日期存储</label>
            <div class="user-top-config-note">前端仍按执行日填写；例如周一执行预约明天，会自动保存到 KV 周二。</div>
          </div>
          <div class="form-row">
            <div class="form-group">
              <label>正式开始时间</label>
              <input type="text" id="new_school_trigger" value="19:57" placeholder="HH:MM">
            </div>
            <div class="form-group">
              <label>正式截止时间</label>
              <input type="text" id="new_school_endtime" value="20:00:40" placeholder="HH:MM:SS">
            </div>
          </div>
          <div class="form-group">
            <label>学校统一 fidEnc（全校共用）</label>
            <input type="text" id="new_school_fidEnc" placeholder="例如: 1b001674cae092c3">
          </div>
          <button class="btn btn-primary" onclick="doAddSchool()" style="width:100%;margin-top:10px">创建学校</button>
        </div>
      </div>
    </div>
  \`;
}

function getSchoolManagementLink(school) {
  if ((!school?.dispatch_target || school.dispatch_target === "github") && /^[\\w.-]+\\/[\\w.-]+$/.test(school.repo || "")) {
    return { url: \`https://github.com/\${school.repo}/actions\`, label: "GitHub Actions" };
  }
  try {
    const serverUrl = new URL(school?.server_url);
    if (serverUrl.protocol === "http:" || serverUrl.protocol === "https:") {
      return { url: serverUrl.origin + "/admin.html", label: "服务器后台" };
    }
  } catch (_) {}
  return { url: "", label: "" };
}

function renderUserManagementTable(userList, options = {}) {
  const showSchool = options.showSchool === true;
  const defaultSchool = options.defaultSchool || null;
  const rows = (Array.isArray(userList) ? userList : []).slice().sort((a, b) => {
    const schoolDiff = String(a.__schoolId || "").localeCompare(String(b.__schoolId || ""));
    if (showSchool && schoolDiff !== 0) return schoolDiff;
    const na = (a.username || a.remark || "").toLowerCase();
    const nb = (b.username || b.remark || "").toLowerCase();
    return na.localeCompare(nb);
  });
  if (!rows.length) {
    return '<div class="empty"><div class="empty-icon">👤</div><p>暂无用户</p></div>';
  }

  return \`
    <div class="\${showSchool ? "user-table-scroll" : ""}">
    <table class="user-table\${showSchool ? " user-table-compact" : ""}">
      <thead>
        <tr>
          \${showSchool ? "<th>学校</th>" : ""}
          <th>手机号（账号）</th>
          <th>密码</th>
          <th>昵称</th>
          <th>状态</th>
          <th>自动签到</th>
          <th title="今天执行任务时实际读取的预约日计划">今日任务计划</th>
          <th>操作</th>
        </tr>
      </thead>
      <tbody>
        \${rows.map(u => {
          const school = u.__school || defaultSchool || {};
          const schoolId = String(u.__schoolId || school.id || "");
          const schoolManagement = getSchoolManagementLink(school);
          const domKey = escapeHtml(schoolId + "_" + u.id);
          const today = browserTodayTaskScheduleDay(school);
          const todaySch = u.schedule?.[today];
          const todayStr = (() => {
            if (!todaySch || !todaySch.enabled) return "无";
            const slots = todaySch.slots || [{ roomid: todaySch.roomid, times: todaySch.times }];
            const active = slots.filter(slot => slot.times && slot.roomid);
            if (active.length === 0) return "已启用/无有效时段";
            return active.map(slot => slot.times).join(" | ");
          })();
          const displayName = u.username || u.remark || "-";
          const customNameClass = userHasCustomTopConfig(u) ? "user-name-custom" : "";
          return \`
            <tr>
              \${showSchool ? \`<td>\${schoolManagement.url
                ? \`<a class="school-server-link" href="\${escapeHtml(schoolManagement.url)}" target="_blank" rel="noopener noreferrer" title="\${escapeHtml(schoolManagement.label)}">\${escapeHtml(schoolId)}</a>\`
                : \`<strong>\${escapeHtml(schoolId)}</strong>\`
              }</td>\` : ""}
              <td>\${escapeHtml(u.phone || "-")}</td>
              <td>
                <div class="password-view">
                  <span class="password-view__text" id="user_password_\${domKey}" data-password-plain="" data-loaded="false">\${u.hasPassword ? "******" : "-"}</span>
                  \${u.hasPassword ? \`<button type="button" class="password-eye" title="显示明文密码" aria-label="显示明文密码" onclick="toggleUserPasswordDisplay('\${escapeHtml(u.id)}', this, '\${escapeHtml(schoolId)}', '\${domKey}')">◉</button>\` : ""}
                </div>
              </td>
              <td><span class="\${customNameClass}">\${escapeHtml(displayName)}</span></td>
              <td class="status-\${u.status}">\${escapeHtml(formatUserStatus(u))}</td>
              <td>
                <span class="sign-status \${u.sign_feature_visible === true && u.auto_sign_enabled === true ? "sign-status-on" : "sign-status-off"}">\${u.sign_feature_visible === true ? (u.auto_sign_enabled === true ? "开启" : "关闭") : "未开放"}</span>
              </td>
              <td style="font-size:12px">\${escapeHtml(todayStr)}</td>
              <td class="actions">
                <button class="btn btn-sm btn-secondary" onclick="showEditUser('\${escapeHtml(u.id)}', '\${escapeHtml(schoolId)}')">编辑</button>
                \${u.status === "active"
                  ? \`<button class="btn btn-sm btn-danger" onclick="pauseUser('\${escapeHtml(u.id)}', '\${escapeHtml(schoolId)}')">暂停</button>\`
                  : \`<button class="btn btn-sm btn-success" onclick="resumeUser('\${escapeHtml(u.id)}', '\${escapeHtml(schoolId)}')">恢复</button>\`}
                <button class="btn btn-sm btn-primary" onclick="triggerUser('\${escapeHtml(u.id)}', '\${escapeHtml(schoolId)}')">触发</button>
                <button class="btn btn-sm btn-danger" onclick="deleteUser('\${escapeHtml(u.id)}', '\${escapeHtml(schoolId)}')">删除</button>
                \${u.status === "active" ? \`
                  <span class="pause-days-action">
                    <input class="pause-days-input" id="pause_days_\${domKey}" type="number" min="1" max="365" value="1" aria-label="暂停天数" oninput="updatePauseDaysButton('\${domKey}', this.value)">
                    <button class="btn btn-sm btn-danger" id="pause_days_button_\${domKey}" onclick="pauseUserForDays('\${escapeHtml(u.id)}', '\${escapeHtml(schoolId)}', '\${domKey}')">暂停1天</button>
                  </span>
                \` : ""}
              </td>
            </tr>
          \`;
        }).join("")}
      </tbody>
    </table>
    </div>
  \`;
}

function renderConflictGroupDetail() {
  const groupSchools = currentConflictGroupSchools;
  if (!groupSchools.length) return "";
  const label = conflictGroupLabel({
    key: currentConflictGroupKey,
    schools: groupSchools,
  });
  if (conflictGroupUsersLoading) {
    return \`
      <div class="container">
        <div class="header">
          <h1>冲突组：\${escapeHtml(label)}</h1>
          <button class="btn btn-secondary" onclick="backToSchools()">返回学校列表</button>
        </div>
        <div class="card">
          <div class="empty"><div class="empty-icon">👥</div><p>正在并行读取组内用户...</p></div>
        </div>
      </div>
    \`;
  }
  const defaultSchoolId = groupSchools[0]?.id || "";
  return \`
    <div class="container">
      <div class="header">
        <h1>冲突组：\${escapeHtml(label)}</h1>
        <div class="actions">
          <button class="btn btn-secondary" onclick="backToSchools()">返回学校列表</button>
        </div>
      </div>
      <div class="breadcrumb">
        <a href="#" onclick="backToSchools();return false">学校列表</a>
        <span>></span>
        <span>冲突组总卡片</span>
      </div>
      <div class="card">
        <div class="card-header">
          <span class="card-title">组内全部用户（\${users.length}）</span>
          <div class="card-actions">
            <button class="btn btn-success" onclick="bulkSetConflictGroupUsersStatus('active')">一键全启动</button>
            <button class="btn btn-secondary" onclick="bulkSetConflictGroupUsersStatus('paused')">一键全暂停</button>
          </div>
        </div>
        <div class="conflict-group-add">
          <input
            id="conflict_group_add_school_id"
            list="conflict_group_school_ids"
            value="\${escapeHtml(defaultSchoolId)}"
            placeholder="输入组内学校 ID"
            aria-label="新增用户所属学校 ID"
          >
          <datalist id="conflict_group_school_ids">
            \${groupSchools.map(s => \`<option value="\${escapeHtml(s.id)}">\${escapeHtml(s.name || s.id)}</option>\`).join("")}
          </datalist>
          <button class="btn btn-primary" onclick="showAddConflictGroupUser()">+ 添加用户</button>
        </div>
        <div class="user-top-config-note" style="margin:10px 0 16px">
          总卡片不提供学校配置。新增用户前，请填写该用户所属的组内学校 ID。
        </div>
        \${renderUserManagementTable(users, { showSchool: true })}
      </div>
    </div>
    \${renderUserModal()}
    \${renderUnitBindingWarningModal()}
  \`;
}

function renderSchoolDetail() {
  const s = currentSchool;
  if (!s) return "";
  const { url: managementUrl, label: managementLabel } = getSchoolManagementLink(s);
  const strategyMode = String(s.strategy?.mode || "C").toUpperCase();
  const endSeconds = parseClientEndtimeSeconds(s.endtime);
  const showStrategyAZeroNotice = strategyMode === "A"
    && endSeconds !== null
    && (endSeconds - 40 + 60) % 60 === 0;
  return \`
    <div class="container school-detail-container">
      <div class="school-detail-layout">
      <main class="school-detail-main">
      <div class="header">
        <h1>\${s.name}</h1>
        <div class="actions">
          <button class="btn btn-secondary" onclick="backToSchools()">返回列表</button>
          <button class="btn btn-primary" onclick="showEditSchool()">编辑配置</button>
          <button id="readSeatConfigBtn" class="btn btn-primary" onclick="readSeatConfigForCurrentSchool()">读取座位规则</button>
          \${managementUrl ? \`<a class="btn btn-primary" href="\${managementUrl}" target="_blank" rel="noopener noreferrer">\${managementLabel}</a>\` : ""}
          <button
            id="scheduleStoreToggleBtn"
            class="btn \${s.schedule_store_by_reserve_date ? "btn-success" : "btn-secondary"}"
            onclick="toggleScheduleStoreByReserveDate()"
            title="只改变周计划显示和编辑换算，不迁移 KV 用户数据"
          >\${s.schedule_store_by_reserve_date ? "预约日期存储: 开" : "预约日期存储: 关"}</button>
          <button class="btn btn-success" onclick="triggerSchool()">手动触发</button>
        </div>
      </div>
      <div class="breadcrumb">
        <a href="#" onclick="backToSchools();return false">学校列表</a>
        <span>></span>
        <span>\${s.name}</span>
      </div>
      <div class="card">
        <div class="card-header">
          <span class="card-title">学校配置</span>
        </div>
        <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:16px;font-size:14px">
          <div><strong>学校ID:</strong> \${s.id}</div>
          <div><strong>正式开始时间:</strong> \${s.trigger_time}</div>
          <div><strong>正式截止时间:</strong> \${s.endtime}</div>
          <div><strong>策略模式:</strong> \${strategyMode}</div>
          <div><strong>GitHub仓库:</strong> \${s.repo}</div>
          <div><strong>今日活跃用户:</strong> \${formatActiveTodayMeta(s.id)}</div>
          <div><strong>GitHub 密匙槽位:</strong> \${s.github_token_key ? s.github_token_key.toUpperCase() : "默认 GH_TOKEN"}</div>
          <div><strong>选座接口:</strong> \${s.seat_api_mode || "seat"}</div>
          <div><strong>预约日期:</strong> \${formatReserveDayLabel(s)}</div>
          <div><strong>学校 fidEnc:</strong> \${s.fidEnc || "-"}</div>
          <div><strong>冲突分组:</strong> \${s.conflict_group || (s.fidEnc ? "自动按 fidEnc" : (s.name || "-"))}</div>
          <div><strong>同座冲突检测:</strong> \${s.ignore_seat_conflicts ? "关闭" : "开启"}</div>
          <div><strong>验证码:</strong> \${s.enable_rotate ? \`旋转滑块（\${formatRotateOcrProvider(s.rotate_ocr_provider)}）\` : (s.enable_slider ? "滑块" : (s.enable_iconclick ? \`图标（\${formatIconclickOcrProvider(s.iconclick_ocr_provider)}）\` : (s.enable_textclick ? "选字" : "关闭")))}</div>
          <div><strong>分发目标:</strong> \${s.dispatch_target || "github"}</div>
          \${s.dispatch_target === "server_relay" ? \`
            <div><strong>服务器地址:</strong> \${s.server_url || "-"}</div>
            <div><strong>服务器并发:</strong> \${s.server_max_concurrency || 13}</div>
            <div><strong>服务器密钥:</strong> \${s.has_server_api_key ? "已配置" : "未配置/使用环境变量"}</div>
          \` : ""}
        </div>
        \${showStrategyAZeroNotice ? '<div class="user-top-config-note" style="margin-top:12px">提示：目标秒数为 00，当前配置仍按策略 A 执行，不影响功能。</div>' : ""}
        \${renderTestEndtimePanel(s)}
      </div>
      <div class="card">
        <div class="card-header">
          <span class="card-title">用户管理</span>
          <div class="card-actions">
            <button class="btn btn-success" onclick="bulkSetUsersStatus('active')">一键全启动</button>
            <button class="btn btn-secondary" onclick="bulkSetUsersStatus('paused')">一键全暂停</button>
            <button class="btn btn-secondary" onclick="disableAllUserTopConfigs()">关闭全部用户个性化参数</button>
            <button class="btn btn-primary" onclick="showAddUser()">+ 添加用户</button>
          </div>
        </div>
        \${renderUserManagementTable(users, { defaultSchool: s })}
      </div>
      <div class="card">
        <div class="card-header">
          <span class="card-title">阅览区 ID 速查</span>
        </div>
        \${renderReadingZonePanel()}
      </div>
      <div class="card">
        <div class="card-header">
          <span class="card-title">计划文本映射</span>
          <div class="card-actions">
            <button type="button" class="btn btn-danger" onclick="clearPlanMappingDraft()">清空已保存内容</button>
          </div>
        </div>
        \${renderPlanMappingPanel()}
      </div>
      </main>
      <aside>\${renderSchoolNotesPanel(s)}</aside>
      </div>
    </div>
    \${renderEditSchoolModal()}
    \${renderUserModal()}
    \${renderUnitBindingWarningModal()}
  \`;
}

function renderSchoolNotesPanel(school) {
  const notes = Array.isArray(school?.notes) ? school.notes : [];
  return \`
    <section class="school-notes-launcher" aria-label="学校事项">
      \${notes.map((note, index) => \`
          <button class="school-note-pill" onclick="toggleSchoolNoteEditor(\${index})">📌 \${escapeHtml(note)}</button>
          <div class="school-note-editor" id="school_note_editor_\${index}">
            <textarea id="school_note_\${index}" maxlength="300">\${escapeHtml(note)}</textarea>
            <div class="school-note-actions">
              <button class="btn btn-secondary" onclick="deleteSchoolNote(\${index})">删除</button>
              <button class="btn btn-primary" onclick="saveSchoolNote(\${index})">保存</button>
            </div>
          </div>
      \`).join("")}
      <button class="btn btn-primary school-notes-toggle" onclick="toggleSchoolNotesPanel()">事项</button>
      <div class="school-note-new" id="school_notes_panel">
        <textarea id="new_school_note" maxlength="300" placeholder="输入新的事项……"></textarea>
        <div class="school-note-actions">
          <button class="btn btn-success" onclick="addSchoolNote()">新增</button>
        </div>
      </div>
    </section>
  \`;
}

function toggleSchoolNotesPanel() {
  const panel = document.getElementById("school_notes_panel");
  panel?.classList.toggle("show");
  if (panel?.classList.contains("show")) document.getElementById("new_school_note")?.focus();
}

function toggleSchoolNoteEditor(index) {
  document.getElementById("school_note_editor_" + index)?.classList.toggle("show");
}

async function persistSchoolNotes(notes, message) {
  if (!currentSchool?.id) return;
  const res = await api("PUT", "/api/school/" + currentSchool.id, { notes });
  if (!res.ok) return toast(res.error || "注意事项保存失败", "error");
  currentSchool = res.school;
  schools = upsertSchoolInOrderedList(schools, res.school);
  render();
  toast(message, "success");
}

function addSchoolNote() {
  const input = document.getElementById("new_school_note");
  const note = String(input?.value || "").trim();
  if (!note) return toast("请输入注意事项", "error");
  const notes = Array.isArray(currentSchool?.notes) ? currentSchool.notes : [];
  if (notes.length >= 20) return toast("每个学校最多保存 20 条提醒", "error");
  persistSchoolNotes([...notes, note], "提醒已添加");
}

function saveSchoolNote(index) {
  const input = document.getElementById("school_note_" + index);
  const note = String(input?.value || "").trim();
  if (!note) return toast("提醒内容不能为空", "error");
  const notes = [...(Array.isArray(currentSchool?.notes) ? currentSchool.notes : [])];
  notes[index] = note;
  persistSchoolNotes(notes, "提醒已保存");
}

function deleteSchoolNote(index) {
  if (!confirm("确定删除这条提醒？")) return;
  const notes = [...(Array.isArray(currentSchool?.notes) ? currentSchool.notes : [])];
  notes.splice(index, 1);
  persistSchoolNotes(notes, "提醒已删除");
}

function renderReadingZonePanel() {
  const groups = getReadingZoneGroups();
  return \`
    <div class="zone-grid">
      \${groups.map(group => \`
        <div class="zone-card">
          <div class="zone-floor">\${group.floor}</div>
          <div class="zone-list">
            \${group.zones.map(z => \`
              <div class="zone-item">
                <span>\${z.name}</span>
                <div class="zone-right">
                  <span class="zone-id">\${z.id}</span>
                  <button class="copy-btn" onclick="copyRoomId('\${z.id}')">复制</button>
                </div>
              </div>
            \`).join("")}
          </div>
        </div>
      \`).join("")}
    </div>
  \`;
}

function renderPlanMappingPanel() {
  const maxHoursDefault = getPlanExtractMaxHoursDefaultForCurrentSchool();
  const seatPageIdDefault = escapeHtml(getPlanExtractSeatPageIdDefaultForCurrentSchool());
  const draft = getPlanMappingDraft();
  return \`
    <div class="mapping-grid">
      <div class="mapping-box">
        <h4>原始计划文本</h4>
        <div class="mapping-inline">
          <div>
            <label>最长单段小时数</label>
            <input type="number" id="plan_extract_max_hours" min="0" step="0.5" value="\${maxHoursDefault}" onchange="handlePlanExtractMaxHoursChange(this)">
          </div>
          <div class="mapping-note" style="margin-top:0">
            留空默认 \${maxHoursDefault} 小时，填 <code>0</code> 表示不拆分超长时间段。
          </div>
        </div>
        <div class="mapping-user-fields">
          <div>
            <label>手机号</label>
            <input type="text" id="plan_extract_phone" value="\${escapeHtml(draft.phone || "")}" placeholder="生成新用户草稿时带入" oninput="persistPlanMappingDraft()">
          </div>
          <div>
            <label>密码</label>
            <input type="text" id="plan_extract_password" value="\${escapeHtml(draft.password || "")}" placeholder="生成新用户草稿时带入" oninput="persistPlanMappingDraft()">
          </div>
          <div>
            <label>昵称</label>
            <input type="text" id="plan_extract_username" value="\${escapeHtml(draft.username || "")}" placeholder="生成新用户草稿时带入" oninput="persistPlanMappingDraft()">
          </div>
          <div>
            <label>seatPageId</label>
            <input type="text" id="plan_extract_seat_page_id" value="\${seatPageIdDefault}" placeholder="可选；不填则默认等于 roomid" onchange="handlePlanExtractSeatPageIdChange(this)">
          </div>
        </div>
        <textarea id="plan_extract_input" rows="12" placeholder="示例：
自习室id：13476
座位号:367
时间段:
周一:14:30-22:00
周二:9:30-22:00
每天:16:30-22:00">\${escapeHtml(draft.text ?? "自习室id:")}</textarea>
        <div class="mapping-actions">
          <button type="button" class="btn btn-primary" onclick="generatePlanMappingJson()">生成周计划 JSON</button>
          <button type="button" class="btn btn-success" onclick="createMappedUserDraft()">一键生成新用户草稿</button>
        </div>
        <div class="mapping-note">
          支持 <code>周一:08:00-12:00，14:00-16:00</code>、空格分隔多个时段、<code>8点到12点</code>、<code>8点半到12点半</code>，以及 <code>13.00-18.00</code>。未指定星期的 <code>时间段:08:00-22:00</code> 默认代表周一至周日。
          “一键生成新用户草稿”会把上面手动填写的手机号、密码、昵称带入新增用户弹窗，不会覆盖已有用户；真正保存时仍走现有座位冲突校验。
          这些输入会按当前学校保存在本浏览器中；密码也会保存在浏览器本地，请勿在公共设备上使用。
        </div>
      </div>
      <div class="mapping-box">
        <h4>周计划 JSON 映射结果</h4>
        <textarea id="plan_extract_output" rows="12" readonly placeholder="生成后会出现在这里，可直接复制，也会被一键带入新增用户弹窗。"></textarea>
        <div class="mapping-actions">
          <button type="button" class="btn btn-secondary" onclick="copyPlanMappingJson()">复制 JSON</button>
        </div>
        <div class="mapping-note">
          输出结构与用户弹窗里的“周计划 JSON 映射”兼容。若你手填了 <code>seatPageId</code>，就优先使用它；没填时才自动回退为 <code>roomid</code>，并带上当前学校配置里的 <code>fidEnc</code>。
        </div>
      </div>
    </div>
  \`;
}

function renderEditSchoolModal() {
  const s = currentSchool || {};
  const st = s.strategy || {};
  const readingZonesText = JSON.stringify(s.reading_zone_groups || [], null, 2)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
  return \`
    <div class="modal" id="editSchoolModal">
      <div class="modal-content">
        <div class="modal-header">
          <h3>编辑学校配置</h3>
          <span class="modal-close" onclick="closeModal('editSchoolModal')">&times;</span>
        </div>
        <div class="modal-body">
          <div class="form-row">
            <div class="form-group">
              <label>学校名称</label>
              <input type="text" id="edit_school_name" value="\${s.name || ''}">
            </div>
            <div class="form-group">
              <label>GitHub 仓库</label>
              <input type="text" id="edit_school_repo" value="\${s.repo || ''}">
            </div>
          </div>
          <div class="form-group">
            <label>分发目标</label>
            <select id="edit_school_dispatch_target">
              <option value="github" \${(!s.dispatch_target || s.dispatch_target==="github") ? "selected" : ""}>github - 仅 GitHub Actions</option>
              <option value="server_relay" \${s.dispatch_target==="server_relay" ? "selected" : ""}>server_relay - GitHub 中转到服务器</option>
            </select>
          </div>
          <div class="form-group">
            <label>GitHub 密匙槽位</label>
            <select id="edit_school_github_token_key">
              <option value="" \${!s.github_token_key ? "selected" : ""}>默认 GH_TOKEN</option>
              <option value="a" \${s.github_token_key==="a" ? "selected" : ""}>A -> GH_TOKEN_A</option>
              <option value="b" \${s.github_token_key==="b" ? "selected" : ""}>B -> GH_TOKEN_B</option>
              <option value="c" \${s.github_token_key==="c" ? "selected" : ""}>C -> GH_TOKEN_C</option>
              <option value="d" \${s.github_token_key==="d" ? "selected" : ""}>D -> GH_TOKEN_D</option>
              <option value="e" \${s.github_token_key==="e" ? "selected" : ""}>E -> GH_TOKEN_E</option>
            </select>
          </div>
          <div id="edit_school_server_only_fields">
            <div class="form-group">
              <label>选座接口模式</label>
              <select id="edit_school_seat_api_mode">
                <option value="auto" \${s.seat_api_mode==="auto" ? "selected" : ""}>auto - 固定 seatengine，不跨接口回退</option>
                <option value="seatengine" \${s.seat_api_mode==="seatengine" ? "selected" : ""}>seatengine - 强制新版接口</option>
                <option value="seat" \${(!s.seat_api_mode || s.seat_api_mode==="seat") ? "selected" : ""}>seat - 强制旧版接口</option>
                <option value="seatengine_code" \${s.seat_api_mode==="seatengine_code" ? "selected" : ""}>seatengine_code - seatengine code 页面</option>
                <option value="seat_code" \${s.seat_api_mode==="seat_code" ? "selected" : ""}>seat_code - seat code 页面</option>
              </select>
            </div>
            <div class="form-row">
              <div class="form-group">
                <label><input type="checkbox" id="edit_school_reserve_next_day" \${s.reserve_next_day === false ? "" : "checked"}> 预约明天</label>
              </div>
              <div class="form-group">
                <label><input type="checkbox" id="edit_school_enable_slider" \${s.enable_slider ? "checked" : ""}> 启用滑块验证码</label>
              </div>
            </div>
            <div class="form-row">
              <div class="form-group">
                <label><input type="checkbox" id="edit_school_enable_textclick" \${s.enable_textclick ? "checked" : ""}> 启用选字验证码</label>
              </div>
              <div class="form-group">
                <label><input type="checkbox" id="edit_school_enable_iconclick" \${s.enable_iconclick ? "checked" : ""}> 启用图标验证码</label>
              </div>
              <div class="form-group">
                <label>图标验证码识别平台</label>
                <select id="edit_school_iconclick_ocr_provider">
	                  <option value="chaojiying" \${normalizeIconclickOcrProvider(s.iconclick_ocr_provider) === "chaojiying" ? "selected" : ""}>超级鹰 9103（默认）</option>
	                  <option value="tulingcloud" \${normalizeIconclickOcrProvider(s.iconclick_ocr_provider) === "tulingcloud" ? "selected" : ""}>图灵云（图标模型）</option>
	                  <option value="jfbym" \${normalizeIconclickOcrProvider(s.iconclick_ocr_provider) === "jfbym" ? "selected" : ""}>jfbym（图标模型）</option>
                </select>
              </div>
              <div class="form-group">
                <label><input type="checkbox" id="edit_school_enable_rotate" \${s.enable_rotate ? "checked" : ""}> 启用旋转滑块验证码</label>
              </div>
              <div class="form-group">
                <label>旋转滑块识别平台</label>
                <select id="edit_school_rotate_ocr_provider">
                  <option value="geepass" \${normalizeRotateOcrProvider(s.rotate_ocr_provider) === "geepass" ? "selected" : ""}>GeePass → 图灵云 → JFBYM</option>
                  <option value="tulingcloud" \${normalizeRotateOcrProvider(s.rotate_ocr_provider) === "tulingcloud" ? "selected" : ""}>图灵云 → GeePass → JFBYM</option>
                  <option value="jfbym" \${normalizeRotateOcrProvider(s.rotate_ocr_provider) === "jfbym" ? "selected" : ""}>JFBYM → GeePass → 图灵云</option>
                </select>
              </div>
            </div>
          </div>
          <div id="edit_school_relay_fields">
            <div class="form-row">
              <div class="form-group">
                <label>服务器分发地址</label>
                <input type="text" id="edit_school_server_url" value="\${s.server_url || ''}" placeholder="例如: https://your-server.example.com/dispatch">
              </div>
              <div class="form-group">
                <label>服务器最大并发</label>
                <input type="number" id="edit_school_server_max_concurrency" value="\${s.server_max_concurrency || 13}" min="1">
              </div>
            </div>
            <div class="form-group">
              <label>提交 day 日期偏移（仅服务器中转）</label>
              <input type="number" id="edit_school_reserve_day_offset" min="0" step="1" value="\${s.reserve_day_offset === null || s.reserve_day_offset === undefined ? '' : s.reserve_day_offset}" placeholder="留空沿用预约明天；0 今天，1 明天，2 后天">
            </div>
          </div>
          <div class="form-group">
            <label>服务器 API Key（GitHub 验证码兜底及服务器中转共用）</label>
            <input type="text" id="edit_school_server_api_key" value="" placeholder="\${s.has_server_api_key ? '已配置，留空不修改' : '留空则使用 Worker 环境变量 SERVER_DISPATCH_API_KEY'}">
          </div>
          <div class="form-group">
            <label>GitHub 验证码备用服务器（默认）</label>
            <input type="text" value="http://62.234.222.77" readonly>
            <div class="user-top-config-note">自动使用 /rotate 或 /recognize 接口，无需填写。</div>
          </div>
          <div class="form-group">
            <label><input type="checkbox" id="edit_school_schedule_store_by_reserve_date" \${s.schedule_store_by_reserve_date ? "checked" : ""}> KV 周计划按预约日期存储</label>
            <div class="user-top-config-note">前端按执行日显示和修改；后台根据预约明天或提交 day 日期偏移自动映射 KV 星期。</div>
          </div>
          <div class="form-group">
            <label>冲突分组</label>
            <input type="text" id="edit_school_conflict_group" value="\${s.conflict_group || ''}" placeholder="可留空；留空时优先按学校 fidEnc 自动归并">
          </div>
          <div class="form-group">
            <label><input type="checkbox" id="edit_school_ignore_seat_conflicts" \${s.ignore_seat_conflicts ? "checked" : ""}> 不检测相同座位冲突</label>
          </div>
          <div class="form-row">
            <div class="form-group">
              <label>正式开始时间 (HH:MM)</label>
              <input type="text" id="edit_school_trigger" value="\${s.trigger_time || '19:57'}">
            </div>
            <div class="form-group">
              <label>正式截止时间 (HH:MM:SS)</label>
              <input type="text" id="edit_school_endtime" value="\${s.endtime || '20:00:40'}" oninput="updateSchoolStrategyNotice()">
            </div>
          </div>
          <div class="form-group">
            <label>学校统一 fidEnc（全校共用）</label>
            <input type="text" id="edit_school_fidEnc" value="\${s.fidEnc || ''}" placeholder="例如: 1b001674cae092c3">
          </div>
          <div class="form-group">
            <label>阅览区映射 JSON（reading_zone_groups）</label>
            <textarea id="edit_school_reading_zones" rows="8" placeholder='示例: [{"floor":"3楼","zones":[{"id":"13484","name":"中阅览区"}]}]'>\${readingZonesText}</textarea>
            <div class="mapping-actions">
              <button type="button" class="btn btn-success" id="map_reading_zones_btn" onclick="mapReadingZonesForCurrentSchool()">一键映射阅览区</button>
            </div>
            <div class="mapping-note">
              会使用本组下第一个可登录用户读取超星 room/list，并直接保存到当前学校配置；成功后后续一直使用这份映射。
            </div>
          </div>
          <h4 style="margin:20px 0 12px">策略配置</h4>
          <div class="form-row">
            <div class="form-group">
              <label>策略模式（mode）</label>
              <select id="edit_strategy_mode" onchange="updateSchoolStrategyNotice()">
                <option value="A" \${st.mode==="A"?"selected":""}>A - 预取token</option>
                <option value="B" \${st.mode==="B"?"selected":""}>B - 即时取token</option>
                <option value="C" \${st.mode==="C"?"selected":""}>C - 延迟取token</option>
              </select>
              <div id="edit_strategy_mode_notice" class="user-top-config-note" hidden>目标秒数为 00，仍将按策略 A 执行。</div>
            </div>
            <div class="form-group">
              <label>提交并发方式（submit_mode）</label>
              <select id="edit_strategy_submit">
                <option value="serial" \${st.submit_mode==="serial"?"selected":""}>serial - 串行</option>
                <option value="burst" \${st.submit_mode==="burst"?"selected":""}>burst - 并行</option>
              </select>
            </div>
          </div>
          <div class="form-row">
            <div class="form-group">
              <label>提前登录随机范围（login_lead_seconds_range）</label>
              <input type="text" id="edit_strategy_login_range" value="\${(st.login_lead_seconds_range || [st.login_lead_seconds || 14, st.login_lead_seconds || 14]).join(',')}" placeholder="例如: 16,25">
            </div>
            <div class="form-group">
              <label>验证码预热提前随机范围（slider_lead_seconds_range，毫秒）</label>
              <input type="text" id="edit_strategy_slider_range" value="\${(st.slider_lead_seconds_range || [10000, 10000]).map(normalizeSliderLeadRangeValueMs).join(',')}" placeholder="例如: 18000,20500">
            </div>
          </div>
          <div class="form-row">
            <div class="form-group">
              <label>首枪偏移随机范围（first_submit_offset_range_ms）</label>
              <input type="text" id="edit_strategy_first_range" value="\${(st.first_submit_offset_range_ms || [st.first_submit_offset_ms || 9, st.first_submit_offset_ms || 9]).join(',')}" placeholder="例如: 5,30">
            </div>
            <div class="form-group">
              <label>取 token 延迟毫秒（token_fetch_delay_ms）</label>
              <input type="number" id="edit_strategy_delay" value="\${st.token_fetch_delay_ms || 45}">
            </div>
          </div>
          <div class="form-row">
            <div class="form-group">
              <label>轻探测随机范围（fast_probe_start_range_ms）</label>
              <input type="text" id="edit_strategy_probe_start_range" value="\${(st.fast_probe_start_range_ms || [st.fast_probe_start_offset_ms || 14, st.fast_probe_start_offset_ms || 14]).join(',')}" placeholder="例如: 8,20">
            </div>
            <div class="form-group">
              <label>预取 token 随机范围（pre_fetch_token_range_ms）</label>
              <input type="text" id="edit_strategy_prefetch_range" value="\${(st.pre_fetch_token_range_ms || [st.pre_fetch_token_ms || 1531, st.pre_fetch_token_ms || 1531]).join(',')}" placeholder="例如: 1200,2400">
            </div>
          </div>
          <div class="form-row">
            <div class="form-group">
              <label>连接预热提前毫秒（warm_connection_lead_ms）</label>
              <input type="number" id="edit_strategy_warm_lead" value="\${st.warm_connection_lead_ms || 2400}">
            </div>
            <div class="form-group"></div>
          </div>
          <div class="form-row">
            <div class="form-group">
              <label>正式取 token 超时毫秒（token_fetch_timeout_ms）</label>
              <input type="number" id="edit_strategy_token_timeout" min="1" value="\${st.token_fetch_timeout_ms || 2830}">
            </div>
            <div class="form-group">
              <label>轻探测超时毫秒（fast_probe_timeout_ms）</label>
              <input type="number" id="edit_strategy_fast_probe_timeout" min="1" value="\${st.fast_probe_timeout_ms || 2830}">
            </div>
          </div>
          <div class="form-row">
            <div class="form-group">
              <label>首次取 token 日期（first_token_date_mode）</label>
              <select id="edit_strategy_first_token_date_mode">
                <option value="submit_date" \${(!st.first_token_date_mode || st.first_token_date_mode==="submit_date")?"selected":""}>submit_date - 与提交日期一致</option>
                <option value="today" \${st.first_token_date_mode==="today"?"selected":""}>today - 使用当天日期</option>
              </select>
            </div>
            <div class="form-group">
              <label><input type="checkbox" id="edit_strategy_skip_first_seat_query" \${st.skip_first_seat_query === false ? "" : "checked"}> 首抢不查询座位</label>
              <div class="user-top-config-note">关闭后，A/C 模式首枪会先查 getusedtimes，再决定是否切换备选座位。</div>
            </div>
          </div>
          <div style="font-size:12px;color:#666;margin-top:6px">
            说明：学校批量触发时，会按固定批次拆成多个 workflow；当前每个 workflow 默认承载 10 个用户。
          </div>
          <button class="btn btn-primary" onclick="doEditSchool()" style="width:100%;margin-top:16px">保存配置</button>
          <button class="btn btn-danger" onclick="doDeleteSchool()" style="width:100%;margin-top:8px">删除学校</button>
        </div>
      </div>
    </div>
  \`;
}

function renderUserModal() {
  const days = ["Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday"];
  const dayNames = {"Monday":"周一","Tuesday":"周二","Wednesday":"周三","Thursday":"周四","Friday":"周五","Saturday":"周六","Sunday":"周日"};
  return \`
    <div class="modal" id="userModal">
      <div class="modal-content">
        <div class="modal-header">
          <h3 id="userModalTitle">添加用户</h3>
          <span class="modal-close" onclick="closeModal('userModal')">&times;</span>
        </div>
        <div class="modal-body">
          <input type="hidden" id="edit_user_id">
          <div id="user_migrate_tools" class="user-migrate-tools" style="display:none">
            <div class="user-migrate-row">
              <div class="form-group" style="margin-bottom:0">
                <label>迁移到目标组 ID</label>
                <input type="text" id="migrate_user_target_group" placeholder="输入目标组 ID">
              </div>
              <button type="button" id="migrateUserButton" class="btn btn-secondary" onclick="migrateCurrentUser()">迁移用户</button>
            </div>
            <div class="user-migrate-note">迁移会保留当前用户配置，并从当前组移除；目标组座位冲突时不会迁移。</div>
          </div>
          <div class="form-row">
            <div class="form-group">
              <label>手机号（登录账号）</label>
              <input type="text" id="edit_user_phone" placeholder="超星登录手机号">
            </div>
            <div class="form-group">
              <label>密码（可查看/修改）</label>
              <div class="password-input-wrap">
                <input type="password" id="edit_user_password" autocomplete="new-password">
                <button type="button" class="password-eye" id="edit_user_password_eye" title="显示明文密码" aria-label="显示明文密码" onclick="toggleEditUserPasswordVisibility()">◉</button>
              </div>
            </div>
          </div>
          <div class="form-row">
            <div class="form-group">
              <label>昵称（便于识别）</label>
              <input type="text" id="edit_user_username" placeholder="如：张三">
            </div>
            <div class="form-group">
              <label>备注</label>
              <input type="text" id="edit_user_remark" placeholder="其他备注">
            </div>
          </div>
          <div class="sign-config">
            <label class="sign-config-toggle">
              <input type="checkbox" id="edit_user_sign_feature_visible" onchange="toggleAutoSignFields()">
              允许显示自动签到开关
            </label>
            <div id="edit_user_auto_sign_fields" style="display:none;margin-top:10px;padding-top:10px;border-top:1px solid #d8ead8">
              <label class="sign-config-toggle">
                <input type="checkbox" id="edit_user_auto_sign_enabled">
                自动签到
              </label>
            </div>
            <div class="user-top-config-note">只有允许显示后，此用户才可以开启自动签到；未允许时保存和派发都会强制关闭。</div>
          </div>
          <div class="user-top-config">
            <label class="user-top-config-toggle">
              <input type="checkbox" id="edit_user_top_config_enabled" onchange="toggleUserTopConfigFields()">
              为此用户定制个性化顶级参数
            </label>
            <div id="edit_user_top_config_fields" style="display:none">
              <div class="user-top-config-fields">
                <div class="form-group" style="margin-bottom:0">
                  <label>预取 token 随机范围（ms）</label>
                  <input type="text" id="edit_user_top_prefetch_range" placeholder="留空沿用学校配置，例如 1200,2400">
                </div>
                <div class="form-group" style="margin-bottom:0">
                  <label>首枪偏移随机范围（ms）</label>
                  <input type="text" id="edit_user_top_first_submit_range" placeholder="留空沿用学校配置，例如 5,30">
                </div>
                <div class="form-group" style="margin-bottom:0">
                  <label>轻探测随机范围（ms）</label>
                  <input type="text" id="edit_user_top_probe_start_range" placeholder="留空沿用学校配置，例如 8,20">
                </div>
                <div class="form-group" style="margin-bottom:0">
                  <label>策略模式（mode）</label>
                  <select id="edit_user_top_mode">
                    <option value="">留空沿用学校配置</option>
                    <option value="A">A - 预取 token</option>
                    <option value="B">B - 即时取 token</option>
                    <option value="C">C - 轻探测取 token</option>
                  </select>
                </div>
                <div class="form-group" style="margin-bottom:0">
                  <label>正式截止时间 (HH:MM:SS)</label>
                  <input type="text" id="edit_user_top_endtime" placeholder="留空沿用学校配置">
                </div>
                <div class="form-group" style="margin-bottom:0">
                  <label>首次取 token 日期</label>
                  <select id="edit_user_top_first_token_date_mode">
                    <option value="">留空沿用学校配置</option>
                    <option value="submit_date">submit_date - 与提交日期一致</option>
                    <option value="today">today - 使用当天日期</option>
                  </select>
                </div>
                <div class="form-group" style="margin-bottom:0">
                  <label>验证码预热提前随机范围（ms）</label>
                  <input type="text" id="edit_user_top_slider_range" placeholder="留空沿用学校配置，例如 18000,20500">
                </div>
              </div>
              <div class="user-top-config-note">只覆盖已填写的字段；留空字段继续使用学校配置。关闭勾选后整组用户级参数都不会生效。</div>
            </div>
          </div>
          <h4 style="margin:20px 0 12px">周计划配置</h4>
          <div id="user_global_time_tools" class="global-time-tools" style="display:none">
            <div class="global-config-fields">
              <input type="text" id="global_sync_roomid" placeholder="房间ID">
              <input type="text" id="global_sync_seatid" placeholder="座位号">
              <input type="text" id="global_sync_times" placeholder="时间段 08:00-12:00">
              <input type="text" id="global_sync_seatPageId" placeholder="页面ID">
              <input type="text" id="global_sync_fidEnc" placeholder="fidEnc">
              <input type="text" id="global_sync_backupSeats" placeholder="备选座位 13501-300,">
            </div>
            <div class="global-config-actions">
              <button type="button" class="btn btn-primary" onclick="applyUserGlobalConfigSync()">同步到已有配置</button>
              <button type="button" class="btn btn-secondary" onclick="resetUserGlobalSyncInputs()">清空输入</button>
            </div>
            <div class="global-time-note">只同步已填写的字段，空着的字段保持原样；只作用于当前用户已有配置，同步后仍需点击“保存用户”。</div>
          </div>
          <div class="user-top-config-note">以下星期始终表示执行抢座的当天；若学校开启“KV 周计划按预约日期存储”，后台会自动换算，编辑时也会自动还原。</div>
          <div class="schedule-grid">
            \${days.map(d => \`
              <div class="schedule-day">
                <div class="schedule-day-header">
                  <input type="checkbox" id="sch_\${d}_enabled">
                  <label>\${dayNames[d]}</label>
                </div>
                \${[0,1,2,3].map(i => \`
                  <div class="slot-row" id="sch_\${d}_row_\${i}" style="\${i > 0 ? 'display:none;' : ''}">
                    <div class="slot-label">时段\${i+1}</div>
                    <div class="schedule-day-fields">
                      <input type="text" id="sch_\${d}_s\${i}_roomid" placeholder="房间ID">
                      <input type="text" id="sch_\${d}_s\${i}_seatid" placeholder="座位号(逗号分隔)">
                      <input type="text" id="sch_\${d}_s\${i}_times" placeholder="09:00-22:00">
                    </div>
                    <div class="schedule-day-fields" style="margin-top:4px">
                      <input type="text" id="sch_\${d}_s\${i}_seatPageId" placeholder="seatPageId">
                      <input type="text" id="sch_\${d}_s\${i}_fidEnc" placeholder="fidEnc">
                      <input type="text" id="sch_\${d}_s\${i}_backupSeats" placeholder="备选座位 13501-300,13502-340,">
                    </div>
                  </div>
                \`).join("")}
                <button type="button" class="btn btn-sm btn-secondary" onclick="addSlotForDay('\${d}')">+ 添加时段</button>
              </div>
            \`).join("")}
          </div>
          <div class="form-group" style="margin-top:12px">
            <label>周计划 JSON 映射（单一输入框）</label>
            <textarea id="edit_user_schedule_json" rows="8" placeholder="自习室id:13484&#10;座位号:356&#10;时间段:&#10;周一:09:00-23:00&#10;周二:09:00-23:00"></textarea>
            <div class="user-top-config-note">按住鼠标中键并拖动，可像文本编辑器一样进行矩形列选择。编辑已有用户时，映射只更新时间段和 seatid，其余座位配置沿用原配置。</div>
            <button type="button" class="btn btn-secondary" onclick="applyScheduleJsonToForm()" style="margin-top:8px">映射到周计划配置</button>
          </div>
          <div class="user-top-config" style="margin-top:20px">
            <div class="panel-header">
              <h4 style="margin:0">续费设置</h4>
              <button type="button" id="toggle_user_renewal" class="btn btn-secondary" onclick="toggleRenewalCard()">查看/修改续费记录</button>
            </div>
            <div id="edit_user_renewal_fields" style="display:none;margin-top:12px">
              <div class="renewal-summary">
                <div class="renewal-stat">
                  <span>本轮开始日期</span>
                  <strong id="edit_user_renewal_started_on">未设置</strong>
                </div>
                <div class="renewal-stat">
                  <span>计划已用</span>
                  <strong id="edit_user_renewal_used">0 天</strong>
                </div>
                <div class="renewal-stat">
                  <span>距离过期</span>
                  <strong id="edit_user_renewal_remaining">未设置结束日期</strong>
                </div>
              </div>
              <div class="form-row">
                <div class="form-group">
                  <label>续费结束日期</label>
                  <input type="date" id="edit_user_renewal_expires_on" onchange="markRenewalCardTouched(); updateRenewalRemaining()">
                </div>
                <div class="form-group">
                  <label>购买渠道标签</label>
                  <select id="edit_user_purchase_channel" onchange="markRenewalCardTouched()">
                    <option value="">未打标签</option>
                    <option value="primary_wechat">主微信</option>
                    <option value="secondary_wechat">次微信</option>
                    <option value="qq">QQ</option>
                    <option value="xianyu">闲鱼</option>
                  </select>
                </div>
              </div>
              <div class="inline-actions">
                <button type="button" class="btn btn-secondary" onclick="extendRenewalDate(1)">+1 月</button>
                <button type="button" class="btn btn-secondary" onclick="extendRenewalDate(3)">+3 月</button>
                <button type="button" class="btn btn-secondary" onclick="extendRenewalDate(12)">+1 年</button>
              </div>
            </div>
          </div>
          <button id="saveUserButton" class="btn btn-primary" onclick="doSaveUser()" style="width:100%;margin-top:16px">保存用户</button>
        </div>
      </div>
    </div>
  \`;
}

function renderUnitBindingWarningModal() {
  return \`
    <div class="modal" id="unitBindingWarningModal" role="alertdialog" aria-modal="true" aria-labelledby="unitBindingWarningTitle">
      <div class="modal-content" style="max-width:480px">
        <div class="modal-header">
          <h3 id="unitBindingWarningTitle">未绑定单位</h3>
        </div>
        <div class="modal-body">
          <p id="unitBindingWarningText" style="line-height:1.8;color:#555;white-space:pre-line"></p>
          <button type="button" class="btn btn-primary" onclick="closeModal('unitBindingWarningModal')" style="width:100%;margin-top:20px">确认</button>
        </div>
      </div>
    </div>
  \`;
}

function bindEvents() {
  const addTarget = document.getElementById("new_school_dispatch_target");
  const editTarget = document.getElementById("edit_school_dispatch_target");
  const toggleRelayFields = (targetId, fieldsId) => {
    const target = document.getElementById(targetId);
    const fields = document.getElementById(fieldsId);
    if (!target || !fields) return;
    fields.style.display = isServerRelayTarget(target.value) ? "" : "none";
  };
  if (addTarget && !addTarget.dataset.boundChange) {
    addTarget.addEventListener("change", () => toggleRelayFields("new_school_dispatch_target", "new_school_relay_fields"));
    addTarget.dataset.boundChange = "1";
  }
  if (editTarget && !editTarget.dataset.boundChange) {
    editTarget.addEventListener("change", () => toggleRelayFields("edit_school_dispatch_target", "edit_school_relay_fields"));
    editTarget.dataset.boundChange = "1";
  }
  toggleRelayFields("new_school_dispatch_target", "new_school_relay_fields");
  toggleRelayFields("edit_school_dispatch_target", "edit_school_relay_fields");

  const testTriggerInput = document.getElementById("school_test_trigger_time");
  const testEndtimeInput = document.getElementById("school_test_endtime");
  const testDayInputs = Array.from(document.querySelectorAll("input[name='school_test_reserve_day']"));
  if (testTriggerInput && !testTriggerInput.dataset.boundPersist) {
    testTriggerInput.addEventListener("change", persistTestEndtimeDefaults);
    testTriggerInput.dataset.boundPersist = "1";
  }
  if (testEndtimeInput && !testEndtimeInput.dataset.boundPersist) {
    testEndtimeInput.addEventListener("change", persistTestEndtimeDefaults);
    testEndtimeInput.dataset.boundPersist = "1";
  }
  for (const input of testDayInputs) {
    if (!input.dataset.boundPersist) {
      input.addEventListener("change", persistTestEndtimeDefaults);
      input.dataset.boundPersist = "1";
    }
  }
}

async function doLogin() {
  const key = document.getElementById("apiKey").value.trim();
  if (!key) return toast("请输入密钥", "error");
  API_KEY = key;
  const res = await api("GET", "/api/schools");
  if (res.error) {
    toast(
      res.status === 401
        ? "密钥错误"
        : (res.error + (res.detail ? ": " + res.detail : "")),
      "error"
    );
    return;
  }
  localStorage.setItem("api_key", key);
  schools = getSortedSchoolsForDisplay(res.schools || []);
  currentView = "schools";
  render();
  refreshSchoolActiveTodayCounts(true);
}

async function loadSchools(options = {}) {
  const res = await api("GET", "/api/schools");
  schools = getSortedSchoolsForDisplay(res.schools || []);
  if (!options.silent) render();
  refreshSchoolActiveTodayCounts();
}

function handleSchoolSearchKeydown(event) {
  if (event.key === "Enter") {
    event.preventDefault();
    searchSchoolsByUser();
  }
}

async function searchSchoolsByUser() {
  await runSchoolUserSearch({ jump: false });
}

async function searchSchoolsByUserAndJump() {
  await runSchoolUserSearch({ jump: true });
}

async function runSchoolUserSearch(options = {}) {
  const input = document.getElementById("school_user_search_input");
  const query = (input ? input.value : schoolSearch.query).trim();
  if (!query) {
    schoolSearch = { query: "", loading: false, error: "", results: [] };
    render();
    return;
  }
  schoolSearch = { query, loading: true, error: "", results: [] };
  render();
  try {
    const res = await api("GET", "/api/users/search?q=" + encodeURIComponent(query));
    if (res.error) throw new Error(res.error);
    schoolSearch = {
      query,
      loading: false,
      error: "",
      results: Array.isArray(res.results) ? res.results : [],
    };
    if (options.jump && schoolSearch.results.length === 1 && schoolSearch.results[0]?.school?.id) {
      openSchool(schoolSearch.results[0].school.id);
      return;
    }
    if (options.jump && schoolSearch.results.length > 1) {
      toast("有重复卡片，不自动跳转，请在结果卡片中选择进入");
    }
    if (options.jump && schoolSearch.results.length === 0) {
      toast("无用户", "error");
    }
  } catch (error) {
    schoolSearch = {
      query,
      loading: false,
      error: error.message || String(error),
      results: [],
    };
  }
  render();
}

function showAddSchool() {
  showModal("addSchoolModal");
}

function showModal(id) {
  const modal = document.getElementById(id);
  if (!modal) {
    console.warn("Modal " + id + " is not mounted");
    return false;
  }
  modal.classList.add("show");
  return true;
}

function closeModal(id) {
  const modal = document.getElementById(id);
  if (!modal) {
    console.warn("Modal " + id + " is not mounted");
    return false;
  }
  modal.classList.remove("show");
  return true;
}

function showUnitBindingWarning(detail) {
  const text = document.getElementById("unitBindingWarningText");
  if (text) {
    text.textContent = "用户已成功保存到 KV 和服务器，但连续 3 次未能从真实选座页获取页面 token。请确认该超星账号已绑定学校/单位。" + (detail ? "\\n" + detail : "");
  }
  showModal("unitBindingWarningModal");
}

async function doAddSchool() {
  const id = document.getElementById("new_school_id").value.trim();
  const name = document.getElementById("new_school_name").value.trim();
  const repo = document.getElementById("new_school_repo").value.trim();
  const dispatch_target = document.getElementById("new_school_dispatch_target").value.trim().toLowerCase();
  const conflict_group = document.getElementById("new_school_conflict_group").value.trim();
  const github_token_key = document.getElementById("new_school_github_token_key").value.trim().toLowerCase();
  const trigger_time = document.getElementById("new_school_trigger").value.trim();
  const endtime = document.getElementById("new_school_endtime").value.trim();
  const fidEnc = document.getElementById("new_school_fidEnc").value.trim();
  if (!id || !name) return toast("请填写必要信息", "error");
  const formalTimeError = validateFormalTimeWindowInput(trigger_time, endtime);
  if (formalTimeError) return toast(formalTimeError, "error");
  if (!confirmFormalEndtimeUnder40(endtime)) return;
  const body = {
    id,
    name,
    repo,
    dispatch_target,
    conflict_group,
    ignore_seat_conflicts: document.getElementById("new_school_ignore_seat_conflicts").checked,
    github_token_key,
    trigger_time: normalizeClientTriggerTimeInput(trigger_time),
    endtime: normalizeClientEndtimeInput(endtime),
    fidEnc,
  };
  body.seat_api_mode = document.getElementById("new_school_seat_api_mode").value.trim().toLowerCase();
  body.reserve_next_day = document.getElementById("new_school_reserve_next_day").checked;
  body.schedule_store_by_reserve_date = document.getElementById("new_school_schedule_store_by_reserve_date").checked;
  body.enable_slider = document.getElementById("new_school_enable_slider").checked;
  body.enable_textclick = document.getElementById("new_school_enable_textclick").checked;
  body.enable_iconclick = document.getElementById("new_school_enable_iconclick").checked;
  body.iconclick_ocr_provider = document.getElementById("new_school_iconclick_ocr_provider").value;
  body.enable_rotate = document.getElementById("new_school_enable_rotate").checked;
  body.rotate_ocr_provider = document.getElementById("new_school_rotate_ocr_provider").value;
  body.server_api_key = document.getElementById("new_school_server_api_key").value.trim();
  if (isServerRelayTarget(dispatch_target)) {
    body.server_url = document.getElementById("new_school_server_url").value.trim();
    body.server_max_concurrency = parseInt(document.getElementById("new_school_server_max_concurrency").value, 10) || 13;
    const reserveDayOffsetRaw = document.getElementById("new_school_reserve_day_offset").value;
    const reserveDayOffset = normalizeReserveDayOffsetInput(reserveDayOffsetRaw);
    if (String(reserveDayOffsetRaw || "").trim() && reserveDayOffset === null) {
      return toast("提交 day 日期偏移只能填 0、1、2 这类非负整数", "error");
    }
    if (reserveDayOffset !== null) body.reserve_day_offset = reserveDayOffset;
  } else {
    body.reserve_day_offset = null;
  }
  const res = await api("POST", "/api/school", body);
  if (res.ok) {
    toast(res.serverCheck
      ? (res.serverCheck.ok ? "学校添加成功，服务器连接正常" : "学校已保存，但" + res.serverCheck.error)
      : "学校添加成功",
      res.serverCheck && !res.serverCheck.ok ? "error" : "success");
    closeModal("addSchoolModal");
    if (res.school) {
      schools = upsertSchoolInOrderedList(schools, res.school, { forceResort: true });
      render();
      refreshSchoolActiveTodayCounts(true);
    } else {
      loadSchools();
    }
  } else {
    toast(res.error || "添加失败", "error");
  }
}

async function openSchool(id) {
  activeTodayRefreshRunId++;
  const [res, usersRes] = await Promise.all([
    api("GET", "/api/school/" + id),
    api("GET", "/api/school/" + id + "/users"),
  ]);
  if (res.error) return toast(res.error, "error");
  if (usersRes.error) return toast(usersRes.error, "error");
  currentSchool = res.school;
  currentConflictGroupKey = "";
  currentConflictGroupSchools = [];
  conflictGroupUsersLoading = false;
  userModalReturnConflictGroupKey = "";
  users = usersRes.users || [];
  setCachedActiveTodayCount(id, {
    count: countActiveUsersForTodayClient(users, currentSchool),
    totalCount: users.length,
    expiresAt: Date.now() + ACTIVE_TODAY_CACHE_TTL_MS,
    error: "",
  });
  currentView = "school";
  render();
}

async function openConflictGroup(key) {
  activeTodayRefreshRunId++;
  const groupSchools = schools.filter(s => getClientSchoolConflictGroup(s) === key);
  if (groupSchools.length < 2) return toast("该冲突组不存在或学校数量不足", "error");
  const cached = conflictGroupUsersCache.get(key);

  currentConflictGroupKey = key;
  currentConflictGroupSchools = groupSchools;
  conflictGroupUsersLoading = !cached;
  userModalReturnConflictGroupKey = "";
  currentSchool = null;
  users = cached?.users || [];
  currentView = "conflict-group";
  render();
  if (cached && Date.now() - cached.cachedAt < CONFLICT_GROUP_USERS_CACHE_TTL_MS) return;

  const results = await Promise.all(groupSchools.map(async school => ({
    school,
    response: await api("GET", "/api/school/" + school.id + "/users"),
  })));
  if (currentView !== "conflict-group" || currentConflictGroupKey !== key) return;
  const failed = results.find(item => item.response.error);
  conflictGroupUsersLoading = false;
  if (failed) {
    render();
    return toast(failed.response.error || ("读取学校 " + failed.school.id + " 用户失败"), "error");
  }

  const nextUsers = results.flatMap(({ school, response }) => {
    const schoolUsers = response.users || [];
    setCachedActiveTodayCount(school.id, {
      count: countActiveUsersForTodayClient(schoolUsers, school),
      totalCount: schoolUsers.length,
      expiresAt: Date.now() + ACTIVE_TODAY_CACHE_TTL_MS,
      error: "",
    });
    return schoolUsers.map(user => ({
      ...user,
      __schoolId: school.id,
      __schoolName: school.name,
      __school: school,
    }));
  });
  conflictGroupUsersCache.set(key, { users: nextUsers, cachedAt: Date.now() });
  users = nextUsers;
  render();
}

function invalidateConflictGroupUsersCache() {
  for (const cached of conflictGroupUsersCache.values()) cached.cachedAt = 0;
}

async function refreshCurrentUserView(schoolId = "") {
  const groupKey = userModalReturnConflictGroupKey || currentConflictGroupKey;
  if (currentView === "conflict-group" || groupKey) {
    return openConflictGroup(groupKey);
  }
  return openSchool(schoolId || currentSchool?.id);
}

async function toggleScheduleStoreByReserveDate() {
  if (!currentSchool?.id) return;
  const nextEnabled = !currentSchool.schedule_store_by_reserve_date;
  const btn = document.getElementById("scheduleStoreToggleBtn");
  if (btn) {
    btn.disabled = true;
    btn.textContent = "保存中...";
  }
  const res = await api("PUT", "/api/school/" + currentSchool.id, {
    ...getCurrentSchoolFormalTimeGuard(),
    schedule_store_by_reserve_date: nextEnabled,
  });
  if (res.ok) {
    currentSchool = res.school;
    schools = upsertSchoolInOrderedList(schools, res.school);
    toast(nextEnabled ? "已开启预约日期存储显示" : "已关闭预约日期存储显示");
    render();
  } else {
    toast(res.error || "保存映射开关失败", "error");
    if (btn) {
      btn.disabled = false;
      btn.textContent = currentSchool.schedule_store_by_reserve_date ? "预约日期存储: 开" : "预约日期存储: 关";
    }
  }
}

function backToSchools() {
  currentSchool = null;
  currentConflictGroupKey = "";
  currentConflictGroupSchools = [];
  conflictGroupUsersLoading = false;
  userModalReturnConflictGroupKey = "";
  users = [];
  currentView = "schools";
  schools = getSortedSchoolsForDisplay(schools);
  render();
  refreshSchoolActiveTodayCounts();
  loadSchools({ silent: true });
}

function showEditSchool() {
  showModal("editSchoolModal");
  updateSchoolStrategyNotice();
}

async function readSeatConfigForCurrentSchool() {
  if (!currentSchool?.id) return toast("请先打开学校", "error");
  const button = document.getElementById("readSeatConfigBtn");
  if (button) {
    button.disabled = true;
    button.textContent = "读取中...";
  }
  try {
    const res = await api("POST", "/api/school/" + currentSchool.id + "/seat-config/read");
    if (!res.ok) return toast(res.error || "座位规则读取失败", "error");
    currentSchool = res.school || currentSchool;
    schools = upsertSchoolInOrderedList(schools, currentSchool);
    render();
    toast("座位规则已写入事项", "success");
  } finally {
    const currentButton = document.getElementById("readSeatConfigBtn");
    if (currentButton) {
      currentButton.disabled = false;
      currentButton.textContent = "读取座位规则";
    }
  }
}

function updateSchoolStrategyNotice() {
  const notice = document.getElementById("edit_strategy_mode_notice");
  const mode = document.getElementById("edit_strategy_mode")?.value;
  const endSeconds = parseClientEndtimeSeconds(
    document.getElementById("edit_school_endtime")?.value,
  );
  if (notice) notice.hidden = !(mode === "A" && endSeconds !== null && (endSeconds - 40 + 60) % 60 === 0);
}

async function mapReadingZonesForCurrentSchool() {
  if (!currentSchool?.id) return toast("请先打开学校", "error");
  if (!confirm("确定使用本组其中一个用户登录超星并映射阅览区吗？成功后会直接保存到当前学校配置。")) return;

  const button = document.getElementById("map_reading_zones_btn");
  const oldText = button ? button.textContent : "";
  if (button) {
    button.disabled = true;
    button.textContent = "映射中...";
  }

  try {
    const res = await api("POST", "/api/school/" + currentSchool.id + "/reading-zones/map", {
      ...getCurrentSchoolFormalTimeGuard(),
    });
    if (!res.ok) {
      return toast(res.error || "阅览区映射失败", "error");
    }
    currentSchool = res.school || currentSchool;
    if (res.school) {
      schools = upsertSchoolInOrderedList(schools, res.school);
    }
    const textarea = document.getElementById("edit_school_reading_zones");
    if (textarea) {
      textarea.value = JSON.stringify(currentSchool.reading_zone_groups || [], null, 2);
    }
    const mapped = res.mapped || {};
    toast("阅览区映射成功：楼层 " + (mapped.groupCount || 0) + " 组，分区 " + (mapped.zoneCount || 0) + " 个");
  } finally {
    if (button) {
      button.disabled = false;
      button.textContent = oldText || "一键映射阅览区";
    }
  }
}

async function doEditSchool() {
  const s = currentSchool;
  const beforeSchool = JSON.parse(JSON.stringify(s));
  const githubTokenKey = document.getElementById("edit_school_github_token_key").value.trim().toLowerCase();
  const dispatchTarget = document.getElementById("edit_school_dispatch_target").value.trim().toLowerCase();
  const {
    burst_offsets_ms: _burstOffsetsMs,
    burst_jitter_range_ms: _burstJitterRangeMs,
    ...baseStrategy
  } = s.strategy || {};
  const parseRangeInput = (id, fallbackA, fallbackB) => {
    const text = (document.getElementById(id).value || "").trim();
    const arr = text.split(",").map(v => parseInt(v.trim(), 10)).filter(v => !Number.isNaN(v));
    if (arr.length >= 2) return [arr[0], arr[1]];
    return [fallbackA, fallbackB];
  };
  const existingLoginLeadSeconds = parseInt((s.strategy || {}).login_lead_seconds, 10) || 14;
  const loginLeadRange = parseRangeInput(
    "edit_strategy_login_range",
    existingLoginLeadSeconds,
    existingLoginLeadSeconds,
  );
  const loginLeadSeconds = loginLeadRange[0];
  const existingSliderLeadRange = Array.isArray((s.strategy || {}).slider_lead_seconds_range)
    ? (s.strategy || {}).slider_lead_seconds_range.map(normalizeSliderLeadRangeValueMs)
    : [10000, 10000];
  const sliderLeadRange = parseRangeInput(
    "edit_strategy_slider_range",
    existingSliderLeadRange[0],
    existingSliderLeadRange[1],
  );
  const normalizedSliderLeadRange = sliderLeadRange.map(normalizeSliderLeadRangeValueMs);
  const existingProbeStartOffset = parseInt((s.strategy || {}).fast_probe_start_offset_ms, 10) || 14;
  const probeStartRange = parseRangeInput(
    "edit_strategy_probe_start_range",
    existingProbeStartOffset,
    existingProbeStartOffset,
  );
  const probeStartOffset = probeStartRange[0];
  const existingFirstSubmitOffset = parseInt((s.strategy || {}).first_submit_offset_ms, 10) || 9;
  const firstSubmitRange = parseRangeInput(
    "edit_strategy_first_range",
    existingFirstSubmitOffset,
    existingFirstSubmitOffset,
  );
  const firstSubmitOffset = firstSubmitRange[0];
  const existingPreFetchTokenMs = parseInt((s.strategy || {}).pre_fetch_token_ms, 10) || 1531;
  const preFetchTokenRange = parseRangeInput(
    "edit_strategy_prefetch_range",
    existingPreFetchTokenMs,
    existingPreFetchTokenMs,
  );
  const preFetchTokenMs = preFetchTokenRange[0];
  const readingZonesRaw = (document.getElementById("edit_school_reading_zones").value || "").trim();
  let readingZoneGroups = [];
  if (readingZonesRaw) {
    try {
      const parsed = JSON.parse(readingZonesRaw);
      if (!Array.isArray(parsed)) return toast("阅览区映射 JSON 必须是数组", "error");
      const normalized = normalizeReadingZoneGroups(parsed);
      if (!normalized.length) {
        return toast("阅览区映射 JSON 结构无效：请使用 floor/zones 或 roomid 列表", "error");
      }
      readingZoneGroups = normalized;
    } catch (e) {
      return toast("阅览区映射 JSON 解析失败: " + (e.message || String(e)), "error");
    }
  }
  const triggerTime = document.getElementById("edit_school_trigger").value.trim();
  const endtime = document.getElementById("edit_school_endtime").value.trim();
  const formalTimeError = validateFormalTimeWindowInput(triggerTime, endtime);
  if (formalTimeError) return toast(formalTimeError, "error");
  if (!confirmFormalEndtimeUnder40(endtime)) return;
  const normalizedTriggerTime = normalizeClientTriggerTimeInput(triggerTime);
  const normalizedEndtime = normalizeClientEndtimeInput(endtime);
  const body = {
    name: document.getElementById("edit_school_name").value.trim(),
    repo: document.getElementById("edit_school_repo").value.trim(),
    dispatch_target: dispatchTarget,
    conflict_group: document.getElementById("edit_school_conflict_group").value.trim(),
    ignore_seat_conflicts: document.getElementById("edit_school_ignore_seat_conflicts").checked,
    github_token_key: githubTokenKey,
    trigger_time: normalizedTriggerTime,
    endtime: normalizedEndtime,
    fidEnc: document.getElementById("edit_school_fidEnc").value.trim(),
    reading_zone_groups: readingZoneGroups,
    strategy: {
      ...baseStrategy,
      mode: document.getElementById("edit_strategy_mode").value,
      submit_mode: document.getElementById("edit_strategy_submit").value,
      login_lead_seconds: loginLeadSeconds,
      login_lead_seconds_range: loginLeadRange,
      slider_lead_seconds_range: normalizedSliderLeadRange,
      warm_connection_lead_ms: parseInt(document.getElementById("edit_strategy_warm_lead").value) || 2400,
      fast_probe_start_offset_ms: probeStartOffset,
      pre_fetch_token_ms: preFetchTokenMs,
      pre_fetch_token_range_ms: preFetchTokenRange,
      first_submit_offset_ms: firstSubmitOffset,
      first_submit_offset_range_ms: firstSubmitRange,
      token_fetch_delay_ms: parseInt(document.getElementById("edit_strategy_delay").value) || 45,
      token_fetch_timeout_ms: parseInt(document.getElementById("edit_strategy_token_timeout").value) || 2830,
      fast_probe_timeout_ms: parseInt(document.getElementById("edit_strategy_fast_probe_timeout").value) || 2830,
      first_token_date_mode: document.getElementById("edit_strategy_first_token_date_mode").value,
      skip_first_seat_query: document.getElementById("edit_strategy_skip_first_seat_query").checked,
      fast_probe_start_range_ms: probeStartRange,
    }
  };
  body.seat_api_mode = document.getElementById("edit_school_seat_api_mode").value.trim().toLowerCase();
  body.reserve_next_day = document.getElementById("edit_school_reserve_next_day").checked;
  body.schedule_store_by_reserve_date = document.getElementById("edit_school_schedule_store_by_reserve_date").checked;
  body.enable_slider = document.getElementById("edit_school_enable_slider").checked;
  body.enable_textclick = document.getElementById("edit_school_enable_textclick").checked;
  body.enable_iconclick = document.getElementById("edit_school_enable_iconclick").checked;
  body.iconclick_ocr_provider = document.getElementById("edit_school_iconclick_ocr_provider").value;
  body.enable_rotate = document.getElementById("edit_school_enable_rotate").checked;
  body.rotate_ocr_provider = document.getElementById("edit_school_rotate_ocr_provider").value;
  const serverApiKeyInput = document.getElementById("edit_school_server_api_key").value.trim();
  if (serverApiKeyInput && serverApiKeyInput !== "******") {
    body.server_api_key = serverApiKeyInput;
  }
  if (isServerRelayTarget(dispatchTarget)) {
    body.server_url = document.getElementById("edit_school_server_url").value.trim();
    body.server_max_concurrency = parseInt(document.getElementById("edit_school_server_max_concurrency").value, 10) || 13;
    const reserveDayOffsetRaw = document.getElementById("edit_school_reserve_day_offset").value;
    const reserveDayOffset = normalizeReserveDayOffsetInput(reserveDayOffsetRaw);
    if (String(reserveDayOffsetRaw || "").trim() && reserveDayOffset === null) {
      return toast("提交 day 日期偏移只能填 0、1、2 这类非负整数", "error");
    }
    body.reserve_day_offset = reserveDayOffset;
  } else {
    body.reserve_day_offset = null;
  }
  const res = await api("PUT", "/api/school/" + s.id, body);
  if (res.ok) {
    if (res.school && (
      normalizeClientTriggerTimeInput(res.school.trigger_time) !== normalizedTriggerTime
      || normalizeClientEndtimeInput(res.school.endtime) !== normalizedEndtime
    )) {
      toast(
        "保存回读异常：服务器返回 "
        + (res.school.trigger_time || "-")
        + " / "
        + (res.school.endtime || "-")
        + "，请刷新后重试",
        "error"
      );
      currentSchool = res.school;
      schools = upsertSchoolInOrderedList(schools, res.school);
      render();
      return;
    }
    let saveNoticeMessage = res.saveMode === "noop"
      ? "学校配置未修改"
      : buildSchoolSaveNotice(
          beforeSchool,
          res.school,
          Object.prototype.hasOwnProperty.call(body, "server_api_key"),
        );
    const targetSecondIsZero = body.strategy.mode === "A"
      && (parseClientEndtimeSeconds(body.endtime) - 40 + 60) % 60 === 0;
    if (targetSecondIsZero) saveNoticeMessage += "\\n目标秒数为 00，仍按策略 A 执行";
    if (res.serverCheck) {
      saveNoticeMessage += res.serverCheck.ok
        ? "\\n服务器连接：正常"
        : "\\n服务器连接：失败（" + res.serverCheck.error + "）";
    }
    showSchoolSaveNotice(saveNoticeMessage);
    currentSchool = res.school;
    schools = upsertSchoolInOrderedList(schools, res.school);
    closeModal("editSchoolModal");
    render();
  } else {
    toast(res.error || "保存失败", "error");
  }
}

async function doDeleteSchool() {
  if (!confirm("确定删除此学校及其所有用户？")) return;
  const res = await api("DELETE", "/api/school/" + currentSchool.id);
  if (res.ok) {
    toast("学校已删除");
    backToSchools();
  } else {
    toast(res.error || "删除失败", "error");
  }
}

async function triggerSchool() {
  if (!confirm("确定手动触发该学校所有活跃用户？")) return;
  const res = await api("POST", "/api/trigger/" + currentSchool.id);
  if (res.ok) {
    toast("已触发 " + (res.triggeredUsers || 0) + " 名用户，批次 " + (res.okBatches || 0) + "/" + (res.totalBatches || 0));
  } else {
    toast(res.error || "触发失败", "error");
  }
}

async function persistTestEndtimeDefaults(options = {}) {
  if (!currentSchool) return false;
  const triggerInput = document.getElementById("school_test_trigger_time");
  const endtimeInput = document.getElementById("school_test_endtime");
  const dayInput = document.querySelector("input[name='school_test_reserve_day']:checked");
  const testTriggerTime = (triggerInput && triggerInput.value || "").trim();
  if (testTriggerTime && parseClientTriggerSeconds(testTriggerTime) === null) {
    if (!options.silent) toast("测试开始时间格式应为 HH:MM", "error");
    return false;
  }
  const rawEndtime = (endtimeInput && endtimeInput.value || "").trim();
  const testEndtime = rawEndtime ? normalizeClientEndtimeInput(rawEndtime) : "";
  if (rawEndtime && !testEndtime) {
    if (!options.silent) toast("测试截止时间格式应为 HH:MM:SS", "error");
    return false;
  }
  const sameTimeWindowError = validateTestTimeWindowAgainstFormalClient(testTriggerTime, testEndtime);
  if (sameTimeWindowError) {
    if (!options.silent) toast(sameTimeWindowError, "error");
    return false;
  }

  const res = await api("POST", "/api/school/" + currentSchool.id + "/test-endtime", {
    ...getCurrentSchoolFormalTimeGuard(),
    action: "save",
    test_trigger_time: testTriggerTime,
    test_endtime: testEndtime,
    test_reserve_day_offset: parseTestReserveDayOffsetClient(dayInput ? dayInput.value : currentSchool.test_reserve_day_offset),
  });
  if (res.ok && res.school) {
    currentSchool = res.school;
    schools = upsertSchoolInOrderedList(schools, res.school);
    if (!options.silent) toast("测试时间已保存");
    return true;
  }
  if (!options.silent) toast(res.error || "测试时间保存失败", "error");
  return false;
}

async function startTestEndtimeOverride() {
  if (!currentSchool) return;
  const triggerInput = document.getElementById("school_test_trigger_time");
  const endtimeInput = document.getElementById("school_test_endtime");
  const dayInput = document.querySelector("input[name='school_test_reserve_day']:checked");
  const testTriggerTime = (triggerInput && triggerInput.value || "").trim();
  if (parseClientTriggerSeconds(testTriggerTime) === null) {
    return toast("测试开始时间格式应为 HH:MM", "error");
  }
  const testEndtime = normalizeClientEndtimeInput(endtimeInput && endtimeInput.value);
  if (!testEndtime) {
    return toast("测试截止时间格式应为 HH:MM:SS", "error");
  }
  const sameTimeWindowError = validateTestTimeWindowAgainstFormalClient(testTriggerTime, testEndtime);
  if (sameTimeWindowError) return toast(sameTimeWindowError, "error");

  const saved = await persistTestEndtimeDefaults({ silent: true });
  if (!saved) return;

  const res = await api("POST", "/api/school/" + currentSchool.id + "/test-endtime", {
    ...getCurrentSchoolFormalTimeGuard(),
    test_trigger_time: testTriggerTime,
    test_endtime: testEndtime,
    test_reserve_day_offset: parseTestReserveDayOffsetClient(dayInput ? dayInput.value : currentSchool.test_reserve_day_offset),
  });
  if (res.ok && res.school) {
    currentSchool = res.school;
    schools = upsertSchoolInOrderedList(schools, res.school);
    render();
    toast("测试覆盖已开启，3 分钟后自动关闭");
  } else {
    toast(res.error || "测试覆盖启动失败", "error");
  }
}

async function stopTestEndtimeOverride() {
  if (!currentSchool) return;
  const res = await api("POST", "/api/school/" + currentSchool.id + "/test-endtime", {
    ...getCurrentSchoolFormalTimeGuard(),
    action: "stop",
  });
  if (res.ok && res.school) {
    currentSchool = res.school;
    schools = upsertSchoolInOrderedList(schools, res.school);
    render();
    toast("测试覆盖已关闭");
  } else {
    toast(res.error || "测试覆盖关闭失败", "error");
  }
}

function showAddUser(prefill = null, options = {}) {
  userModalReturnConflictGroupKey = options.returnConflictGroupKey || "";
  clearPlanMappingAfterUserSave = options.clearPlanMappingAfterSave === true;
  setUserSavePending(false);
  setUserMigratePending(false);
  document.getElementById("userModalTitle").textContent = "添加用户";
  document.getElementById("edit_user_id").value = "";
  document.getElementById("user_migrate_tools").style.display = "none";
  document.getElementById("migrate_user_target_group").value = "";
  document.getElementById("edit_user_phone").value = "";
  document.getElementById("edit_user_username").value = "";
  document.getElementById("edit_user_password").value = "";
  document.getElementById("edit_user_password").dataset.originalPasswordPlain = "";
  setEditUserPasswordVisible(false);
  document.getElementById("edit_user_remark").value = "";
  document.getElementById("edit_user_sign_feature_visible").checked = false;
  document.getElementById("edit_user_auto_sign_enabled").checked = false;
  toggleAutoSignFields();
  document.getElementById("edit_user_renewal_expires_on").value = "";
  document.getElementById("edit_user_purchase_channel").value = "";
  document.getElementById("edit_user_renewal_started_on").textContent = "未设置";
  document.getElementById("edit_user_renewal_used").textContent = "0 天";
  document.getElementById("edit_user_renewal_remaining").textContent = "未设置结束日期";
  document.getElementById("edit_user_renewal_fields").style.display = "none";
  document.getElementById("toggle_user_renewal").textContent = "查看/修改续费记录";
  fillUserTopConfigForm(false, {});
  resetUserGlobalSyncInputs();
  document.getElementById("user_global_time_tools").style.display = "none";
  const days = ["Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday"];
  days.forEach(d => {
    document.getElementById("sch_" + d + "_enabled").checked = false;
    setVisibleSlotsForDay(d, 1);
    [0,1,2,3].forEach(i => {
      document.getElementById("sch_" + d + "_s" + i + "_roomid").value = "";
      document.getElementById("sch_" + d + "_s" + i + "_seatid").value = "";
      document.getElementById("sch_" + d + "_s" + i + "_times").value = "";
      document.getElementById("sch_" + d + "_s" + i + "_seatPageId").value = "";
      document.getElementById("sch_" + d + "_s" + i + "_fidEnc").value = "";
    });
  });
  setScheduleText("");
  if (prefill && typeof prefill === "object") {
    document.getElementById("edit_user_phone").value = prefill.phone || "";
    document.getElementById("edit_user_username").value = prefill.username || "";
    document.getElementById("edit_user_password").value = prefill.password || "";
    document.getElementById("edit_user_remark").value = prefill.remark || "";
    document.getElementById("edit_user_sign_feature_visible").checked = prefill.sign_feature_visible === true;
    document.getElementById("edit_user_auto_sign_enabled").checked = prefill.sign_feature_visible === true && prefill.auto_sign_enabled === true;
    toggleAutoSignFields();
    if (prefill.schedule) {
      fillScheduleFormFromSchedule(prefill.schedule);
    }
    if (prefill.scheduleJsonText) {
      setScheduleText(prefill.scheduleJsonText);
      if (!prefill.schedule) {
        fillScheduleFormFromSchedule(parseScheduleJsonMapping(prefill.scheduleJsonText));
      }
    }
  }
  renewalCardTouched = false;
  showModal("userModal");
}

function showAddConflictGroupUser() {
  const schoolId = document.getElementById("conflict_group_add_school_id")?.value.trim();
  const school = currentConflictGroupSchools.find(item => String(item.id) === schoolId);
  if (!school) return toast("请输入当前冲突组内有效的学校 ID", "error");
  currentSchool = school;
  showAddUser(null, { returnConflictGroupKey: currentConflictGroupKey });
}

async function showEditUser(userId, schoolId = "") {
  const returnGroupKey = currentView === "conflict-group" ? currentConflictGroupKey : "";
  if (schoolId) {
    const school = currentConflictGroupSchools.find(item => String(item.id) === String(schoolId))
      || schools.find(item => String(item.id) === String(schoolId));
    if (!school) return toast("未找到用户所属学校", "error");
    currentSchool = school;
  }
  if (!currentSchool?.id) return toast("未找到用户所属学校", "error");
  userModalReturnConflictGroupKey = returnGroupKey;
  setUserSavePending(false);
  setUserMigratePending(false);
  const res = await api("GET", "/api/school/" + currentSchool.id + "/user/" + userId);
  if (res.error) return toast(res.error, "error");
  const u = res.user;
  document.getElementById("userModalTitle").textContent = "编辑用户";
  document.getElementById("edit_user_id").value = u.id;
  document.getElementById("user_migrate_tools").style.display = "";
  document.getElementById("migrate_user_target_group").value = "";
  document.getElementById("edit_user_phone").value = u.phone || "";
  document.getElementById("edit_user_username").value = u.username || "";
  document.getElementById("edit_user_password").value = "";
  document.getElementById("edit_user_password").placeholder = u.hasPassword ? "留空表示不修改密码" : "未配置密码";
  document.getElementById("edit_user_password").dataset.originalPasswordPlain = "";
  setEditUserPasswordVisible(false);
  document.getElementById("edit_user_remark").value = u.remark || "";
  document.getElementById("edit_user_sign_feature_visible").checked = u.sign_feature_visible === true;
  document.getElementById("edit_user_auto_sign_enabled").checked = u.sign_feature_visible === true && u.auto_sign_enabled === true;
  toggleAutoSignFields();
  document.getElementById("edit_user_renewal_expires_on").value = "";
  document.getElementById("edit_user_purchase_channel").value = "";
  document.getElementById("edit_user_renewal_started_on").textContent = "未设置";
  document.getElementById("edit_user_renewal_used").textContent = "0 天";
  document.getElementById("edit_user_renewal_remaining").textContent = "未设置结束日期";
  document.getElementById("edit_user_renewal_fields").style.display = "none";
  document.getElementById("toggle_user_renewal").textContent = "查看/修改续费记录";
  fillUserTopConfigForm(u.user_top_config_enabled, u.user_top_config || {});
  fillScheduleFormFromSchedule(u.schedule || {});
  setScheduleText(scheduleToStandardText(u.schedule || {}));
  resetUserGlobalSyncInputs();
  document.getElementById("user_global_time_tools").style.display = "";
  renewalCardTouched = false;
  showModal("userModal");
}

function markRenewalCardTouched() {
  renewalCardTouched = true;
}

function updateRenewalRemaining() {
  const value = document.getElementById("edit_user_renewal_expires_on").value;
  const output = document.getElementById("edit_user_renewal_remaining");
  if (!value) {
    output.textContent = "未设置结束日期";
    return;
  }
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const expires = new Date(value + "T00:00:00");
  const days = Math.round((expires - today) / 86400000);
  output.textContent = days >= 0 ? days + " 天后过期" : "已过期 " + Math.abs(days) + " 天";
}

function renderRenewalDetails(profile = null) {
  const renewal = profile || {};
  document.getElementById("edit_user_renewal_started_on").textContent = renewal.cycleStartedOn || "未设置";
  document.getElementById("edit_user_renewal_used").textContent = Number(renewal.activeDays ?? renewal.usedDays ?? 0) + " 天";
  document.getElementById("edit_user_renewal_expires_on").value = renewal.expiresOn || "";
  document.getElementById("edit_user_purchase_channel").value = renewal.purchaseChannel || "";
  updateRenewalRemaining();
}

async function toggleRenewalCard() {
  const fields = document.getElementById("edit_user_renewal_fields");
  const button = document.getElementById("toggle_user_renewal");
  if (fields.style.display !== "none") {
    fields.style.display = "none";
    button.textContent = "查看/修改续费记录";
    return;
  }

  const userId = document.getElementById("edit_user_id").value;
  if (userId) {
    button.disabled = true;
    button.textContent = "读取中...";
    try {
      const result = await api("GET", "/api/school/" + currentSchool.id + "/user/" + userId + "/renewal");
      if (result.error) {
        button.textContent = "查看/修改续费记录";
        return toast(result.error, "error");
      }
      renderRenewalDetails(result.renewal);
    } finally {
      button.disabled = false;
    }
  }
  renewalCardTouched = false;
  fields.style.display = "";
  button.textContent = "收起续费记录";
}

function extendRenewalDate(months) {
  const input = document.getElementById("edit_user_renewal_expires_on");
  const current = input.value ? new Date(input.value + "T00:00:00") : new Date();
  const day = current.getDate();
  current.setDate(1);
  current.setMonth(current.getMonth() + months);
  current.setDate(Math.min(day, new Date(current.getFullYear(), current.getMonth() + 1, 0).getDate()));
  input.value = [
    current.getFullYear(),
    String(current.getMonth() + 1).padStart(2, "0"),
    String(current.getDate()).padStart(2, "0"),
  ].join("-");
  updateRenewalRemaining();
  markRenewalCardTouched();
}

async function doSaveUser() {
  if (isSavingUser) return;
  const userId = document.getElementById("edit_user_id").value;
  const phone = document.getElementById("edit_user_phone").value.trim();
  const username = document.getElementById("edit_user_username").value.trim();
  const passwordInput = document.getElementById("edit_user_password");
  const password = passwordInput.value;
  const originalPassword = passwordInput.dataset.originalPasswordPlain || "";
  const remark = document.getElementById("edit_user_remark").value.trim();
  if (!phone) return toast("请填写手机号（登录账号）", "error");
  if (!userId && !password) return toast("新增用户必须填写密码", "error");
  const schedule = buildScheduleFromForm();

  let userTopConfig;
  try {
    userTopConfig = buildUserTopConfigFromForm();
  } catch (error) {
    return toast(error.message || String(error), "error");
  }
  if (document.getElementById("edit_user_top_config_enabled").checked
      && userTopConfig.endtime
      && !confirmFormalEndtimeUnder40(userTopConfig.endtime)) return;
  const body = {
    phone,
    username,
    remark,
    sign_feature_visible: document.getElementById("edit_user_sign_feature_visible").checked,
    auto_sign_enabled: document.getElementById("edit_user_auto_sign_enabled").checked,
    schedule,
    user_top_config_enabled: document.getElementById("edit_user_top_config_enabled").checked,
    user_top_config: userTopConfig,
  };
  if (renewalCardTouched) {
    body.renewalExpiresOn = document.getElementById("edit_user_renewal_expires_on").value;
    body.purchaseChannel = document.getElementById("edit_user_purchase_channel").value;
  }
  if (!userId || (password && password !== originalPassword)) body.password = password;
  setUserSavePending(true);
  try {
    const targetSchoolId = currentSchool.id;
    const returnGroupKey = userModalReturnConflictGroupKey;
    let res;
    if (userId) {
      res = await api("PUT", "/api/school/" + currentSchool.id + "/user/" + userId, body);
    } else {
      res = await api("POST", "/api/school/" + currentSchool.id + "/user", body);
    }
    if (res.ok) {
      if (!userId && clearPlanMappingAfterUserSave) {
        clearPlanMappingDraft();
        clearPlanMappingAfterUserSave = false;
      }
      toast("用户已保存");
      closeModal("userModal");
      invalidateConflictGroupUsersCache();
      if (returnGroupKey) {
        await openConflictGroup(returnGroupKey);
      } else {
        await openSchool(targetSchoolId);
      }
      if (res.pageTokenCheck && !res.pageTokenCheck.ok) {
        showUnitBindingWarning(res.warning || res.pageTokenCheck.error || "真实选座接口不可用");
      }
    } else {
      toast(res.error || "保存失败", "error");
    }
  } finally {
    setUserSavePending(false);
  }
}

async function migrateCurrentUser() {
  if (isMigratingUser) return;
  const userId = document.getElementById("edit_user_id").value;
  const targetSchoolId = document.getElementById("migrate_user_target_group").value.trim();
  if (!userId) return toast("请先打开已有用户", "error");
  if (!targetSchoolId) return toast("请填写目标组 ID", "error");
  if (targetSchoolId === currentSchool.id) return toast("目标组不能和当前组相同", "error");
  if (!confirm("确定将此用户迁移到组 " + targetSchoolId + "？")) return;

  setUserMigratePending(true);
  try {
    const sourceSchoolId = currentSchool.id;
    const returnGroupKey = userModalReturnConflictGroupKey;
    const res = await api("POST", "/api/school/" + sourceSchoolId + "/user/" + userId + "/migrate", {
      target_school_id: targetSchoolId,
    });
    if (res.ok) {
      toast("用户已迁移");
      closeModal("userModal");
      invalidateConflictGroupUsersCache();
      if (returnGroupKey) {
        openConflictGroup(returnGroupKey);
      } else {
        openSchool(sourceSchoolId);
      }
    } else {
      toast(res.error || "迁移失败", "error");
    }
  } finally {
    setUserMigratePending(false);
  }
}

async function pauseUser(userId, schoolId = "") {
  const targetSchoolId = schoolId || currentSchool?.id;
  if (!targetSchoolId) return;
  const res = await api("POST", "/api/school/" + targetSchoolId + "/user/" + userId + "/pause");
  if (!res.ok) return toast(res.error || "暂停失败", "error");
  invalidateConflictGroupUsersCache();
  toast("用户已暂停");
  refreshCurrentUserView(targetSchoolId);
}

function updatePauseDaysButton(userId, value) {
  const button = document.getElementById("pause_days_button_" + userId);
  if (!button) return;
  const days = Number(value);
  button.textContent = Number.isInteger(days) && days >= 1 && days <= 365
    ? "暂停" + days + "天"
    : "暂停N天";
}

async function pauseUserForDays(userId, schoolId = "", domKey = "") {
  const targetSchoolId = schoolId || currentSchool?.id;
  if (!targetSchoolId) return;
  const days = Number(document.getElementById("pause_days_" + (domKey || userId))?.value);
  if (!Number.isInteger(days) || days < 1 || days > 365) {
    return toast("暂停天数必须是 1 到 365 的整数", "error");
  }
  const res = await api(
    "POST",
    "/api/school/" + targetSchoolId + "/user/" + userId + "/pause",
    { days },
  );
  if (!res.ok) return toast(res.error || "暂停失败", "error");
  invalidateConflictGroupUsersCache();
  toast("用户已暂停 " + days + " 天");
  refreshCurrentUserView(targetSchoolId);
}

async function resumeUser(userId, schoolId = "") {
  const targetSchoolId = schoolId || currentSchool?.id;
  if (!targetSchoolId) return;
  const res = await api("POST", "/api/school/" + targetSchoolId + "/user/" + userId + "/resume");
  if (!res.ok) return toast(res.error || "恢复失败", "error");
  invalidateConflictGroupUsersCache();
  toast("用户已恢复");
  refreshCurrentUserView(targetSchoolId);
}

async function bulkSetUsersStatus(status) {
  if (!currentSchool) return;
  const isActive = status === "active";
  const actionText = isActive ? "启动" : "暂停";
  if (!confirm("确定一键" + actionText + "当前组所有用户？")) return;

  const res = await api("POST", "/api/school/" + currentSchool.id + "/users/status", { status });
  if (res.ok) {
    invalidateConflictGroupUsersCache();
    toast(
      "已" + actionText + " " + (res.updated || 0) + " 名用户"
      + "，无需变更 " + (res.unchanged || 0) + " 名"
    );
    openSchool(currentSchool.id);
  } else {
    toast(res.error || ("一键" + actionText + "失败"), "error");
  }
}

async function disableAllUserTopConfigs() {
  if (!currentSchool) return;
  if (!confirm("确定关闭并清空当前学校所有用户的个性化顶级参数？学校默认参数不会改变。")) return;

  const res = await api("POST", "/api/school/" + currentSchool.id + "/users/top-config/disable");
  if (!res.ok) return toast(res.error || "批量关闭失败", "error");
  toast("已关闭 " + (res.updated || 0) + " 名用户的个性化参数，无需变更 " + (res.unchanged || 0) + " 名");
  openSchool(currentSchool.id);
}

async function bulkSetConflictGroupUsersStatus(status) {
  if (!currentConflictGroupSchools.length) return;
  const isActive = status === "active";
  const actionText = isActive ? "启动" : "暂停";
  if (!confirm("确定一键" + actionText + "整个冲突组的所有用户？")) return;

  const groupKey = currentConflictGroupKey;
  const results = await Promise.all(currentConflictGroupSchools.map(async school => ({
    school,
    response: await api("POST", "/api/school/" + school.id + "/users/status", { status }),
  })));
  const failed = results.filter(item => !item.response.ok);
  const updated = results.reduce((sum, item) => sum + Number(item.response.updated || 0), 0);
  const unchanged = results.reduce((sum, item) => sum + Number(item.response.unchanged || 0), 0);
  if (failed.length) {
    toast(
      "已" + actionText + " " + updated + " 名用户，但有 " + failed.length + " 个学校处理失败",
      "error",
    );
  } else {
    toast("已" + actionText + " " + updated + " 名用户，无需变更 " + unchanged + " 名");
  }
  invalidateConflictGroupUsersCache();
  openConflictGroup(groupKey);
}

async function triggerUser(userId, schoolId = "") {
  const targetSchoolId = schoolId || currentSchool?.id;
  if (!targetSchoolId) return;
  try {
    const res = await api("POST", "/api/trigger/" + targetSchoolId + "/" + userId);
    if (res.ok) {
      toast("已触发");
      return;
    }
    const detailText = typeof res.detail === "string" ? res.detail.slice(0, 120) : "";
    const msg = [
      res.error || "触发失败",
      res.status ? ("status=" + res.status) : "",
      detailText,
    ].filter(Boolean).join(" | ");
    toast(msg, "error");
  } catch (e) {
    toast("触发异常: " + (e.message || String(e)), "error");
  }
}

async function deleteUser(userId, schoolId = "") {
  const targetSchoolId = schoolId || currentSchool?.id;
  if (!targetSchoolId) return;
  if (!confirm("确定删除此用户？")) return;
  const res = await api("DELETE", "/api/school/" + targetSchoolId + "/user/" + userId);
  if (!res.ok) return toast(res.error || "删除失败", "error");
  invalidateConflictGroupUsersCache();
  toast("用户已删除");
  refreshCurrentUserView(targetSchoolId);
}

// 初始化
setInterval(updateTestEndtimeStatusView, 1000);

(async function init() {
  try {
    if (API_KEY) {
      const res = await api("GET", "/api/schools");
      if (!res.error) {
        schools = getSortedSchoolsForDisplay(res.schools || []);
        currentView = "schools";
      }
    }
    render();
    refreshSchoolActiveTodayCounts();
  } catch (e) {
    console.error("init failed:", e);
    renderFatalError(e, "init");
  }
})();

window.addEventListener("error", (event) => {
  renderFatalError(event.error || event.message || "Unknown error", "window.error");
});

window.addEventListener("unhandledrejection", (event) => {
  renderFatalError(event.reason || "Unhandled promise rejection", "unhandledrejection");
});
</script>
</body>
</html>`;

export {
  buildFallbackTriggerKey,
  buildChaoxingSeatPageUrl,
  didLoginAccountChange,
  extractPageToken,
  formatSeatConfigNote,
  formalTriggerScope,
  normalizeSchoolNotes,
  resolveSeatApiFamily,
  resolveUserTopModeForSchool,
  cloudflareServerFetchUrl,
  validateFormalTimeWindow,
  validateChaoxingSeatPage,
};

export default {
  async scheduled(event, env, ctx) {
    const resumeTask = resumeExpiredPausedUsers(env).catch(error => {
      console.error("Auto-resume paused users failed:", error?.message || String(error));
    });
    if (event.cron === EMERGENCY_STAGE_CRON) {
      // Emergency snapshot staging has its own cadence and must not update the
      // primary heartbeat observed by worker2.
      ctx.waitUntil(Promise.all([resumeTask, handleEmergencySnapshotScheduled(env)]));
      return;
    }
    ctx.waitUntil(writeHeartbeatTimestamp(env.SEAT_KV));
    ctx.waitUntil(cleanupYesterdayHeartbeatAndFallbackRecords(env.SEAT_KV));
    ctx.waitUntil(resumeTask.then(() => handleScheduled(env)));
  },
  async fetch(request, env, ctx) {
    try {
      return await handleFetch(request, env, ctx);
    } catch (error) {
      const requestId = crypto.randomUUID();
      console.error(`Unhandled Worker request error [${requestId}]`, error);
      return jsonResp({
        ok: false,
        error: "Worker request failed",
        detail: error?.message || String(error),
        requestId,
      }, 500);
    }
  },
};

export {
  pauseUntilFromDays,
  resumeExpiredPausedUsers,
  syncSignSettings,
  syncUserDeleteToServer,
  syncUserToServer,
};
