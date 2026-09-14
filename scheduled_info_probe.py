#!/usr/bin/env python3
"""Log in once, then probe a configured Chaoxing endpoint at scheduled times."""

from __future__ import annotations

import argparse
import datetime as dt
import getpass
import json
import time
from pathlib import Path
from zoneinfo import ZoneInfo

TZ = ZoneInfo("Asia/Shanghai")
ENDPOINTS = {
    "seatengine": "https://office.chaoxing.com/data/apps/seatengine/room/info",
    "seat": "https://office.chaoxing.com/data/apps/seat/room/info",
}
RISK_CONFIG_URL = "https://office.chaoxing.com/data/apps/seat/risk/check/config"


def parse_at(value: str, now: dt.datetime) -> dt.datetime:
    value = value.strip()
    try:
        parsed = dt.datetime.fromisoformat(value)
    except ValueError:
        parsed = dt.datetime.combine(now.date(), dt.time.fromisoformat(value), TZ)
        if parsed <= now:
            parsed += dt.timedelta(days=1)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=TZ)
    return parsed.astimezone(TZ)


def prompt(value: str | None, label: str, *, secret: bool = False) -> str:
    if value:
        return value
    return (getpass.getpass if secret else input)(f"{label}: ").strip()


def wait_until(target: dt.datetime) -> None:
    while True:
        remaining = (target - dt.datetime.now(TZ)).total_seconds()
        if remaining <= 0:
            return
        time.sleep(min(remaining, 1.0))


def write_status(path: Path | None, status: str, error: str = "") -> None:
    if path:
        path.write_text(json.dumps({
            "status": status,
            "error": error,
            "updatedAt": dt.datetime.now(TZ).isoformat(timespec="seconds"),
        }, ensure_ascii=False), encoding="utf-8")


def probe_once(session, url: str, form: dict, metadata: dict, scheduled_at: dt.datetime) -> dict:
    send_ns = time.time_ns()
    perf_ns = time.perf_counter_ns()
    result = {
        **metadata,
        "scheduledAt": scheduled_at.isoformat(timespec="milliseconds"),
        "localSendMs": send_ns // 1_000_000,
    }
    try:
        response = session.post(url, data=form, verify=False, timeout=5)
        payload = response.json()
        data = payload.get("data") if isinstance(payload, dict) else {}
        result.update(
            httpStatus=response.status_code,
            success=bool(response.ok and payload.get("success", True) is not False),
            serverNow=data.get("serverNow"),
            beforeOpenTimeStamp=data.get("beforeOpenTimeStamp", payload.get("beforeOpenTimeStamp")),
        )
    except Exception as exc:
        result.update(success=False, error=f"{type(exc).__name__}: {exc}")
    result["localRecvMs"] = time.time_ns() // 1_000_000
    result["rttMs"] = round((time.perf_counter_ns() - perf_ns) / 1_000_000, 3)
    if result.get("serverNow") is not None:
        result["serverMinusSendMs"] = int(result["serverNow"]) - result["localSendMs"]
        result["midpointOffsetMs"] = round(
            int(result["serverNow"]) - (result["localSendMs"] + result["localRecvMs"]) / 2,
            3,
        )
    return result


def probe_risk_config_once(session, form: dict, metadata: dict, scheduled_at: dt.datetime) -> dict:
    send_ns = time.time_ns()
    perf_ns = time.perf_counter_ns()
    result = {
        **metadata,
        "scheduledAt": scheduled_at.isoformat(timespec="milliseconds"),
        "localSendMs": send_ns // 1_000_000,
    }
    try:
        response = session.post(RISK_CONFIG_URL, data=form, verify=False, timeout=5)
        payload = response.json()
        data = payload.get("data") if isinstance(payload, dict) else {}
        if not isinstance(data, dict):
            data = {}
        result.update(
            httpStatus=response.status_code,
            success=bool(response.ok and isinstance(payload, dict) and payload.get("success") is True),
            riskCheckOpen=data.get("riskCheckOpen"),
            riskCheckAfterMilliSecond=data.get("riskCheckAfterMilliSecond"),
            riskCheckType=data.get("riskCheckType"),
            riskCheckBeforeMilliSecond=data.get("riskCheckBeforeMilliSecond"),
            response=payload,
        )
    except Exception as exc:
        result.update(success=False, error=f"{type(exc).__name__}: {exc}")
    result["localRecvMs"] = time.time_ns() // 1_000_000
    result["rttMs"] = round((time.perf_counter_ns() - perf_ns) / 1_000_000, 3)
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="定时探测超星接口")
    parser.add_argument("--test-type", choices=("info_timing", "risk_config"), default="info_timing")
    parser.add_argument("--username")
    parser.add_argument("--password", help="不建议写在命令行；省略后安全输入")
    parser.add_argument("--room-id")
    parser.add_argument("--school-id", default="")
    parser.add_argument("--seat-page-id", default="")
    parser.add_argument("--seat", default="")
    parser.add_argument("--reserve-time", default="", help="仅作为测试备注，例如 09:00-22:00")
    parser.add_argument("--day", help="room/info 的 toDay，默认明天，格式 YYYY-MM-DD")
    parser.add_argument("--fid-enc")
    parser.add_argument("--api-family", choices=sorted(ENDPOINTS), default="seatengine")
    parser.add_argument("--app-type", default="0")
    parser.add_argument("--app-id", default="41612")
    parser.add_argument("--at", action="append", help="可重复；HH:MM[:SS[.微秒]] 或 ISO 日期时间")
    parser.add_argument("--submit-at", help="可选；测试时刻或 last（最后一次 info 后真实提交一次）")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--status-file", type=Path)
    args = parser.parse_args()

    username = prompt(args.username, "学习通账号")
    password = prompt(args.password, "学习通密码", secret=True)
    room_id = prompt(args.room_id, "roomId") if args.test_type == "info_timing" else ""
    fid_enc = prompt(args.fid_enc, "fidEnc") if args.test_type == "info_timing" else ""
    seat = prompt(args.seat, "座位号（仅记录）") if args.test_type == "info_timing" else ""
    reserve_time = prompt(args.reserve_time, "座位时间段（仅记录）") if args.test_type == "info_timing" else ""
    at_values = args.at or prompt(None, "测试时间，多个用逗号分隔").split(",")
    now = dt.datetime.now(TZ)
    schedule = sorted(parse_at(value, now) for value in at_values if value.strip())
    if not schedule:
        parser.error("至少需要一个测试时间")
    submit_at = schedule[-1] if args.submit_at == "last" else (parse_at(args.submit_at, now) if args.submit_at else None)
    if args.test_type != "info_timing" and submit_at:
        parser.error("风险配置测试不支持提交预约")

    to_day = args.day or (now.date() + dt.timedelta(days=1)).isoformat()
    output = args.output or Path("logs") / f"info_probe_{now:%Y%m%d_%H%M%S}.jsonl"
    output.parent.mkdir(parents=True, exist_ok=True)

    login_at = schedule[0] - dt.timedelta(minutes=2)
    write_status(args.status_file, "waiting")
    print(f"任务已保存；将在 {login_at.isoformat(timespec='milliseconds')} 登录", flush=True)
    wait_until(login_at)
    write_status(args.status_file, "logging_in")

    from utils.reserve import reserve

    day_offset = max(0, (dt.date.fromisoformat(to_day) - now.date()).days)
    client = reserve(max_attempt=1, reserve_day_offset=day_offset)
    client._set_api_family(args.api_family)
    if not client.bootstrap_login(username, password, attempts=1):
        write_status(args.status_file, "failed", "登录失败")
        raise SystemExit("登录失败")

    form = {"id": room_id, "toDay": to_day, "fidEnc": fid_enc}
    metadata = {
        "type": "risk_config" if args.test_type == "risk_config" else "info",
        "source": "test_center",
        "apiFamily": args.api_family,
        "schoolId": args.school_id,
        "roomId": room_id,
        "seatPageId": args.seat_page_id,
        "seat": seat,
        "reserveTime": reserve_time,
        "toDay": to_day,
        "fidEnc": fid_enc,
        "appType": args.app_type if args.test_type == "risk_config" else "",
        "appId": args.app_id if args.test_type == "risk_config" else "",
    }
    target_name = RISK_CONFIG_URL if args.test_type == "risk_config" else ENDPOINTS[args.api_family]
    write_status(args.status_file, "running")
    print(f"已登录；计划 {len(schedule)} 次，仅请求 {target_name}；结果写入 {output}", flush=True)
    with output.open("a", encoding="utf-8", buffering=1) as stream:
        for scheduled_at in schedule:
            print(f"等待 {scheduled_at.isoformat(timespec='milliseconds')}")
            wait_until(scheduled_at)
            result = (
                probe_risk_config_once(
                    client.requests,
                    {"appType": args.app_type, "appId": args.app_id},
                    metadata,
                    scheduled_at,
                )
                if args.test_type == "risk_config"
                else probe_once(client.requests, ENDPOINTS[args.api_family], form, metadata, scheduled_at)
            )
            line = json.dumps(result, ensure_ascii=False)
            stream.write(line + "\n")
            print(line)
            if submit_at == scheduled_at:
                start_time, end_time = (part.strip() for part in reserve_time.split("-", 1))
                submit_result = {
                    **metadata,
                    "type": "submit",
                    "scheduledAt": scheduled_at.isoformat(timespec="milliseconds"),
                    "startedAt": dt.datetime.now(TZ).isoformat(timespec="milliseconds"),
                }
                try:
                    submit_result["success"] = bool(client.submit(
                        times=[start_time, end_time], roomid=room_id, seatid=[seat],
                        action=False, fidEnc=fid_enc,
                        seat_page_id=args.seat_page_id or room_id,
                    ))
                except Exception as exc:
                    submit_result.update(success=False, error=f"{type(exc).__name__}: {exc}")
                submit_result["finishedAt"] = dt.datetime.now(TZ).isoformat(timespec="milliseconds")
                submit_line = json.dumps(submit_result, ensure_ascii=False)
                stream.write(submit_line + "\n")
                print(submit_line)
    write_status(args.status_file, "completed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
