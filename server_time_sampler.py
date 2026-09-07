#!/usr/bin/env python3
"""Observe Chaoxing room/info timing without affecting reservation timing."""

import argparse
import datetime as dt
import logging
import os
import random
import statistics
import time
from zoneinfo import ZoneInfo

from utils.reserve import reserve


BEIJING_TZ = ZoneInfo("Asia/Shanghai")
ENDPOINTS = {
    "seatengine": "https://office.chaoxing.com/data/apps/seatengine/room/info",
    "seat": "https://office.chaoxing.com/data/apps/seat/room/info",
}


def _format_ms(value):
    if value is None:
        return "-"
    return dt.datetime.fromtimestamp(value / 1000, BEIJING_TZ).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def _title(sample_type):
    return "抢座前时间采样" if sample_type == "pre_open" else "平时时间采样"


def _log_start(sample_type, target_at, success_target):
    logging.info(
        "================【%s开始】================\n\n"
        "程序目标时间：%s\n"
        "采样窗口：%s\n"
        "目标成功采样：%d 次（到截止时间不足 %d 次也直接结束）",
        _title(sample_type),
        target_at.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] if target_at else "-",
        "开放前约 2 分钟" if sample_type == "pre_open" else "平时低负载",
        success_target,
        success_target,
    )


def _percentile(values, percent):
    values = sorted(values)
    if not values:
        return None
    position = (len(values) - 1) * percent / 100
    lower = int(position)
    upper = min(lower + 1, len(values) - 1)
    fraction = position - lower
    return values[lower] + (values[upper] - values[lower]) * fraction


def _summary(sample_type, records, target_at=None):
    successes = [record for record in records if record["success"]]
    cold = [record for record in successes if record["connection_reused"] == "false"]
    reused = [record for record in successes if record["connection_reused"] in {"true", "likely_reused"}]
    unknown = [record for record in successes if record["connection_reused"] == "unknown"]
    official_open_ms = next(
        (record["before_open_timestamp"] for record in successes if record.get("before_open_timestamp") is not None),
        None,
    )

    def values(field):
        return [record[field] for record in reused if record.get(field) is not None]

    def p1090(field, signed=False):
        series = values(field)
        if not series:
            return "-"
        formatter = (lambda value: f"{value:+.2f}") if signed else (lambda value: f"{value:.2f}")
        return " / ".join(formatter(_percentile(series, p)) for p in (10, 50, 90)) + " ms"

    reused_rtts = values("rtt_ms")
    midpoint = values("midpoint_offset_ms")
    reused_median = statistics.median(reused_rtts) if reused_rtts else None
    anomalies = [record for record in reused if reused_median is not None and record["rtt_ms"] > reused_median * 1.5]

    logging.info(
        "================【%s汇总】================\n\n"
        "服务器官方开放时间：%s\n程序目标时间：%s\n\n"
        "总样本：%d\n冷连接：%d\n复用连接：%d\n未知连接：%d\n失败：%d\n\n"
        "【复用连接】\n请求往返耗时（第10/50/90百分位）：%s\n请求往返耗时最小/最大：%s\n\n"
        "服务器时间－本地发出（第10/50/90百分位）：%s\n"
        "本地收到－服务器时间（第10/50/90百分位）：%s\n\n"
        "中点偏差估计（第10/50/90百分位）：%s\n中点偏差估计稳定区间：%s\n\n"
        "异常延迟样本：%d\n采样结果用途：仅时间观测，不修改正式请求逻辑\n"
        "====================================================",
        _title(sample_type),
        _format_ms(official_open_ms),
        target_at.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] if target_at else "-",
        len(records),
        len(cold),
        len(reused),
        len(unknown),
        len(records) - len(successes),
        p1090("rtt_ms"),
        f"{min(reused_rtts):.2f} / {max(reused_rtts):.2f} ms" if reused_rtts else "-",
        p1090("server_minus_send_ms", signed=True),
        p1090("recv_minus_server_ms", signed=True),
        p1090("midpoint_offset_ms", signed=True),
        f"{_percentile(midpoint, 10):+.2f} ～ {_percentile(midpoint, 90):+.2f} ms" if midpoint else "-",
        len(anomalies),
    )


def sample_once(
    session, url, form, sample_type, index, success_target, successful_before=0,
    timeout=5.0, target_at=None, trace_owner=None, reused_rtts_before=None,
):
    local_send_ms = time.time_ns() // 1_000_000
    perf_start_ns = time.perf_counter_ns()
    status = None
    server_now_ms = before_open = None
    error = ""
    if trace_owner is not None:
        trace_owner._time_sample_request_trace = {}
    try:
        response = session.post(
            url,
            data=form,
            verify=False,
            timeout=timeout,
            headers={"X-CX-Trace-Kind": "time_sample"},
        )
        status = response.status_code
        payload = response.json()
        data = payload.get("data") if isinstance(payload, dict) else None
        server_now_ms = int(data["serverNow"])
        before_open = data.get("beforeOpenTimeStamp", payload.get("beforeOpenTimeStamp"))
        before_open = int(before_open) if before_open is not None else None
        success = response.ok and payload.get("success", True) is not False
    except Exception as exc:
        success = False
        error = f"{type(exc).__name__}: {exc}"
    local_recv_ms = time.time_ns() // 1_000_000
    rtt_ms = (time.perf_counter_ns() - perf_start_ns) / 1_000_000
    server_minus_send = server_now_ms - local_send_ms if server_now_ms is not None else None
    recv_minus_server = local_recv_ms - server_now_ms if server_now_ms is not None else None
    midpoint_offset = (
        server_now_ms - (local_send_ms + local_recv_ms) / 2
        if server_now_ms is not None
        else None
    )
    trace = getattr(trace_owner, "_time_sample_request_trace", {}) if trace_owner is not None else {}
    reused = trace.get("connection_reused")
    tcp_ms = trace.get("tcp_connect_seconds")
    ssl_ms = trace.get("ssl_handshake_seconds")
    if isinstance(reused, bool):
        connection_reused = str(reused).lower()
    elif all(isinstance(value, (int, float)) and value <= 0.001 for value in (tcp_ms, ssl_ms)):
        connection_reused = "likely_reused"
    else:
        connection_reused = "unknown"
    seconds_before_open = (
        (before_open - server_now_ms) / 1000
        if before_open is not None and server_now_ms is not None
        else None
    )
    baseline = list(reused_rtts_before or [])
    latency_anomaly = (
        success
        and connection_reused in {"true", "likely_reused"}
        and len(baseline) >= 3
        and rtt_ms > statistics.median(baseline) * 1.5
    )
    record = {
        "success": success,
        "local_send_ms": local_send_ms,
        "server_now_ms": server_now_ms,
        "local_recv_ms": local_recv_ms,
        "rtt_ms": rtt_ms,
        "server_minus_send_ms": server_minus_send,
        "recv_minus_server_ms": recv_minus_server,
        "midpoint_offset_ms": midpoint_offset,
        "connection_reused": connection_reused,
        "tcp_connect_ms": tcp_ms * 1000 if isinstance(tcp_ms, (int, float)) else None,
        "ssl_handshake_ms": ssl_ms * 1000 if isinstance(ssl_ms, (int, float)) else None,
        "before_open_timestamp": before_open,
        "latency_anomaly": latency_anomaly,
    }
    logging.info(
        "────────【采样请求 %02d｜成功 %02d/%02d】────────\n"
        "本地发出：%s\n服务器时间：%s\n本地收到：%s\n\n"
        "请求往返耗时：%.2f ms\n服务器时间－本地发出：%s ms\n"
        "本地收到－服务器时间：%s ms\n中点偏差估计：%s ms\n\n"
        "服务器官方开放时间：%s\n程序目标时间：%s\n服务器距官方开放：%s\n"
        "连接复用：%s\n延迟异常：%s\n\nHTTP 状态：%s\n接口状态：%s%s\n\n"
        "原始时间戳：\nlocal_send_ms=%d\nserver_now_ms=%s\nlocal_recv_ms=%d\n"
        "sample_type=%s\nsample_index=%d\nconnection_reused=%s\n"
        "tcp_connect_ms=%s\nssl_handshake_ms=%s\n"
        "http_status=%s\nsuccess=%s\n"
        "beforeOpenTimeStamp=%s\n"
        "────────────────────────────",
        index,
        successful_before + int(success),
        success_target,
        _format_ms(local_send_ms),
        _format_ms(server_now_ms),
        _format_ms(local_recv_ms),
        rtt_ms,
        f"{server_minus_send:+d}" if server_minus_send is not None else "-",
        recv_minus_server if recv_minus_server is not None else "-",
        f"{midpoint_offset:+.2f}" if midpoint_offset is not None else "-",
        _format_ms(before_open),
        target_at.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] if target_at else "-",
        f"{seconds_before_open:.3f} 秒" if seconds_before_open is not None else "-",
        connection_reused,
        "是" if latency_anomaly else "否",
        status if status is not None else "-",
        "成功" if success else "失败",
        f"\n失败原因：{error}" if error else "",
        local_send_ms,
        server_now_ms if server_now_ms is not None else "-",
        local_recv_ms,
        sample_type,
        index,
        connection_reused,
        f"{tcp_ms * 1000:.3f}" if isinstance(tcp_ms, (int, float)) else "-",
        f"{ssl_ms * 1000:.3f}" if isinstance(ssl_ms, (int, float)) else "-",
        status if status is not None else "-",
        str(success).lower(),
        before_open if before_open is not None else "-",
    )
    return record


def run_sampling(
    username,
    password,
    room_id,
    to_day,
    fid_enc,
    api_family,
    sample_type="normal",
    *,
    start_at=None,
    stop_at=None,
    count=12,
    interval_range=(0.7, 2.0),
    target_at=None,
):
    family = "seatengine" if str(api_family) in {"auto", "seatengine", "seatengine_code"} else "seat"
    if start_at is not None:
        delay = (start_at - dt.datetime.now(BEIJING_TZ)).total_seconds()
        if delay > 0:
            time.sleep(delay)
    if stop_at is not None and dt.datetime.now(BEIJING_TZ) >= stop_at:
        logging.info("[时间采样][%s] 已到采样截止时间，未启动", sample_type)
        return

    sampler = reserve()
    sampler._set_api_family(family)
    try:
        login_ok = sampler.bootstrap_login(username, password, attempts=1)
    except Exception as exc:
        logging.error("[时间采样][%s] 独立登录异常：%s: %s", sample_type, type(exc).__name__, exc)
        return
    if not login_ok:
        logging.error("[时间采样][%s] 独立登录失败，停止本轮采样", sample_type)
        return

    form = {"id": str(room_id), "toDay": str(to_day), "fidEnc": str(fid_enc or "")}
    records = []
    total = 0
    success_count = 0
    _log_start(sample_type, target_at, count)
    while success_count < count:
        remaining = (stop_at - dt.datetime.now(BEIJING_TZ)).total_seconds() if stop_at else None
        if remaining is not None and remaining <= 0:
            break
        total += 1
        record = sample_once(
            sampler.requests,
            ENDPOINTS[family],
            form,
            sample_type,
            total,
            count,
            success_count,
            timeout=max(0.1, min(1.0, remaining)) if remaining is not None else 5.0,
            target_at=target_at,
            trace_owner=sampler,
            reused_rtts_before=[
                item["rtt_ms"] for item in records
                if item["success"] and item["connection_reused"] in {"true", "likely_reused"}
            ],
        )
        records.append(record)
        success_count += int(record["success"])
        if success_count >= count:
            break
        delay = random.uniform(*interval_range)
        if stop_at is not None:
            delay = min(delay, max(0.0, (stop_at - dt.datetime.now(BEIJING_TZ)).total_seconds()))
        if delay > 0:
            time.sleep(delay)
    _summary(sample_type, records, target_at)


def main():
    parser = argparse.ArgumentParser(description="Chaoxing serverNow observation sampler")
    parser.add_argument("--username", default=os.getenv("CX_USERNAME", ""))
    parser.add_argument("--password", default=os.getenv("CX_PASSWORD", ""))
    parser.add_argument("--room-id", required=True)
    parser.add_argument("--to-day", required=True)
    parser.add_argument("--fid-enc", required=True)
    parser.add_argument("--api-family", choices=sorted(ENDPOINTS), default="seat")
    parser.add_argument("--sample-type", choices=("normal", "pre_open"), default="normal")
    parser.add_argument("--count", type=int, default=12)
    args = parser.parse_args()
    if not args.username or not args.password:
        parser.error("CX_USERNAME/CX_PASSWORD or --username/--password is required")
    run_sampling(
        args.username,
        args.password,
        args.room_id,
        args.to_day,
        args.fid_enc,
        args.api_family,
        args.sample_type,
        count=max(1, args.count),
    )


if __name__ == "__main__":
    main()
