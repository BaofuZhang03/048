#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import requests

from server_store.kv_write_lock import kv_write_lock
from server_store.db_write_lock import db_write_lock
from server_store.repository import (
    delete_user,
    get_school_snapshot,
    get_user,
    open_repo,
    replace_user,
)
from server_store.runtime import build_client, load_env_file
from server_store.schedule_mapping import user_for_kv
from server_store.sync_push import sync_pending


TZ = timezone(timedelta(hours=8))
DAYS = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")


def empty_schedule(marker: str) -> dict:
    return {day: {"enabled": False, "slots": [], "testMarker": marker} for day in DAYS}


def expected_user(run_id: str, index: int) -> dict:
    base = datetime(2099, 1, 1, 0, 0, 0, tzinfo=TZ) + timedelta(
        seconds=(int(run_id[-4:], 16) % 50000) * 3 + index * 3
    )
    v2 = (base + timedelta(seconds=2)).isoformat()
    return {
        "id": f"zz-consistency-{run_id}-{index:03d}",
        "schoolId": "100",
        "phone": f"199{int(run_id[-4:], 16) % 10000:04d}{index:04d}",
        "username": f"一致性测试-{index:03d}",
        "password": "TEST_ONLY_NOT_A_REAL_ACCOUNT",
        "remark": "AUTOMATED_CONSISTENCY_TEST",
        "status": "active" if index % 2 else "paused",
        "schedule": empty_schedule(f"final-{index}"),
        "user_top_config_enabled": True,
        "user_top_config": {"mode": "C", "testIndex": index},
        "status_version": v2,
        "schedule_version": v2,
        "account_version": v2,
        "config_version": v2,
        "sync_status": "pending",
        "last_local_change_at": v2,
        "updatedAt": v2,
    }


def relay(user: dict) -> None:
    base_url = os.environ["SIGN_CONTROL_BASE_URL"].rstrip("/")
    token = os.environ.get("SIGN_CONTROL_TOKEN") or os.environ["SERVER_DISPATCH_API_KEY"]
    response = requests.post(
        base_url + "/api/internal/user-sync",
        json={"schoolId": "100", "user": user},
        headers={"X-Tongyi-Key": token, "X-Sign-Control-Token": token},
        timeout=30,
    )
    response.raise_for_status()
    if not response.json().get("ok"):
        raise RuntimeError(response.text)


def write_one(run_id: str, index: int) -> None:
    final = expected_user(run_id, index)
    old = dict(final)
    old_version = (datetime.fromisoformat(final["updatedAt"]) - timedelta(seconds=1)).isoformat()
    old.update({
        "status": "paused" if final["status"] == "active" else "active",
        "schedule": empty_schedule(f"old-{index}"),
        "user_top_config": {"mode": "A", "testIndex": index},
        "status_version": old_version,
        "schedule_version": old_version,
        "config_version": old_version,
        "last_local_change_at": old_version,
        "updatedAt": old_version,
    })
    with db_write_lock():
        conn = open_repo()
        try:
            replace_user(conn, "100", old, mark_synced=False)
            conn.commit()
        finally:
            conn.close()
    relay(old)
    with db_write_lock():
        conn = open_repo()
        try:
            replace_user(conn, "100", final, mark_synced=False)
            conn.commit()
        finally:
            conn.close()
    relay(final)


def run_load(run_id: str, count: int) -> None:
    with ThreadPoolExecutor(max_workers=count) as pool:
        list(pool.map(lambda i: write_one(run_id, i), range(count)))
    result = sync_pending(limit=max(200, count * 2))
    if result["failed"]:
        raise RuntimeError(result)
    print({"phase": "run", "runId": run_id, "count": count, "sync": result})


def verify(run_id: str, count: int) -> None:
    kv = build_client()
    conn = open_repo()
    failures = []
    try:
        school = get_school_snapshot(conn, "100")
        snapshot = kv.get_json("school:100:users:full") or []
        by_id = {str(row.get("id") or ""): row for row in snapshot if isinstance(row, dict)}
        for index in range(count):
            expected = expected_user(run_id, index)
            user_id = expected["id"]
            local = get_user(conn, "100", user_id)
            remote = kv.get_json(f"school:100:user:{user_id}")
            expected_kv = user_for_kv(school, expected)
            for label, actual in (("101", local), ("kv", remote), ("snapshot", by_id.get(user_id))):
                if not isinstance(actual, dict):
                    failures.append((user_id, label, "missing"))
                    continue
                for field in ("phone", "status", "schedule", "user_top_config", "updatedAt"):
                    wanted = expected[field] if label == "101" else expected_kv[field]
                    if actual.get(field) != wanted:
                        failures.append((user_id, label, field))
    finally:
        conn.close()
    if failures:
        raise RuntimeError(f"consistency failures={len(failures)} sample={failures[:20]}")
    print({"phase": "verify", "runId": run_id, "count": count, "failures": 0})


def cleanup(run_id: str, count: int) -> None:
    kv = build_client()
    ids = {expected_user(run_id, index)["id"] for index in range(count)}
    token = os.environ.get("SIGN_CONTROL_TOKEN") or os.environ["SERVER_DISPATCH_API_KEY"]
    base_url = os.environ["SIGN_CONTROL_BASE_URL"].rstrip("/")
    for user_id in ids:
        requests.post(
            base_url + "/api/internal/user-delete",
            json={"schoolId": "100", "userId": user_id},
            headers={"X-Tongyi-Key": token},
            timeout=30,
        ).raise_for_status()
    with kv_write_lock():
        for user_id in ids:
            kv.delete_key(f"school:100:user:{user_id}")
        user_ids = kv.get_json("school:100:users") or []
        kv.put_json("school:100:users", [value for value in user_ids if str(value) not in ids])
        snapshot = kv.get_json("school:100:users:full") or []
        kv.put_json("school:100:users:full", [row for row in snapshot if str((row or {}).get("id") or "") not in ids])
        paused = kv.get_json("meta:paused_users") or []
        kv.put_json("meta:paused_users", [row for row in paused if str((row or {}).get("userId") or "") not in ids])
    conn = open_repo()
    try:
        for user_id in ids:
            delete_user(conn, "100", user_id)
        conn.commit()
    finally:
        conn.close()
    print({"phase": "cleanup", "runId": run_id, "count": count})


def main() -> None:
    load_env_file()
    parser = argparse.ArgumentParser()
    parser.add_argument("phase", choices=("run", "verify", "cleanup"))
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--count", type=int, default=100)
    args = parser.parse_args()
    {"run": run_load, "verify": verify, "cleanup": cleanup}[args.phase](args.run_id, args.count)


if __name__ == "__main__":
    main()
