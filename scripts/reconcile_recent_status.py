#!/usr/bin/env python3
import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from server_store.repository import open_repo, now_beijing
from server_store.runtime import build_client, load_env_file


def parse_time(value):
    try:
        return datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
    except ValueError:
        return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--hours", type=int, default=24)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    cutoff = datetime.now(timezone(timedelta(hours=8))) - timedelta(hours=args.hours)
    load_env_file()
    kv = build_client()
    conn = open_repo()
    rows = conn.execute("SELECT school_id,user_id,username,status,sync_status,raw_json FROM users").fetchall()
    recent = []
    for row in rows:
        raw = json.loads(row["raw_json"] or "{}")
        changed = max(filter(None, (parse_time(raw.get("last_paused_at")), parse_time(raw.get("last_resumed_at")))), default=None)
        if changed and changed.astimezone(cutoff.tzinfo) >= cutoff:
            recent.append((row, changed))
    snapshots = {}
    differences = []
    for row, changed in recent:
        school_id, user_id = row["school_id"], row["user_id"]
        direct = kv.get_json(f"school:{school_id}:user:{user_id}") or {}
        if school_id not in snapshots:
            snapshots[school_id] = kv.get_json(f"school:{school_id}:users:full") or []
        snapshot = next((item for item in snapshots[school_id] if isinstance(item, dict) and str(item.get("id")) == user_id), {})
        if row["status"] != direct.get("status") or row["status"] != snapshot.get("status"):
            differences.append({"schoolId": school_id, "userId": user_id, "username": row["username"], "changedAt": changed.isoformat(), "local": row["status"], "directKV": direct.get("status"), "snapshotKV": snapshot.get("status"), "previousSyncStatus": row["sync_status"]})
    if args.apply:
        stamp = now_beijing()
        for item in differences:
            conn.execute("UPDATE users SET sync_status='pending',last_local_change_at=?,last_sync_error='' WHERE user_id=?", (stamp, item["userId"]))
        conn.commit()
    conn.close()
    print(json.dumps({"hours": args.hours, "checked": len(recent), "markedPending": len(differences) if args.apply else 0, "differences": differences}, ensure_ascii=False))


if __name__ == "__main__":
    main()
