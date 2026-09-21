#!/usr/bin/env python3
from __future__ import annotations

import argparse

from server_store.runtime import build_client, load_env_file


SCHOOL_ID = "083"
USER_ID = "__sync_probe_20260915__"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("seed", "cleanup"))
    args = parser.parse_args()
    load_env_file()
    kv = build_client()
    user_key = f"school:{SCHOOL_ID}:user:{USER_ID}"
    ids_key = f"school:{SCHOOL_ID}:users"
    full_key = f"school:{SCHOOL_ID}:users:full"
    user_ids = kv.get_json(ids_key) or []
    snapshot = kv.get_json(full_key) or []

    if args.action == "seed":
        if kv.get_json(user_key) is not None or USER_ID in user_ids or any(
            isinstance(row, dict) and str(row.get("id") or "") == USER_ID for row in snapshot
        ):
            raise SystemExit("probe user already exists; refusing to overwrite")
        user = {
            "id": USER_ID,
            "schoolId": SCHOOL_ID,
            "phone": "19900000083",
            "username": "sync-probe",
            "password": "probe-cipher",
            "remark": "KV→101临时同步测试",
            "status": "active",
            "schedule": {},
            "user_top_config_enabled": False,
            "user_top_config": {},
            "updatedAt": "2026-09-15T03:40:00.000Z",
        }
        kv.put_json(user_key, user)
        kv.put_json(ids_key, [*user_ids, USER_ID])
        kv.put_json(full_key, [*snapshot, user])
        print({"ok": True, "action": "seed", "userId": USER_ID})
        return

    kv.delete_key(user_key)
    kv.put_json(ids_key, [value for value in user_ids if str(value) != USER_ID])
    kv.put_json(full_key, [
        row for row in snapshot
        if not (isinstance(row, dict) and str(row.get("id") or "") == USER_ID)
    ])
    print({"ok": True, "action": "cleanup", "userId": USER_ID})


if __name__ == "__main__":
    main()
