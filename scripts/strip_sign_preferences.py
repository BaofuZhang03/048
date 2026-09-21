#!/usr/bin/env python3
from __future__ import annotations

import argparse
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from server_store.kv_sync_meta import put_school_sync_meta
from server_store.kv_write_lock import kv_write_lock
from server_store.repository import list_schools, open_repo
from server_store.runtime import build_client, load_env_file

SIGN_FIELDS = {"sign_feature_visible", "sign_feature_override", "auto_sign_enabled", "sign_control_version"}


def clean(value):
    return {key: item for key, item in value.items() if key not in SIGN_FIELDS}


def main() -> None:
    parser = argparse.ArgumentParser(description="Remove sign preferences from KV; keep the 101 mirror intact")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    load_env_file()
    conn = open_repo()
    kv = build_client()
    contaminated = 0
    try:
        for school in list_schools(conn):
            school_id = str(school.get("id") or "")
            user_ids = kv.get_json(f"school:{school_id}:users") or []
            snapshot = kv.get_json(f"school:{school_id}:users:full") or []
            next_snapshot = []
            school_changed = False
            for row in snapshot:
                if not isinstance(row, dict):
                    next_snapshot.append(row)
                    continue
                next_row = clean(row)
                changed = next_row != row
                contaminated += int(changed)
                school_changed = school_changed or changed
                next_snapshot.append(next_row)
                if args.apply and changed:
                    kv.put_json(f"school:{school_id}:user:{row.get('id')}", next_row)
            if args.apply and school_changed:
                with kv_write_lock():
                    kv.put_json(f"school:{school_id}:users:full", next_snapshot)
                    put_school_sync_meta(kv, school_id, user_ids, next_snapshot)
        print({"contaminated": contaminated, "apply": args.apply})
    finally:
        conn.close()


if __name__ == "__main__":
    main()
