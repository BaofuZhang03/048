#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import sqlite3
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import requests

PROJECT_ROOT = Path(__file__).resolve().parents[1]
import sys

sys.path.insert(0, str(PROJECT_ROOT))

from server_store.db import get_db_path
from server_store.repository import get_user, open_repo, replace_user, strip_user_local_state_for_kv
from server_store.runtime import load_env_file


def main() -> None:
    parser = argparse.ArgumentParser(description="Reconcile 62 sign preferences into the 101 source of truth")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    load_env_file()

    base_url = os.getenv("SIGN_CONTROL_BASE_URL", "").rstrip("/")
    token = os.getenv("SIGN_CONTROL_TOKEN", "") or os.getenv("SERVER_DISPATCH_API_KEY", "")
    if not base_url or not token:
        raise SystemExit("SIGN_CONTROL_BASE_URL and SIGN_CONTROL_TOKEN are required")
    response = requests.get(
        f"{base_url}/api/internal/sign-feature-dashboard",
        headers={"X-Sign-Control-Token": token, "X-Tongyi-Key": token},
        timeout=30,
    )
    response.raise_for_status()
    dashboard = response.json()
    if not dashboard.get("ok"):
        raise SystemExit(dashboard.get("error") or "sign dashboard failed")

    remote = {
        (str(school.get("schoolId") or ""), str(user.get("userId") or "")): user
        for school in dashboard.get("schools", [])
        for user in school.get("users", [])
    }
    conn = open_repo()
    changes = []
    backup_path = None
    try:
        if args.apply:
            db_path = get_db_path()
            backup_path = db_path.with_name(
                f"{db_path.name}.before-sign-reconcile-{datetime.now().strftime('%Y%m%d-%H%M%S')}.bak"
            )
            backup = sqlite3.connect(backup_path)
            conn.backup(backup)
            backup.close()
        for (school_id, user_id), sign_user in remote.items():
            user = get_user(conn, school_id, user_id)
            if not user:
                continue
            next_values = {
                "sign_feature_visible": sign_user.get("featureVisible") is True,
                "sign_feature_override": str(sign_user.get("userOverride") or ""),
                "auto_sign_enabled": sign_user.get("autoEnabled") is True,
            }
            before = {key: user.get(key) for key in next_values}
            if before == next_values:
                continue
            changes.append({"schoolId": school_id, "userId": user_id, "before": before, "after": next_values})
            if args.apply:
                now_iso = datetime.now(ZoneInfo("Asia/Shanghai")).isoformat()
                replace_user(
                    conn,
                    school_id,
                    {**user, **next_values, "sign_control_version": now_iso},
                    mark_synced=True,
                    synced_source=strip_user_local_state_for_kv(user),
                )
        if args.apply:
            conn.commit()
            print({"matched": len(remote), "changed": len(changes), "backup": str(backup_path)})
        else:
            conn.rollback()
            print({"matched": len(remote), "changed": len(changes), "apply": False})
    finally:
        conn.close()


if __name__ == "__main__":
    main()
