#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sqlite3
from datetime import datetime
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    db_path = Path(args.db)
    conn = sqlite3.connect(db_path)
    deleted = "SELECT user_id FROM source_users WHERE user_status = 'deleted'"
    counts = {
        "auto_settings": conn.execute(f"SELECT COUNT(*) FROM user_collection_settings WHERE user_id IN ({deleted})").fetchone()[0],
        "feature_settings": conn.execute(f"SELECT COUNT(*) FROM user_sign_feature_settings WHERE user_id IN ({deleted})").fetchone()[0],
        "live_tasks": conn.execute(f"SELECT COUNT(*) FROM scheduled_sign_requests WHERE user_id IN ({deleted}) AND status IN ('pending','running')").fetchone()[0],
    }
    print({**counts, "apply": args.apply})
    if not args.apply:
        conn.close()
        return
    backup_path = db_path.with_name(f"{db_path.name}.before-deleted-user-cleanup-{datetime.now():%Y%m%d-%H%M%S}.bak")
    backup = sqlite3.connect(backup_path)
    conn.backup(backup)
    backup.close()
    now = datetime.now().astimezone().isoformat()
    conn.execute(f"UPDATE scheduled_sign_requests SET status='cancelled', updated_at=?, error_message='cancelled: user deleted' WHERE user_id IN ({deleted}) AND status IN ('pending','running')", (now,))
    conn.execute(f"DELETE FROM user_collection_settings WHERE user_id IN ({deleted})")
    conn.execute(f"DELETE FROM user_sign_feature_settings WHERE user_id IN ({deleted})")
    conn.commit()
    conn.close()
    print({"backup": str(backup_path), "cleaned": counts})


if __name__ == "__main__":
    main()
