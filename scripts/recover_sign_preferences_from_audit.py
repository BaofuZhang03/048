#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sqlite3
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo


def main() -> None:
    parser = argparse.ArgumentParser(description="Recover sign preferences overwritten by source sync")
    parser.add_argument("--db", type=Path, required=True)
    parser.add_argument("--since", required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    conn = sqlite3.connect(args.db)
    conn.row_factory = sqlite3.Row
    candidates = conn.execute(
        """
        SELECT a.*
        FROM sign_control_audit_log a
        WHERE a.id IN (
            SELECT MAX(id)
            FROM sign_control_audit_log
            WHERE changed_at >= ?
              AND source = 'source_sync'
              AND ((setting = 'auto_enabled' AND old_value = '1' AND new_value = '0')
                OR (setting = 'feature_visible' AND old_value = 'show' AND new_value = 'hide'))
            GROUP BY school_id, user_id, setting
        )
          AND NOT EXISTS (
              SELECT 1 FROM sign_control_audit_log later
              WHERE later.school_id = a.school_id
                AND later.user_id = a.user_id
                AND later.setting = a.setting
                AND later.id > a.id
                AND later.source NOT LIKE 'source_%'
          )
        ORDER BY a.id
        """,
        (args.since,),
    ).fetchall()
    print({"candidates": len(candidates), "apply": args.apply})
    if not args.apply:
        conn.close()
        return

    backup_path = args.db.with_name(
        f"{args.db.name}.before-sign-recovery-{datetime.now().strftime('%Y%m%d-%H%M%S')}.bak"
    )
    backup = sqlite3.connect(backup_path)
    conn.backup(backup)
    backup.close()

    changed_at = datetime.now(ZoneInfo("Asia/Shanghai")).isoformat()
    restored = 0
    conn.execute("BEGIN IMMEDIATE")
    for row in candidates:
        if row["setting"] == "auto_enabled":
            current = conn.execute(
                "SELECT auto_enabled FROM user_collection_settings WHERE user_id = ?",
                (row["user_id"],),
            ).fetchone()
            if not current or int(current["auto_enabled"] or 0) != 0:
                continue
            conn.execute(
                "UPDATE user_collection_settings SET auto_enabled = 1, updated_at = ? WHERE user_id = ?",
                (changed_at, row["user_id"]),
            )
        else:
            current = conn.execute(
                "SELECT visible_override FROM user_sign_feature_settings WHERE user_id = ?",
                (row["user_id"],),
            ).fetchone()
            if not current or current["visible_override"] != "hide":
                continue
            conn.execute(
                "UPDATE user_sign_feature_settings SET visible_override = 'show', updated_at = ? WHERE user_id = ?",
                (changed_at, row["user_id"]),
            )
        conn.execute(
            """
            INSERT INTO sign_control_audit_log (
                sign_server_id, school_id, user_id, setting,
                old_value, new_value, source, changed_at
            ) VALUES (?, ?, ?, ?, ?, ?, 'audit_recovery', ?)
            """,
            (row["sign_server_id"], row["school_id"], row["user_id"], row["setting"],
             row["new_value"], row["old_value"], changed_at),
        )
        restored += 1
    conn.commit()
    conn.close()
    print({"restored": restored, "backup": str(backup_path)})


if __name__ == "__main__":
    main()
