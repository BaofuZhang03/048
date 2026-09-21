#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", default="sign/current_reservations.sqlite3")
    parser.add_argument("--days", type=int, default=3)
    args = parser.parse_args()
    cutoff = (datetime.now(ZoneInfo("Asia/Shanghai")) - timedelta(days=args.days)).isoformat()
    conn = sqlite3.connect(Path(args.db))
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        """
        SELECT u.school_id, u.user_id, u.account, u.remark, u.user_status,
               COUNT(t.id) AS task_count,
               SUM(CASE WHEN t.status = 'completed' THEN 1 ELSE 0 END) AS completed_count,
               SUM(CASE WHEN t.status = 'cancelled' THEN 1 ELSE 0 END) AS cancelled_count,
               SUM(CASE WHEN t.status = 'failed' THEN 1 ELSE 0 END) AS failed_count,
               MAX(t.due_at) AS latest_due_at,
               CASE
                 WHEN COALESCE(uf.visible_override, '') = 'show' THEN 1
                 WHEN COALESCE(uf.visible_override, '') = 'hide' THEN 0
                 ELSE COALESCE(sf.visible, 0)
               END AS feature_visible,
               COALESCE(uf.visible_override, '') AS feature_override,
               COALESCE(uc.auto_enabled, 0) AS auto_enabled,
               COALESCE(uc.updated_at, '') AS auto_updated_at,
               COALESCE((
                 SELECT a.source FROM sign_control_audit_log a
                 WHERE a.user_id = u.user_id AND a.setting IN ('auto_enabled', 'feature_visible')
                 ORDER BY a.id DESC LIMIT 1
               ), '') AS latest_change_source,
               COALESCE((
                 SELECT a.changed_at FROM sign_control_audit_log a
                 WHERE a.user_id = u.user_id AND a.setting IN ('auto_enabled', 'feature_visible')
                 ORDER BY a.id DESC LIMIT 1
               ), '') AS latest_change_at
        FROM scheduled_sign_requests t
        JOIN source_users u ON u.user_id = t.user_id AND u.school_id = t.school_id
        LEFT JOIN user_collection_settings uc ON uc.user_id = u.user_id
        LEFT JOIN user_sign_feature_settings uf ON uf.user_id = u.user_id
        LEFT JOIN school_sign_feature_settings sf ON sf.school_id = u.school_id
        WHERE t.due_at >= ?
        GROUP BY u.user_id
        HAVING auto_enabled = 0 OR feature_visible = 0
        ORDER BY latest_due_at DESC, u.school_id, u.account
        """,
        (cutoff,),
    ).fetchall()
    print(json.dumps({"cutoff": cutoff, "count": len(rows), "users": [dict(row) for row in rows]}, ensure_ascii=False))


if __name__ == "__main__":
    main()
