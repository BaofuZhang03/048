#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from server_store.runtime import load_env_file


ACCOUNTS = {
    "15063177339", "13860883746", "17638289671", "15515655206",
    "17809565008", "19937268677", "18736097779", "16638495733",
    "18569918468", "19555768112", "18530337872", "18337886613",
    "17836918015", "18937760285", "15239738667", "15515578539",
}
EXACT_TARGETS = {
    "15515655206": ("001", "29342177bdf7"),
    "17809565008": ("100", "3d060298eff2"),
    "19937268677": ("902", "daf7ce013a19"),
}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    load_env_file()
    base = os.environ["SIGN_CONTROL_BASE_URL"].rstrip("/")
    token = os.getenv("SIGN_CONTROL_TOKEN") or os.environ["SERVER_DISPATCH_API_KEY"]
    headers = {"X-Sign-Control-Token": token, "X-Tongyi-Key": token}
    dashboard = requests.get(
        f"{base}/api/internal/sign-feature-dashboard", headers=headers, timeout=30
    ).json()
    users = {
        str(user.get("account") or ""): (str(school.get("schoolId") or ""), str(user.get("userId") or ""))
        for school in dashboard.get("schools", [])
        for user in school.get("users", [])
        if str(user.get("account") or "") in ACCOUNTS
    }
    users.update(EXACT_TARGETS)
    missing = sorted(ACCOUNTS - set(users))
    print({"matched": len(users), "missing": missing, "apply": args.apply})
    if missing or not args.apply:
        return
    for account in sorted(ACCOUNTS):
        school_id, user_id = users[account]
        common = {"schoolId": school_id, "userId": user_id, "changeSource": "recent_task_bulk_enable"}
        response = requests.put(
            f"{base}/api/internal/sign-feature-user",
            headers=headers,
            json={**common, "override": "show"},
            timeout=30,
        )
        response.raise_for_status()
        if not response.json().get("ok"):
            raise RuntimeError(f"{account}: {response.text}")
        response = requests.put(
            f"{base}/api/internal/sign-control",
            headers=headers,
            json={**common, "enabled": True},
            timeout=30,
        )
        response.raise_for_status()
        if not response.json().get("ok"):
            raise RuntimeError(f"{account}: {response.text}")
    print({"enabled": len(ACCOUNTS)})


if __name__ == "__main__":
    main()
