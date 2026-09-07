from pathlib import Path


source = (Path(__file__).resolve().parents[1] / "qianduan/server_api_example.py").read_text()
public = source.split('@app.post("/api/me/status")', 1)[1].split(
    '@app.post("/api/internal/user-status")', 1
)[0]
assert '"/api/internal/user-status"' in public
assert "_call_self_service(" in public
assert "add_service_audit(" in public
assert "push_user_to_kv_now" not in public
assert "cache_user(school_id, local_user, mark_synced=True)" in public
assert '("pauseUntil", "pause_until")' in public
assert '("lastResumedAt", "last_resumed_at")' in public
assert public.index('if remote.get("ok"):\n') < public.index('remote.get("saveMode") != "noop"')

internal = source.split('@app.post("/api/internal/user-status")', 1)[1].split(
    '@app.get("/api/school-meta")', 1
)[0]
assert "_require_server_dispatch_api_key()" in internal
assert "return update_user_status(school_id, user_id, body)" in internal

logic = source.split("def update_user_status(", 1)[1].split(
    '@app.post("/api/me/status")', 1
)[0]
assert "pause_until" in logic
assert '"syncStatus": "pending"' in logic
assert "立即同步暂停时间失败" not in logic

print("status service relay check passed")
