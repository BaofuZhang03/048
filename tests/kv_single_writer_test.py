from unittest.mock import patch

from server_store.runtime import CloudflareKVClient


def test_read_only_client_rejects_writes():
    with patch.dict("os.environ", {"KV_WRITE_ENABLED": "0"}):
        client = CloudflareKVClient("account", "namespace", "token")
        for operation in (
            lambda: client.put_json("key", {"value": 1}),
            lambda: client.delete_key("key"),
        ):
            try:
                operation()
            except RuntimeError as exc:
                assert "read-only server" in str(exc)
            else:
                raise AssertionError("read-only KV client accepted a write")


def test_deployment_defaults_to_101_as_only_writer():
    source = open("deploy_server.sh", encoding="utf-8").read()
    assert 'DEFAULT_STORE_SYNC_HOSTS="101.43.25.136"' in source
    assert "KV_WRITE_ENABLED=$enable_store_sync_timers" in source


def test_read_only_sign_server_does_not_dirty_user_cache():
    source = open("qianduan/server_api_example.py", encoding="utf-8").read()
    logic = source.split("def _set_sign_user_auto(", 1)[1].split(
        "def _sign_feature_visibility_dashboard(", 1
    )[0]
    assert "if kv_write_enabled and isinstance(source_user, dict):" in logic
