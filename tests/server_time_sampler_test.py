import sys
import datetime as dt
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import server_time_sampler


def test_sample_once_records_raw_clocks_and_monotonic_rtt():
    response = Mock(status_code=200, ok=True)
    response.json.return_value = {
        "data": {"serverNow": 1_788_470_710_201, "beforeOpenTimeStamp": 1_788_470_856_886}
    }
    session = Mock()
    session.post.return_value = response
    with patch.object(server_time_sampler.time, "time_ns", side_effect=[1_788_470_710_123_000_000, 1_788_470_710_286_000_000]), patch.object(
        server_time_sampler.time, "perf_counter_ns", side_effect=[10_000_000, 173_400_000]
    ), patch.object(server_time_sampler.logging, "info") as log:
        record = server_time_sampler.sample_once(
            session, server_time_sampler.ENDPOINTS["seatengine"], {}, "normal", 1, 12,
            target_at=dt.datetime.fromtimestamp(1_788_470_860_886 / 1000, server_time_sampler.BEIJING_TZ),
        )

    assert record == {
        "success": True,
        "local_send_ms": 1_788_470_710_123,
        "server_now_ms": 1_788_470_710_201,
        "local_recv_ms": 1_788_470_710_286,
        "rtt_ms": 163.4,
        "server_minus_send_ms": 78,
        "recv_minus_server_ms": 85,
        "midpoint_offset_ms": -3.5,
        "connection_reused": "unknown",
        "tcp_connect_ms": None,
        "ssl_handshake_ms": None,
        "before_open_timestamp": 1_788_470_856_886,
        "latency_anomaly": False,
    }
    session.post.assert_called_once()
    message, *args = log.call_args.args
    rendered = message % tuple(args)
    assert "本地发出：2026-09-04 05:25:10.123" in rendered
    assert "请求往返耗时：163.40 ms" in rendered
    assert "local_send_ms=1788470710123" in rendered
    assert "connection_reused=unknown" in rendered
    assert "服务器距官方开放：146.685 秒" in rendered
    assert "中点偏差估计：-3.50 ms" in rendered


def test_sampling_stops_after_success_target_and_does_not_count_failures():
    sampler = Mock()
    sampler.bootstrap_login.return_value = True
    records = [
        {"success": False, "connection_reused": "unknown", "rtt_ms": 1, "server_minus_send_ms": None, "recv_minus_server_ms": None, "midpoint_offset_ms": None},
        {"success": True, "connection_reused": "true", "rtt_ms": 2, "server_minus_send_ms": 1, "recv_minus_server_ms": 1, "midpoint_offset_ms": 0},
        {"success": True, "connection_reused": "true", "rtt_ms": 3, "server_minus_send_ms": 1, "recv_minus_server_ms": 1, "midpoint_offset_ms": 0},
    ]
    with patch.object(server_time_sampler, "reserve", return_value=sampler), patch.object(
        server_time_sampler, "sample_once", side_effect=records
    ) as sample, patch.object(server_time_sampler.time, "sleep"), patch.object(
        server_time_sampler, "_log_start"
    ), patch.object(server_time_sampler, "_summary") as summary:
        server_time_sampler.run_sampling("u", "p", "1", "2026-09-05", "f", "seat", count=2)

    assert sample.call_count == 3
    assert summary.call_args.args[1] == records


def test_zero_connect_timings_are_only_marked_likely_reused():
    owner = Mock()
    owner._time_sample_request_trace = {}
    response = Mock(status_code=200, ok=True)
    response.json.return_value = {"data": {"serverNow": 1_788_470_710_201}}

    def post(*_args, **_kwargs):
        owner._time_sample_request_trace = {
            "connection_reused": None,
            "tcp_connect_seconds": 0.0,
            "ssl_handshake_seconds": 0.0,
        }
        return response

    session = Mock()
    session.post.side_effect = post
    with patch.object(server_time_sampler.time, "time_ns", side_effect=[1_788_470_710_123_000_000, 1_788_470_710_286_000_000]), patch.object(
        server_time_sampler.time, "perf_counter_ns", side_effect=[10_000_000, 173_400_000]
    ), patch.object(server_time_sampler.logging, "info"):
        record = server_time_sampler.sample_once(
            session, server_time_sampler.ENDPOINTS["seat"], {}, "normal", 1, 12, trace_owner=owner
        )

    assert record["connection_reused"] == "likely_reused"


def test_summary_excludes_cold_connection_from_reused_percentiles():
    def record(rtt, reused):
        return {
            "success": True,
            "rtt_ms": rtt,
            "server_minus_send_ms": -2,
            "recv_minus_server_ms": 35,
            "midpoint_offset_ms": -18.5,
            "connection_reused": reused,
            "before_open_timestamp": 1_788_470_856_886,
        }

    records = [record(113.51, "false"), record(31, "true"), record(33, "likely_reused"), record(50, "true")]
    with patch.object(server_time_sampler.logging, "info") as log:
        server_time_sampler._summary("pre_open", records)
    message, *args = log.call_args.args
    rendered = message % tuple(args)
    assert "冷连接：1" in rendered
    assert "复用连接：3" in rendered
    assert "请求往返耗时最小/最大：31.00 / 50.00 ms" in rendered
    assert "113.51" not in rendered
    assert "异常延迟样本：1" in rendered


if __name__ == "__main__":
    test_sample_once_records_raw_clocks_and_monotonic_rtt()
    test_sampling_stops_after_success_target_and_does_not_count_failures()
    test_zero_connect_timings_are_only_marked_likely_reused()
    test_summary_excludes_cold_connection_from_reused_percentiles()
