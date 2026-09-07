from pathlib import Path


source = (Path(__file__).resolve().parents[1] / "server_store/result_repository.py").read_text()

assert "r.status IN ('backup_success', 'partial_success')" in source
assert "CASE WHEN r.status IN ('backup_success', 'partial_success')" in source

print("conflict-group detail includes partial success")
