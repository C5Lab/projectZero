from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "main" / "crack_worker.c").read_text(encoding="utf-8")
CORE = (ROOT / "main" / "crack_worker_core.c").read_text(encoding="utf-8")


def function_body(name: str) -> str:
    match = re.search(rf"static\s+[^\n]+\s+{name}\s*\([^)]*\)\s*\{{", SOURCE)
    assert match, f"missing function {name}"
    start = match.end() - 1
    depth = 0
    for index in range(start, len(SOURCE)):
        if SOURCE[index] == "{":
            depth += 1
        elif SOURCE[index] == "}":
            depth -= 1
            if depth == 0:
                return SOURCE[start : index + 1]
    raise AssertionError(f"unterminated function {name}")


def test_start_replays_before_reset_or_task_creation():
    body = function_body("cw_start")
    first_classify = body.index("cw_start_action_locked")
    first_reply = body.index("cw_start_reply_existing")
    reset = body.index("memset(&cw_job")
    create = body.index("xTaskCreate")
    assert first_classify < first_reply < reset < create
    assert body.count("cw_start_action_locked") >= 2


def test_replay_conflict_and_busy_have_distinct_wire_results():
    body = function_body("cw_start_reply_existing")
    assert "ACCEPTED job=%s start=%" in body
    assert "replay=1 state=%s" in body
    assert "REJECTED code=job_conflict job=%s" in body
    assert "REJECTED code=busy job=%s" in body


def test_status_exposes_optional_health_fields():
    body = function_body("cw_status")
    assert "phase=%s progress_age_ms=%" in body
    assert "cw_phase_name(&snapshot)" in body
    assert "snapshot.last_progress_us" in body


def test_progress_age_starts_at_acceptance_until_safe_offset_advances():
    start = function_body("cw_start")
    task = function_body("cw_task")
    assert "cw_job.last_progress_us = esp_timer_get_time()" in start
    assert "cw_job.last_progress_us = cw_job.started_us" not in task
    assert "if (aligned > range_start) cw_job.last_progress_us" in task


def test_protocol_and_janos_version_remain_compatible():
    assert "protocol=4" in CORE
    assert "start=idempotent" in CORE
    assert "health=phase,progress_age_ms" in CORE
    assert 'set(JANOS_VERSION "1.7.5")' in (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
    assert '#define JANOS_VERSION "1.7.5"' in (ROOT / "main" / "main.c").read_text(encoding="utf-8")


if __name__ == "__main__":
    tests = [value for name, value in globals().copy().items()
             if name.startswith("test_") and callable(value)]
    for test in tests:
        test()
    print(f"test_crack_worker_job_replay: PASS ({len(tests)} tests)")
