import json
import os
import subprocess
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_entropy_integration(tmp_path):
    subprocess.run(["make", "core"], cwd=ROOT, check=True)

    scan = tmp_path / "scan"
    scan.mkdir()

    config = tmp_path / "radar.conf"
    events = tmp_path / "events.jsonl"
    log = tmp_path / "engine.log"
    decoy = tmp_path / "decoy.txt"

    config.write_text(
        f"SCAN_PATH={scan}\n"
        "SCAN_INTERVAL=1\n"
        "ENTROPY_THRESHOLD=7.5\n"
        f"LOG_FILE={tmp_path / 'radar.log'}\n"
        f"DECOY_PATH={decoy}\n"
    )

    env = os.environ.copy()
    env["RADAR_CONF_PATH"] = str(config)
    env["RADAR_RULES_PATH"] = str(ROOT / "rules.txt")

    def read_alerts():
        lines = events.read_text().splitlines(keepends=True)
        records = [
            json.loads(line)
            for line in lines if line.endswith("\n")
        ]
        return [
            e for e in records
            if e.get("event") == "high_entropy"
        ]

    with events.open("w") as out, log.open("w") as err:
        proc = subprocess.Popen(
            [str(ROOT / "build/radar_core"), str(decoy)],
            cwd=ROOT,
            env=env,
            stdout=out,
            stderr=err,
        )

        def wait_for(condition, timeout=15):
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                assert proc.poll() is None, log.read_text()
                if condition():
                    return
                time.sleep(0.2)
            raise AssertionError(log.read_text())

        try:
            wait_for(
                lambda: "Entropy scanner on" in log.read_text()
            )
            time.sleep(2)

            normal = scan / "normal.bin"
            high = scan / "high_entropy.bin"

            normal.write_bytes(b"A" * 65536)
            high.write_bytes(bytes(range(256)) * 256)

            wait_for(lambda: len(read_alerts()) >= 1)

            alerts = read_alerts()
            assert len(alerts) == 1
            assert alerts[0]["source"] == "scanner"
            assert alerts[0]["level"] == "MEDIUM"
            assert str(high) in alerts[0]["detail"]
            assert "entropy 8.00" in alerts[0]["detail"]

            time.sleep(3)
            assert len(read_alerts()) == 1

            high.touch()
            wait_for(lambda: len(read_alerts()) >= 2)

            time.sleep(2)
            alerts = read_alerts()
            assert len(alerts) == 2
            assert all(str(high) in e["detail"] for e in alerts)

        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()

        assert proc.returncode == 0
        assert "Shutting down" in log.read_text()
