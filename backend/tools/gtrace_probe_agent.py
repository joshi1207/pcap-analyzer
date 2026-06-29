#!/usr/bin/env python3
import os
import sys
import time
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.services.gtrace_service import run_gtrace

CONTROLLER = os.getenv("GTRACE_CONTROLLER", "http://127.0.0.1:8000")
PROBE_ID = os.getenv("GTRACE_PROBE_ID", "probe-de-01")
SOURCE_REGION = os.getenv("GTRACE_SOURCE_REGION", "de-germany")
POLL_INTERVAL = int(os.getenv("GTRACE_POLL_INTERVAL", "5"))

def post_json(path, payload):
    url = CONTROLLER.rstrip("/") + path
    r = requests.post(url, json=payload, timeout=60)
    r.raise_for_status()
    return r.json()

def main():
    print(f"[probe] started: {PROBE_ID} ({SOURCE_REGION})")

    while True:
        try:
            data = post_json("/api/gtrace/probe/next", {
                "probe_id": PROBE_ID,
                "source_region": SOURCE_REGION,
            })

            job = data.get("job")
            if not job:
                time.sleep(POLL_INTERVAL)
                continue

            print(f"[probe] running job {job['job_id']} → {job['target']}")

            result = run_gtrace(
                target=job.get("target"),
                protocol=job.get("protocol", "icmp"),
                port=job.get("port"),
                max_hops=job.get("max_hops", 30),
                packets=job.get("packets", 3),
                env=None,
            )

            post_json(f"/api/gtrace/probe/{job['job_id']}/result", {
                "probe_id": PROBE_ID,
                "result": result,
            })

            print(f"[probe] submitted job {job['job_id']}")

        except Exception as e:
            print(f"[probe] error: {e}")
            time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
