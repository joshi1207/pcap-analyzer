import os
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = Path(
    os.environ.get("PCAP_DATA_DIR", BACKEND_DIR / "data")
).resolve()

UPLOAD_DIR = DATA_DIR / "uploads"
RESULTS_DIR = DATA_DIR / "results"
GTRACE_RESULTS_DIR = DATA_DIR / "gtrace_results"
GTRACE_INFO_CACHE_DIR = DATA_DIR / "gtrace_info_cache"

for directory in (
    UPLOAD_DIR,
    RESULTS_DIR,
    GTRACE_RESULTS_DIR,
    GTRACE_INFO_CACHE_DIR,
):
    directory.mkdir(parents=True, exist_ok=True)
