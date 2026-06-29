import os
import uuid
from pathlib import Path
from fastapi import UploadFile
from app.core.paths import DATA_DIR, UPLOAD_DIR, RESULTS_DIR

BASE_DIR = DATA_DIR

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
RESULTS_DIR.mkdir(parents=True, exist_ok=True)

JOBS: dict[str, dict] = {}


def create_job(filename: str) -> dict:
    job_id = str(uuid.uuid4())
    job_data = {
        "job_id": job_id,
        "filename": filename,
        "status": "uploaded",
        "stored_path": ""
    }
    JOBS[job_id] = job_data
    return job_data


def update_job_status(job_id: str, status: str):
    if job_id in JOBS:
        JOBS[job_id]["status"] = status


def get_job(job_id: str) -> dict | None:
    return JOBS.get(job_id)


async def save_uploaded_file(job_id: str, upload_file: UploadFile) -> str:
    job_dir = UPLOAD_DIR / job_id
    job_dir.mkdir(parents=True, exist_ok=True)

    safe_name = os.path.basename(upload_file.filename or "capture.pcap")
    file_path = job_dir / safe_name

    with open(file_path, "wb") as f:
        while True:
            chunk = await upload_file.read(1024 * 1024)
            if not chunk:
                break
            f.write(chunk)

    JOBS[job_id]["stored_path"] = str(file_path)
    return str(file_path)
