from pydantic import BaseModel
from typing import Optional


class UploadResponse(BaseModel):
    job_id: str
    filename: str
    status: str
    stored_path: str


class JobStatusResponse(BaseModel):
    job_id: str
    filename: str
    status: str
    stored_path: str


class CaptureSummaryResponse(BaseModel):
    job_id: str
    filename: str
    status: str
    total_packets: int
    total_bytes: int
    duration_seconds: float
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    protocols: dict[str, int]
    top_src_ips: dict[str, int]
    top_dst_ips: dict[str, int]
