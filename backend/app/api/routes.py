import shutil
from pathlib import Path

from fastapi import APIRouter, UploadFile, File, HTTPException, BackgroundTasks
from app.services.jobs import create_job, get_job, save_uploaded_file, update_job_status
from app.services.analyzer import (
    analyze_pcap,
    load_summary,
    load_packets,
    load_streams,
    load_findings,
    load_root_causes,
    load_root_causes_v2,
    load_timeline_analysis,
    load_packets_for_stream,
    extract_http_records,
    extract_dns_transactions,
    summarize_dns_health,
    correlate_dns_to_tcp,
    build_latency_chain,
    build_rca_summary,
)
from app.services.gtrace_service import run_gtrace, get_gtrace_job, get_gtrace_result, compare_gtrace_results, create_gtrace_probe_job, claim_next_gtrace_probe_job, save_gtrace_probe_result
from app.models.schemas import (
    UploadResponse,
    JobStatusResponse,
    CaptureSummaryResponse,
)

router = APIRouter()

GTRACE_PROBE_REGISTRY = {
    "local-default": {
        "probe_id": "probe-local-01",
        "source_region": "local-default",
        "country": "Local",
        "city": "Local",
        "probe_public_ip": None,
        "execution_mode": "local",
        "enabled": True,
    },
    "in-india": {
        "probe_id": "probe-local-01",
        "source_region": "in-india",
        "country": "India",
        "city": "Local-mapped",
        "probe_public_ip": None,
        "execution_mode": "local",
        "enabled": True,
    },
    "de-germany": {
        "probe_id": "probe-de-01",
        "source_region": "de-germany",
        "country": "Germany",
        "city": "Polling-probe",
        "probe_public_ip": None,
        "execution_mode": "polling",
        "enabled": True,
    },
    "sg-singapore": {
        "probe_id": "probe-local-01",
        "source_region": "sg-singapore",
        "country": "Singapore",
        "city": "Local-mapped",
        "probe_public_ip": None,
        "execution_mode": "local",
        "enabled": True,
    },
    "us-east": {
        "probe_id": "probe-local-01",
        "source_region": "us-east",
        "country": "United States",
        "city": "Local-mapped",
        "probe_public_ip": None,
        "execution_mode": "local",
        "enabled": True,
    },
}


def resolve_gtrace_probe(source_region: str | None):
    region = source_region or "local-default"
    probe = GTRACE_PROBE_REGISTRY.get(region)
    if not probe or not probe.get("enabled"):
        return GTRACE_PROBE_REGISTRY["local-default"]
    return probe


ALLOWED_EXTENSIONS = {".pcap", ".pcapng"}


def flush_previous_analysis_data():
    base_dir = Path("/opt/pcap-analyzer/backend/data")
    uploads_dir = base_dir / "uploads"
    results_dir = base_dir / "results"

    for directory in (uploads_dir, results_dir):
        directory.mkdir(parents=True, exist_ok=True)
        for item in list(directory.iterdir()):
            if item.is_dir():
                shutil.rmtree(item, ignore_errors=True)
            else:
                try:
                    item.unlink()
                except FileNotFoundError:
                    pass

    print("DEBUG: previous upload/result data flushed")


def run_analysis(job_id: str, filename: str, stored_path: str):
    try:
        update_job_status(job_id, "processing")
        analyze_pcap(job_id=job_id, filename=filename, file_path=stored_path)
        update_job_status(job_id, "completed")
    except Exception as e:
        update_job_status(job_id, f"failed: {str(e)}")


@router.get("/health")
def health():
    return {"status": "ok"}


@router.post("/api/upload", response_model=UploadResponse)
async def upload_pcap(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...)
):
    filename = file.filename or ""
    if not any(filename.lower().endswith(ext) for ext in ALLOWED_EXTENSIONS):
        raise HTTPException(status_code=400, detail="Only .pcap and .pcapng files are allowed")

    flush_previous_analysis_data()

    job = create_job(filename=filename)
    saved_path = await save_uploaded_file(job_id=job["job_id"], upload_file=file)

    # PCAP_PERSIST_CLEAN_FOR_DNS
    try:
        import shutil
        from pathlib import Path

        base_dir = Path("data")
        uploads_dir = base_dir / "uploads" / job["job_id"]
        results_dir = base_dir / "results" / job["job_id"]
        results_dir.mkdir(parents=True, exist_ok=True)

        candidates = list(uploads_dir.glob("*.pcap")) + list(uploads_dir.glob("*.pcapng"))

        src = Path(saved_path)
        if src.exists():
            dst = results_dir / src.name
            shutil.copyfile(src, dst)
            print(f"DEBUG: PCAP copied to results: {dst}")
        elif candidates:
            src = candidates[0]
            dst = results_dir / src.name
            shutil.copyfile(src, dst)
            print(f"DEBUG: PCAP copied to results: {dst}")
        else:
            print(f"WARNING: No uploaded PCAP found for job {job['job_id']}")
    except Exception as e:
        print(f"WARNING: Failed to persist PCAP for DNS: {e}")

    background_tasks.add_task(run_analysis, job["job_id"], filename, saved_path)

    return UploadResponse(
        job_id=job["job_id"],
        filename=filename,
        status="uploaded",
        stored_path=saved_path
    )


@router.get("/api/jobs/{job_id}", response_model=JobStatusResponse)
def get_job_status(job_id: str):
    job = get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return JobStatusResponse(**job)


@router.get("/api/jobs/{job_id}/summary", response_model=CaptureSummaryResponse)
def get_job_summary(job_id: str):
    job = get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    summary = load_summary(job_id)
    if not summary:
        raise HTTPException(status_code=404, detail="Summary not ready yet")

    return CaptureSummaryResponse(**summary)


@router.get("/api/jobs/{job_id}/packets")
def get_packets(job_id: str):
    packets = load_packets(job_id)

    if not packets:
        raise HTTPException(status_code=404, detail="Packets not ready")

    return packets[:500]


@router.get("/api/jobs/{job_id}/streams")
def get_streams(job_id: str):
    streams = load_streams(job_id)

    if not streams:
        raise HTTPException(status_code=404, detail="Streams not ready")

    return streams




@router.get("/api/jobs/{job_id}/dns")
def get_dns_transactions(job_id: str):
    return extract_dns_transactions(job_id)


@router.get("/api/jobs/{job_id}/mtu")
def get_job_mtu_analysis(job_id: str):
    from app.services.mtu_analyzer import analyze_mtu_for_job
    return analyze_mtu_for_job(job_id)



@router.get("/api/jobs/{job_id}/dns/summary")
def get_dns_summary(job_id: str):
    return summarize_dns_health(job_id)


@router.get("/api/jobs/{job_id}/dns/tcp-correlation")
def get_dns_tcp_correlation(job_id: str):
    return correlate_dns_to_tcp(job_id)


@router.get("/api/jobs/{job_id}/latency-chain")
def get_latency_chain(job_id: str):
    return build_latency_chain(job_id)


@router.get("/api/jobs/{job_id}/rca-summary")
def get_rca_summary(job_id: str):
    return build_rca_summary(job_id)


@router.get("/api/jobs/{job_id}/http")
def get_http_records(job_id: str):
    records = extract_http_records(job_id)
    if records is None:
        raise HTTPException(status_code=404, detail="HTTP records not ready")
    return records


@router.get("/api/jobs/{job_id}/findings")
def get_findings(job_id: str):
    findings = load_findings(job_id)

    if findings is None:
        raise HTTPException(status_code=404, detail="Findings not ready")

    return findings


@router.get("/api/jobs/{job_id}/root-causes")
def get_root_causes(job_id: str):
    root_causes = load_root_causes(job_id)

    if root_causes is None:
        raise HTTPException(status_code=404, detail="Root causes not ready")

    return root_causes


@router.get("/api/jobs/{job_id}/streams/{stream_id:path}/packets")
def get_stream_packets(job_id: str, stream_id: str):
    result = load_packets_for_stream(job_id, stream_id)

    if result is None:
        raise HTTPException(status_code=404, detail="Stream packets not found")

    return result


@router.post("/api/gtrace/run")
def api_run_gtrace(payload: dict):
    payload["source_region"] = payload.get("source_region") or "local-default"
    probe = resolve_gtrace_probe(payload.get("source_region"))
    try:
        env = probe.get("env") or {}
        if probe.get("execution_mode") == "polling":
            result = create_gtrace_probe_job(
                target=payload.get("target"),
                protocol=payload.get("protocol", "icmp"),
                port=payload.get("port"),
                max_hops=payload.get("max_hops", 30),
                packets=payload.get("packets", 3),
                source_region=probe["source_region"],
                probe_id=probe["probe_id"],
            )
            result["probe_public_ip"] = probe.get("probe_public_ip")
            return result

        result = run_gtrace(
            target=payload.get("target"),
            protocol=payload.get("protocol", "icmp"),
            port=payload.get("port"),
            max_hops=payload.get("max_hops", 30),
            packets=payload.get("packets", 3),
            env=env
        )
        if isinstance(result, dict):
            result["source_region"] = probe["source_region"]
            result["probe_id"] = probe["probe_id"]
            result["probe_public_ip"] = probe.get("probe_public_ip")
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"gtrace failed: {e}")


@router.get("/api/gtrace/jobs/{job_id}")
def api_get_gtrace_job(job_id: str):
    job = get_gtrace_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="gtrace job not found")
    return job


@router.get("/api/gtrace/jobs/{job_id}/result")
def api_get_gtrace_result(job_id: str):
    result = get_gtrace_result(job_id)
    if not result:
        raise HTTPException(status_code=404, detail="gtrace result not found")
    return result



@router.post("/api/gtrace/probe/next")
def api_gtrace_probe_next(payload: dict):
    probe_id = payload.get("probe_id")
    source_region = payload.get("source_region")

    if not probe_id:
        raise HTTPException(status_code=400, detail="probe_id is required")

    job = claim_next_gtrace_probe_job(probe_id=probe_id, source_region=source_region)
    if not job:
        return {"job": None}

    return {"job": job}


@router.post("/api/gtrace/probe/{job_id}/result")
def api_gtrace_probe_result(job_id: str, payload: dict):
    probe_id = payload.get("probe_id")
    result = payload.get("result")

    if not probe_id:
        raise HTTPException(status_code=400, detail="probe_id is required")
    if not isinstance(result, dict):
        raise HTTPException(status_code=400, detail="result must be an object")

    try:
        saved = save_gtrace_probe_result(job_id=job_id, probe_id=probe_id, result=result)
        return {"ok": True, "result": saved}
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="gtrace job not found")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/api/gtrace/compare")
def api_compare_gtrace(payload: dict):
    job_id_a = payload.get("job_id_a")
    job_id_b = payload.get("job_id_b")

    if not job_id_a or not job_id_b:
        raise HTTPException(status_code=400, detail="job_id_a and job_id_b are required")

    result = compare_gtrace_results(job_id_a, job_id_b)
    if not result:
        raise HTTPException(status_code=404, detail="One or both gtrace results not found")

    return result


@router.get("/api/jobs/{job_id}/root-causes-v2")
def get_root_causes_v2(job_id: str):
    result = load_root_causes_v2(job_id)

    if result is None:
        raise HTTPException(status_code=404, detail="Root causes v2 not ready")

    return result


@router.get("/api/jobs/{job_id}/timeline")
def get_timeline_analysis(job_id: str):
    result = load_timeline_analysis(job_id)

    if result is None:
        raise HTTPException(status_code=404, detail="Timeline analysis not ready")

    return result

