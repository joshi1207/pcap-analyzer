import json
import re
import shlex
import subprocess
import uuid
from pathlib import Path
from app.core.paths import DATA_DIR, GTRACE_RESULTS_DIR, GTRACE_INFO_CACHE_DIR


BASE_DIR = DATA_DIR
GTRACE_RESULTS_DIR.mkdir(parents=True, exist_ok=True)
GTRACE_INFO_CACHE_DIR.mkdir(parents=True, exist_ok=True)


ALLOWED_PROTOCOLS = {"icmp", "udp", "tcp"}


def parse_gtrace_simple_output(stdout: str):
    hops = []
    destination_reached = False
    reached_hops = None

    if not stdout:
        return {"hops": hops, "destination_reached": False, "reached_hops": None}

    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        if line.lower().startswith("trace complete:"):
            destination_reached = True
            m = re.search(r"in\s+(\d+)\s+hops", line, re.IGNORECASE)
            if m:
                reached_hops = int(m.group(1))
            continue

        if not re.match(r"^\d+\s+", line):
            continue

        hop_match = re.match(r"^(\d+)\s+(.*)$", line)
        if not hop_match:
            continue

        hop_no = int(hop_match.group(1))
        rest = hop_match.group(2).strip()

        asn = None
        asn_match = re.search(r"\[(AS\d+)\]", rest)
        if asn_match:
            asn = asn_match.group(1)
            rest = re.sub(r"\s*\[AS\d+\]\s*", " ", rest).strip()

        rtts = re.findall(r"(\d+(?:\.\d+)?)ms", rest)
        stars = rest.count("*")

        rest_no_rtt = re.sub(r"\s*\d+(?:\.\d+)?ms", "", rest)
        rest_no_rtt = re.sub(r"\s+\*\s*", " ", rest_no_rtt).strip()

        host = None
        ip = None

        paren = re.search(r"(.+?)\s+\(([^)]+)\)", rest_no_rtt)
        if paren:
            host = paren.group(1).strip()
            ip = paren.group(2).strip()
        else:
            token = rest_no_rtt.strip()
            ip_only = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3})$", token)
            if ip_only:
                ip = ip_only.group(1)
            elif token:
                host = token

        latency_values = [float(x) for x in rtts]
        avg_latency = round(sum(latency_values) / len(latency_values), 2) if latency_values else None

        notes = []
        if stars > 0:
            notes.append("Some probes unanswered")
        if host == "_gateway":
            notes.append("Local gateway")
        if host and "akamai" in host.lower():
            notes.append("CDN hop (Akamai)")
        if host and "google" in host.lower():
            notes.append("Google destination/service")

        hops.append({
            "hop": hop_no,
            "host": host,
            "ip": ip,
            "asn": asn,
            "rtts_ms": latency_values,
            "avg_rtt_ms": avg_latency,
            "missing_probes": stars,
            "notes": notes,
            "raw": raw_line,
        })

    return {
        "hops": hops,
        "destination_reached": destination_reached,
        "reached_hops": reached_hops,
    }


def build_gtrace_insights(parsed: dict):
    hops = parsed.get("hops", [])
    insights = []

    if not hops:
        return {
            "summary": ["No hops parsed from gtrace output."],
            "max_avg_rtt_ms": None,
            "asn_path": [],
        }

    asn_path = []
    for hop in hops:
        asn = hop.get("asn")
        if asn and (not asn_path or asn_path[-1] != asn):
            asn_path.append(asn)

    max_avg = None
    for hop in hops:
        if hop.get("avg_rtt_ms") is not None:
            if max_avg is None or hop["avg_rtt_ms"] > max_avg:
                max_avg = hop["avg_rtt_ms"]

    loss_hops = [h for h in hops if h.get("missing_probes", 0) > 0]
    if parsed.get("destination_reached"):
        insights.append(f"Destination reached in {parsed.get('reached_hops') or len(hops)} hops.")
    else:
        insights.append("Destination not confirmed as reached.")

    if asn_path:
        if len(asn_path) == 1:
            insights.append(f"Path stayed within {asn_path[0]} for visible ASN-tagged hops.")
        else:
            insights.append(f"ASN path observed: {' → '.join(asn_path)}")

    if max_avg is not None:
        insights.append(f"Highest observed average RTT was {max_avg} ms.")

    if loss_hops:
        hop_list = ", ".join(str(h["hop"]) for h in loss_hops[:5])
        insights.append(f"Some probes were unanswered at hops: {hop_list}. This may be ICMP rate limiting rather than true path loss.")

    cdn_hops = [h for h in hops if any("CDN hop" in n for n in h.get("notes", []))]
    if cdn_hops:
        insights.append("CDN infrastructure detected in path.")

    return {
        "summary": insights,
        "max_avg_rtt_ms": max_avg,
        "asn_path": asn_path,
    }



def safe_cache_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", value)


def lookup_ip_info(ip: str):
    if not ip:
        return {}

    cache_file = GTRACE_INFO_CACHE_DIR / f"{safe_cache_name(ip)}.json"
    if cache_file.exists():
        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass

    cmd = ["gtrace", "info", ip]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        stdout = proc.stdout or ""
        info = parse_gtrace_info_output(stdout)

        with open(cache_file, "w", encoding="utf-8") as f:
            json.dump(info, f, indent=2)

        return info
    except Exception:
        return {}


def parse_gtrace_info_output(stdout: str):
    info = {
        "asn": None,
        "asn_org": None,
        "country": None,
        "city": None,
        "hostname": None,
        "raw": stdout or "",
    }

    if not stdout:
        return info

    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        lower = line.lower()

        if lower.startswith("asn:"):
            info["asn"] = line.split(":", 1)[1].strip() or None
        elif lower.startswith("organization:") or lower.startswith("org:"):
            info["asn_org"] = line.split(":", 1)[1].strip() or None
        elif lower.startswith("country:"):
            info["country"] = line.split(":", 1)[1].strip() or None
        elif lower.startswith("city:"):
            info["city"] = line.split(":", 1)[1].strip() or None
        elif lower.startswith("hostname:") or lower.startswith("rdns:"):
            info["hostname"] = line.split(":", 1)[1].strip() or None

    return info


def enrich_hops_with_ip_info(hops):
    enriched = []

    for hop in hops:
        hop = dict(hop)
        ip = hop.get("ip")
        if ip:
            ip_info = lookup_ip_info(ip)
            hop["asn_org"] = ip_info.get("asn_org")
            hop["country"] = ip_info.get("country")
            hop["city"] = ip_info.get("city")

            if not hop.get("asn") and ip_info.get("asn"):
                hop["asn"] = ip_info.get("asn")

            if not hop.get("host") and ip_info.get("hostname"):
                hop["host"] = ip_info.get("hostname")
        else:
            hop["asn_org"] = None
            hop["country"] = None
            hop["city"] = None

        enriched.append(hop)

    return enriched

def validate_target(target: str) -> str:
    target = (target or "").strip()
    if not target:
        raise ValueError("Target is required")

    # conservative allowlist: hostname, IPv4, IPv6-ish, dash/underscore
    if not re.fullmatch(r"[A-Za-z0-9\.\-_:]+", target):
        raise ValueError("Target contains invalid characters")

    return target


def validate_protocol(protocol: str) -> str:
    protocol = (protocol or "icmp").strip().lower()
    if protocol not in ALLOWED_PROTOCOLS:
        raise ValueError(f"Unsupported protocol: {protocol}")
    return protocol


def validate_port(port):
    if port is None or port == "":
        return None
    port = int(port)
    if not (1 <= port <= 65535):
        raise ValueError("Port must be between 1 and 65535")
    return port


def validate_positive_int(value, default_value):
    if value is None or value == "":
        return default_value
    value = int(value)
    if value <= 0:
        raise ValueError("Value must be positive")
    return value


def build_gtrace_command(target: str, protocol: str, port=None, max_hops=30, packets=3):
    cmd = [
        "sudo","-n",
        "gtrace",
        target,
        "--simple",
        "--protocol",
        protocol,
        "--max-hops",
        str(max_hops),
        "--packets",
        str(packets),
    ]

    if protocol == "tcp" and port:
        cmd.extend(["--port", str(port)])
    elif protocol == "udp" and port:
        cmd.extend(["--port", str(port)])

    return cmd


def run_gtrace(target: str, protocol: str = "icmp", port=None, max_hops=30, packets=3, env=None):
    target = validate_target(target)
    protocol = validate_protocol(protocol)
    port = validate_port(port)
    max_hops = validate_positive_int(max_hops, 30)
    packets = validate_positive_int(packets, 3)

    job_id = str(uuid.uuid4())
    job_dir = GTRACE_RESULTS_DIR / job_id
    job_dir.mkdir(parents=True, exist_ok=True)

    cmd = build_gtrace_command(
        target=target,
        protocol=protocol,
        port=port,
        max_hops=max_hops,
        packets=packets,
    )

    cmd_string = " ".join(shlex.quote(part) for part in cmd)

    metadata = {
        "job_id": job_id,
        "target": target,
        "protocol": protocol,
        "port": port,
        "max_hops": max_hops,
        "packets": packets,
        "status": "running",
        "command": cmd_string,
    }

    with open(job_dir / "metadata.json", "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=45,
            check=False,
            env=env,
        )

        stdout = proc.stdout or ""
        stderr = proc.stderr or ""

        parsed = parse_gtrace_simple_output(stdout)
        parsed["hops"] = enrich_hops_with_ip_info(parsed["hops"])
        insights = build_gtrace_insights(parsed)

        result = {
            "job_id": job_id,
            "target": target,
            "protocol": protocol,
            "port": port,
            "max_hops": max_hops,
            "packets": packets,
            "status": "completed" if proc.returncode == 0 else "failed",
            "returncode": proc.returncode,
            "stdout": stdout,
            "stderr": stderr,
            "command": cmd_string,
            "parsed_hops": parsed["hops"],
            "destination_reached": parsed["destination_reached"],
            "reached_hops": parsed["reached_hops"],
            "path_summary": insights["summary"],
            "max_avg_rtt_ms": insights["max_avg_rtt_ms"],
            "asn_path": insights["asn_path"],
        }

    except subprocess.TimeoutExpired:
        result = {
            "job_id": job_id,
            "target": target,
            "protocol": protocol,
            "port": port,
            "max_hops": max_hops,
            "packets": packets,
            "status": "failed",
            "returncode": None,
            "stdout": "",
            "stderr": "gtrace execution timed out",
            "command": cmd_string,
            "parsed_hops": [],
            "destination_reached": False,
            "reached_hops": None,
            "path_summary": ["gtrace execution timed out."],
            "max_avg_rtt_ms": None,
            "asn_path": [],
        }

    with open(job_dir / "result.json", "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    metadata["status"] = result["status"]
    with open(job_dir / "metadata.json", "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    return result


def get_gtrace_job(job_id: str):
    meta_file = GTRACE_RESULTS_DIR / job_id / "metadata.json"
    if not meta_file.exists():
        return None

    with open(meta_file, "r", encoding="utf-8") as f:
        return json.load(f)



def compare_gtrace_results(job_id_a: str, job_id_b: str):
    result_a = get_gtrace_result(job_id_a)
    result_b = get_gtrace_result(job_id_b)

    if not result_a or not result_b:
        return None

    hops_a = result_a.get("parsed_hops", [])
    hops_b = result_b.get("parsed_hops", [])

    max_hops = max(len(hops_a), len(hops_b))
    hop_diffs = []

    for idx in range(max_hops):
        a = hops_a[idx] if idx < len(hops_a) else None
        b = hops_b[idx] if idx < len(hops_b) else None

        hop_diffs.append({
            "hop": idx + 1,
            "a_host": a.get("host") if a else None,
            "b_host": b.get("host") if b else None,
            "a_ip": a.get("ip") if a else None,
            "b_ip": b.get("ip") if b else None,
            "a_asn": a.get("asn") if a else None,
            "b_asn": b.get("asn") if b else None,
            "a_avg_rtt_ms": a.get("avg_rtt_ms") if a else None,
            "b_avg_rtt_ms": b.get("avg_rtt_ms") if b else None,
            "a_missing": a.get("missing_probes") if a else None,
            "b_missing": b.get("missing_probes") if b else None,
            "changed": (
                (a.get("ip") if a else None) != (b.get("ip") if b else None)
                or (a.get("asn") if a else None) != (b.get("asn") if b else None)
            ),
        })

    summary = []

    if result_a.get("destination_reached") != result_b.get("destination_reached"):
        summary.append("Destination reachability changed between traces.")

    if result_a.get("reached_hops") != result_b.get("reached_hops"):
        summary.append(
            f"Hop count changed: {result_a.get('reached_hops')} → {result_b.get('reached_hops')}"
        )

    changed_hops = [h["hop"] for h in hop_diffs if h["changed"]]
    if changed_hops:
        summary.append(f"Path changed at hops: {', '.join(str(x) for x in changed_hops[:10])}")

    max_rtt_a = result_a.get("max_avg_rtt_ms")
    max_rtt_b = result_b.get("max_avg_rtt_ms")
    if max_rtt_a is not None and max_rtt_b is not None and max_rtt_a != max_rtt_b:
        summary.append(f"Peak average RTT changed: {max_rtt_a} ms → {max_rtt_b} ms")

    return {
        "job_id_a": job_id_a,
        "job_id_b": job_id_b,
        "target_a": result_a.get("target"),
        "target_b": result_b.get("target"),
        "summary": summary,
        "hop_diffs": hop_diffs,
    }


def get_gtrace_result(job_id: str):
    result_file = GTRACE_RESULTS_DIR / job_id / "result.json"
    if not result_file.exists():
        return None

    with open(result_file, "r", encoding="utf-8") as f:
        return json.load(f)


def create_gtrace_probe_job(
    target: str,
    protocol: str = "icmp",
    port=None,
    max_hops=30,
    packets=3,
    source_region: str = "local-default",
    probe_id: str | None = None,
):
    target = validate_target(target)
    protocol = validate_protocol(protocol)
    port = validate_port(port)
    max_hops = validate_positive_int(max_hops, 30)
    packets = validate_positive_int(packets, 3)

    job_id = str(uuid.uuid4())
    job_dir = GTRACE_RESULTS_DIR / job_id
    job_dir.mkdir(parents=True, exist_ok=True)

    metadata = {
        "job_id": job_id,
        "target": target,
        "protocol": protocol,
        "port": port,
        "max_hops": max_hops,
        "packets": packets,
        "status": "queued",
        "source_region": source_region,
        "assigned_probe_id": probe_id,
        "execution_mode": "polling",
    }

    with open(job_dir / "metadata.json", "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    return metadata


def claim_next_gtrace_probe_job(probe_id: str, source_region: str | None = None):
    jobs = []
    for job_dir in GTRACE_RESULTS_DIR.iterdir():
        if not job_dir.is_dir():
            continue
        metadata_file = job_dir / "metadata.json"
        if not metadata_file.exists():
            continue
        try:
            with open(metadata_file, "r", encoding="utf-8") as f:
                meta = json.load(f)
            jobs.append((job_dir.stat().st_mtime, job_dir, meta))
        except Exception:
            continue

    jobs.sort(key=lambda x: x[0])

    for _, job_dir, meta in jobs:
        if meta.get("status") != "queued":
            continue
        if meta.get("execution_mode") != "polling":
            continue
        if meta.get("assigned_probe_id") and meta.get("assigned_probe_id") != probe_id:
            continue
        if source_region and meta.get("source_region") != source_region:
            continue

        meta["status"] = "assigned"
        meta["assigned_probe_id"] = probe_id

        with open(job_dir / "metadata.json", "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)

        return meta

    return None


def save_gtrace_probe_result(job_id: str, probe_id: str, result: dict):
    job_dir = GTRACE_RESULTS_DIR / job_id
    metadata_file = job_dir / "metadata.json"
    result_file = job_dir / "result.json"

    if not metadata_file.exists():
        raise FileNotFoundError(f"gtrace job not found: {job_id}")

    with open(metadata_file, "r", encoding="utf-8") as f:
        meta = json.load(f)

    assigned = meta.get("assigned_probe_id")
    if assigned and assigned != probe_id:
        raise ValueError(f"job {job_id} is assigned to {assigned}, not {probe_id}")

    result["job_id"] = job_id
    result["source_region"] = meta.get("source_region")
    result["probe_id"] = probe_id

    with open(result_file, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    meta["status"] = result.get("status", "completed")
    meta["assigned_probe_id"] = probe_id

    with open(metadata_file, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    return result
