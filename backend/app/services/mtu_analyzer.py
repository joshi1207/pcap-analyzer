from pathlib import Path
from collections import defaultdict
import subprocess
import shutil


def _to_int(value, default=0):
    try:
        if value in (None, "", "-"):
            return default
        return int(float(str(value).split(",")[0]))
    except Exception:
        return default


def _to_float(value, default=None):
    try:
        if value in (None, "", "-"):
            return default
        return float(str(value).split(",")[0])
    except Exception:
        return default


def _is_true(value):
    if value is None:
        return False
    v = str(value).strip().lower()
    return v in ("1", "true", "yes", "set")


def _find_pcap(job_id: str):
    result_dir = Path("data/results") / job_id
    if not result_dir.exists():
        return None

    candidates = list(result_dir.glob("*.pcap")) + list(result_dir.glob("*.pcapng"))
    if not candidates:
        return None

    return candidates[0]


def _run_tshark_fields(pcap_path: Path):
    tshark = shutil.which("tshark")
    if not tshark:
        return {
            "ok": False,
            "error": "tshark not found. Install tshark or ensure it is in PATH.",
            "rows": [],
        }

    fields = [
        "frame.number",
        "frame.time_epoch",
        "frame.len",
        "ip.src",
        "ip.dst",
        "ipv6.src",
        "ipv6.dst",
        "ip.len",
        "ip.flags.df",
        "tcp.stream",
        "tcp.srcport",
        "tcp.dstport",
        "tcp.len",
        "tcp.seq",
        "tcp.flags.syn",
        "tcp.flags.ack",
        "tcp.options.mss_val",
        "tcp.analysis.retransmission",
        "tcp.analysis.fast_retransmission",
        "tcp.analysis.out_of_order",
        "icmp.type",
        "icmp.code",
        "icmp.mtu",
        "icmpv6.type",
        "icmpv6.mtu",
        "_ws.col.Info",
    ]

    cmd = [
        tshark,
        "-r",
        str(pcap_path),
        "-Y",
        "tcp or icmp or icmpv6",
        "-T",
        "fields",
        "-E",
        "header=y",
        "-E",
        "separator=\t",
        "-E",
        "occurrence=f",
    ]

    for f in fields:
        cmd.extend(["-e", f])

    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "error": "tshark MTU analysis timed out.",
            "rows": [],
        }

    if proc.returncode != 0:
        return {
            "ok": False,
            "error": proc.stderr.strip() or "tshark failed.",
            "rows": [],
        }

    lines = proc.stdout.splitlines()
    if not lines:
        return {"ok": True, "error": None, "rows": []}

    headers = lines[0].split("\t")
    rows = []

    for line in lines[1:]:
        parts = line.split("\t")
        if len(parts) < len(headers):
            parts += [""] * (len(headers) - len(parts))
        rows.append(dict(zip(headers, parts)))

    return {"ok": True, "error": None, "rows": rows}


def analyze_mtu_for_job(job_id: str):
    pcap_path = _find_pcap(job_id)

    if not pcap_path:
        return {
            "job_id": job_id,
            "status": "no_pcap",
            "summary": {
                "mtu_health": "unknown",
                "reason": "No original PCAP/PCAPNG file found in result directory.",
            },
            "streams": [],
            "icmp_frag_needed_events": [],
        }

    result = _run_tshark_fields(pcap_path)
    if not result["ok"]:
        return {
            "job_id": job_id,
            "status": "error",
            "summary": {
                "mtu_health": "unknown",
                "reason": result["error"],
            },
            "streams": [],
            "icmp_frag_needed_events": [],
        }

    rows = result["rows"]

    streams = defaultdict(lambda: {
        "tcp_stream_id": None,
        "endpoint_a": None,
        "endpoint_b": None,
        "packet_count": 0,
        "max_frame_len": 0,
        "max_ip_len": 0,
        "max_tcp_payload": 0,
        "realistic_max_tcp_payload": 0,
        "offload_artifact_suspected": False,
        "mss_clamping_detected": False,
        "effective_path_mss": None,
        "df_packet_count": 0,
        "large_df_packet_count": 0,
        "large_tcp_payload_count": 0,
        "large_retransmission_count": 0,
        "retransmission_count": 0,
        "out_of_order_count": 0,
        "client_mss": None,
        "server_mss": None,
        "mss_values": [],
        "sample_frames": [],
    })

    icmp_frag_needed_events = []

    for r in rows:
        frame_no = _to_int(r.get("frame.number"))
        time_epoch = _to_float(r.get("frame.time_epoch"))
        frame_len = _to_int(r.get("frame.len"))
        ip_len = _to_int(r.get("ip.len"))
        tcp_len = _to_int(r.get("tcp.len"))
        stream_id = r.get("tcp.stream")
        info = r.get("_ws.col.Info") or ""

        src = r.get("ip.src") or r.get("ipv6.src") or ""
        dst = r.get("ip.dst") or r.get("ipv6.dst") or ""
        sport = r.get("tcp.srcport") or ""
        dport = r.get("tcp.dstport") or ""

        icmp_type = r.get("icmp.type")
        icmp_code = r.get("icmp.code")
        icmp_mtu = r.get("icmp.mtu")
        icmpv6_type = r.get("icmpv6.type")
        icmpv6_mtu = r.get("icmpv6.mtu")

        # IPv4 ICMP type 3 code 4 = Fragmentation needed and DF set
        if str(icmp_type) == "3" and str(icmp_code) == "4":
            icmp_frag_needed_events.append({
                "frame": frame_no,
                "time_epoch": time_epoch,
                "src": src,
                "dst": dst,
                "mtu": _to_int(icmp_mtu, None),
                "type": "icmp_fragmentation_needed",
                "interpretation": "ICMP Fragmentation Needed observed. This is direct evidence of a path MTU problem or PMTUD event.",
                "info": info,
            })

        # ICMPv6 type 2 = Packet Too Big
        if str(icmpv6_type) == "2":
            icmp_frag_needed_events.append({
                "frame": frame_no,
                "time_epoch": time_epoch,
                "src": src,
                "dst": dst,
                "mtu": _to_int(icmpv6_mtu, None),
                "type": "icmpv6_packet_too_big",
                "interpretation": "ICMPv6 Packet Too Big observed. This is direct evidence of a path MTU problem or PMTUD event.",
                "info": info,
            })

        if stream_id in (None, ""):
            continue

        s = streams[stream_id]
        s["tcp_stream_id"] = stream_id
        s["packet_count"] += 1

        if not s["endpoint_a"] and src and sport:
            s["endpoint_a"] = f"{src}:{sport}"
        if not s["endpoint_b"] and dst and dport:
            s["endpoint_b"] = f"{dst}:{dport}"

        s["max_frame_len"] = max(s["max_frame_len"], frame_len)
        s["max_ip_len"] = max(s["max_ip_len"], ip_len)
        s["max_tcp_payload"] = max(s["max_tcp_payload"], tcp_len)

        # Very large packet sizes in endpoint captures can be TSO/GSO/LRO offload artifacts.
        # Keep the raw max, but use realistic_max_tcp_payload for MTU classification.
        if tcp_len > 9000 or ip_len > 9000 or frame_len > 9018:
            s["offload_artifact_suspected"] = True
        elif tcp_len > 0:
            s["realistic_max_tcp_payload"] = max(s["realistic_max_tcp_payload"], tcp_len)

        df_set = _is_true(r.get("ip.flags.df"))
        retrans = _is_true(r.get("tcp.analysis.retransmission")) or _is_true(r.get("tcp.analysis.fast_retransmission"))
        out_of_order = _is_true(r.get("tcp.analysis.out_of_order"))

        if df_set:
            s["df_packet_count"] += 1

        if df_set and ip_len >= 1400:
            s["large_df_packet_count"] += 1

        if tcp_len >= 1200:
            s["large_tcp_payload_count"] += 1

        if retrans:
            s["retransmission_count"] += 1

        if out_of_order:
            s["out_of_order_count"] += 1

        if retrans and df_set and (ip_len >= 1400 or tcp_len >= 1200):
            s["large_retransmission_count"] += 1
            if len(s["sample_frames"]) < 10:
                s["sample_frames"].append({
                    "frame": frame_no,
                    "time_epoch": time_epoch,
                    "ip_len": ip_len,
                    "tcp_payload": tcp_len,
                    "info": info,
                })

        mss = _to_int(r.get("tcp.options.mss_val"), None)
        syn = _is_true(r.get("tcp.flags.syn"))
        ack = _is_true(r.get("tcp.flags.ack"))

        if mss and syn:
            s["mss_values"].append(mss)
            if not ack and s["client_mss"] is None:
                s["client_mss"] = mss
            elif ack and s["server_mss"] is None:
                s["server_mss"] = mss

    stream_results = []

    for stream_id, s in streams.items():
        health = "ok"
        confidence = "low"
        evidence = []
        action = []

        mss_candidates = [m for m in [s.get("client_mss"), s.get("server_mss")] if isinstance(m, int) and m > 0]
        effective_mss = min(mss_candidates) if mss_candidates else None
        s["effective_path_mss"] = effective_mss

        if effective_mss and effective_mss < 1400:
            s["mss_clamping_detected"] = True

        realistic_payload = s.get("realistic_max_tcp_payload") or 0

        # If captured payload is much larger than negotiated/effective MSS, it is likely
        # capture-side segmentation offload/coalescing rather than a real on-wire MTU packet.
        if effective_mss and realistic_payload > (effective_mss * 2):
            s["offload_artifact_suspected"] = True
            s["payload_vs_effective_mss_ratio"] = round(realistic_payload / effective_mss, 2)
            realistic_payload_for_classification = effective_mss
        else:
            s["payload_vs_effective_mss_ratio"] = None
            realistic_payload_for_classification = realistic_payload

        if icmp_frag_needed_events:
            health = "confirmed_mtu_issue"
            confidence = "high"
            evidence.append("ICMP Fragmentation Needed / Packet Too Big messages were observed in the capture.")
            action.append("Check path MTU, tunnel overhead, firewall ICMP handling, and PMTUD behavior.")

        elif s["mss_clamping_detected"] and s["retransmission_count"] >= 3:
            health = "mss_clamped_path_with_retransmissions"
            confidence = "medium"
            evidence.append(
                f"MSS/path-MTU adjustment is visible: effective MSS is {effective_mss}. Retransmissions are present, but MSS clamping suggests the path is already avoiding full-size 1460-byte payloads."
            )
            action.append("Investigate packet loss/congestion on the adjusted-MSS path first. Also verify MSS clamping policy is expected for VPN/SD-WAN/Zscaler/tunnel path.")

        elif s["large_retransmission_count"] >= 3 and s["large_df_packet_count"] >= 3:
            health = "probable_mtu_blackhole"
            confidence = "medium"
            evidence.append(
                f"Large DF-set TCP packets were retransmitted {s['large_retransmission_count']} times without visible ICMP Fragmentation Needed."
            )
            action.append("Validate PMTUD blackhole, ICMP filtering, tunnel overhead, and MSS clamping.")

        elif s["large_df_packet_count"] >= 3 and s["retransmission_count"] >= 3:
            health = "possible_mtu_issue"
            confidence = "low"
            evidence.append(
                f"Stream has {s['large_df_packet_count']} large DF-set packets and {s['retransmission_count']} retransmissions."
            )
            action.append("Check packet size, DF bit, retransmission pattern, and path MTU.")

        elif realistic_payload_for_classification >= 1400 and s["retransmission_count"] >= 3:
            health = "possible_mtu_issue"
            confidence = "low"
            evidence.append(
                f"Stream has realistic TCP payloads up to {realistic_payload_for_classification} bytes and retransmissions."
            )
            action.append("Check MSS clamping and path MTU, especially across VPN/SD-WAN/Zscaler/tunnel paths.")

        if s["offload_artifact_suspected"]:
            ratio = s.get("payload_vs_effective_mss_ratio")
            ratio_text = f", about {ratio}x effective MSS" if ratio else ""
            evidence.append(
                f"Large captured packet sizes were seen, max_tcp_payload={s['max_tcp_payload']}{ratio_text}. This may be TSO/GSO/LRO or packet coalescing artifact, so raw max packet size is not treated as direct MTU evidence."
            )

        if s["client_mss"] and s["client_mss"] >= 1460:
            evidence.append(f"Client MSS is {s['client_mss']}, consistent with Ethernet MTU 1500.")
        elif s["client_mss"]:
            evidence.append(f"Client MSS is {s['client_mss']}, suggesting MSS adjustment or tunnel-aware path.")

        if s["server_mss"] and s["server_mss"] < 1400:
            evidence.append(f"Server MSS is {s['server_mss']}, indicating MSS clamping or lower path MTU on the return/server side.")

        if not evidence:
            evidence.append("No strong MTU/PMTUD evidence found for this stream.")

        stream_results.append({
            **s,
            "mtu_health": health,
            "mtu_confidence": confidence,
            "mtu_evidence": " ".join(evidence),
            "mtu_engineer_action": " ".join(action) if action else "No MTU-specific action required from current evidence.",
        })

    priority = {
        "confirmed_mtu_issue": 0,
        "probable_mtu_blackhole": 1,
        "mss_clamped_path_with_retransmissions": 2,
        "possible_mtu_issue": 3,
        "ok": 4,
    }

    stream_results.sort(
        key=lambda x: (
            priority.get(x["mtu_health"], 9),
            -x["large_retransmission_count"],
            -x["retransmission_count"],
            -x["max_ip_len"],
        )
    )

    confirmed = sum(1 for s in stream_results if s["mtu_health"] == "confirmed_mtu_issue")
    probable = sum(1 for s in stream_results if s["mtu_health"] == "probable_mtu_blackhole")
    mss_clamped = sum(1 for s in stream_results if s["mtu_health"] == "mss_clamped_path_with_retransmissions")
    possible = sum(1 for s in stream_results if s["mtu_health"] == "possible_mtu_issue")

    if confirmed:
        mtu_health = "confirmed_mtu_issue"
        summary_text = "Confirmed MTU/PMTUD evidence found through ICMP Fragmentation Needed or Packet Too Big messages."
    elif probable:
        mtu_health = "probable_mtu_blackhole"
        summary_text = "Probable PMTUD blackhole behavior found: large DF packets retransmit without visible ICMP Fragmentation Needed."
    elif mss_clamped:
        mtu_health = "mss_clamped_path_with_retransmissions"
        summary_text = "MSS/path-MTU adjustment is visible on multiple streams, with retransmissions. This suggests an adjusted tunnel/proxy path with packet loss, not necessarily a PMTUD blackhole."
    elif possible:
        mtu_health = "possible_mtu_issue"
        summary_text = "Possible MTU issue found in some streams, but evidence is not conclusive."
    else:
        mtu_health = "no_clear_mtu_issue"
        summary_text = "No clear MTU/PMTUD issue detected from available packet evidence."

    return {
        "job_id": job_id,
        "status": "ok",
        "pcap_file": str(pcap_path),
        "summary": {
            "mtu_health": mtu_health,
            "summary": summary_text,
            "total_tcp_streams_analyzed": len(stream_results),
            "confirmed_mtu_streams": confirmed,
            "probable_mtu_blackhole_streams": probable,
            "mss_clamped_path_with_retransmissions_streams": mss_clamped,
            "possible_mtu_issue_streams": possible,
            "icmp_frag_needed_count": len(icmp_frag_needed_events),
            "top_mtu_streams": stream_results[:10],
        },
        "streams": stream_results,
        "icmp_frag_needed_events": icmp_frag_needed_events,
    }
