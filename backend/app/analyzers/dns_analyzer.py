from collections import defaultdict
from datetime import datetime, timezone
from typing import Any


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _to_utc(ts: Any):
    try:
        val = float(ts)
        return datetime.fromtimestamp(val, tz=timezone.utc).isoformat()
    except Exception:
        return None


def analyze_dns_packets(packets: list[dict]) -> list[dict]:
    findings: list[dict] = []
    if not packets:
        return findings

    dns_packets = []
    for p in packets:
        proto = str(p.get("protocol") or p.get("_ws.col.Protocol") or "").upper()
        if "DNS" in proto:
            dns_packets.append(p)

    if not dns_packets:
        return findings

    queries_by_key: dict[tuple, list[dict]] = defaultdict(list)
    responses_by_key: dict[tuple, list[dict]] = defaultdict(list)

    nxdomain_packets: list[dict] = []
    servfail_packets: list[dict] = []
    slow_responses: list[dict] = []
    query_name_counts: dict[str, int] = defaultdict(int)

    for p in dns_packets:
        dns_id = p.get("dns_id")
        qname = p.get("dns_qry_name") or p.get("query_name") or p.get("info") or "-"
        qtype = p.get("dns_qry_type") or "-"
        src = p.get("src") or p.get("ip_src") or "-"
        dst = p.get("dst") or p.get("ip_dst") or "-"
        ts = _safe_float(p.get("time") or p.get("timestamp") or 0.0)
        is_response = str(p.get("dns_flags_response") or "").lower() in {"1", "true", "yes"}
        rcode = _safe_int(p.get("dns_flags_rcode"), 0)
        frame = p.get("frame") or p.get("number")

        key = (dns_id, qname, qtype, src, dst)
        reverse_key = (dns_id, qname, qtype, dst, src)

        packet_info = {
            "timestamp": ts,
            "src": src,
            "dst": dst,
            "qname": str(qname),
            "qtype": qtype,
            "frame": frame,
            "rcode": rcode,
            "raw": p,
        }

        if is_response:
            responses_by_key[reverse_key].append(packet_info)
            if rcode == 3:
                nxdomain_packets.append(packet_info)
            elif rcode == 2:
                servfail_packets.append(packet_info)
        else:
            queries_by_key[key].append(packet_info)
            query_name_counts[str(qname)] += 1

    unanswered_queries: list[dict] = []
    matched_latencies: list[float] = []

    for key, queries in queries_by_key.items():
        responses = sorted(responses_by_key.get(key, []), key=lambda x: x["timestamp"])
        for q in sorted(queries, key=lambda x: x["timestamp"]):
            matched = None
            for r in responses:
                if r["timestamp"] >= q["timestamp"]:
                    matched = r
                    break
            if matched is None:
                unanswered_queries.append(q)
            else:
                latency_ms = round((matched["timestamp"] - q["timestamp"]) * 1000, 3)
                matched_latencies.append(latency_ms)
                if latency_ms >= 500:
                    slow_responses.append({
                        "qname": q["qname"],
                        "src": q["src"],
                        "dst": q["dst"],
                        "latency_ms": latency_ms,
                        "query_frame": q["frame"],
                        "response_frame": matched["frame"],
                        "timestamp": q["timestamp"],
                    })

    repeated_queries = [
        {"qname": qname, "count": count}
        for qname, count in query_name_counts.items()
        if count >= 3
    ]
    repeated_queries.sort(key=lambda x: x["count"], reverse=True)

    def _top_frames(items: list[dict], limit: int = 5) -> list[Any]:
        result = []
        for x in items[:limit]:
            frame = x.get("frame") or x.get("query_frame")
            if frame is not None:
                result.append(frame)
        return result

    def _first_seen(items: list[dict]):
        return min((x["timestamp"] for x in items), default=None)

    def _last_seen(items: list[dict]):
        return max((x["timestamp"] for x in items), default=None)

    if unanswered_queries:
        first_seen = _first_seen(unanswered_queries)
        last_seen = _last_seen(unanswered_queries)
        count = len(unanswered_queries)
        findings.append({
            "type": "dns_issue",
            "severity": "high" if count >= 5 else "medium",
            "category": "dns",
            "title": "Unanswered DNS queries detected",
            "description": (
                "Some DNS queries did not receive responses. This may indicate "
                "resolver unreachability, filtering, packet loss, or DNS service issues."
            ),
            "affected_streams": count,
            "confidence": round(min(0.95, 0.58 + (count * 0.03)), 2),
            "summary": f"{count} DNS queries had no matching response.",
            "directional_hint": "Client -> Resolver",
            "impact_hint": "Name resolution failure likely delayed or blocked application connectivity",
            "recommended_actions": [
                "Check DNS resolver reachability and service health",
                "Validate firewall or ACL rules for DNS",
                "Inspect packet loss between client and resolver",
            ],
            "evidence_frames": _top_frames(unanswered_queries),
            "top_qnames": list({x['qname'] for x in unanswered_queries[:5]}),
            "first_seen": first_seen,
            "last_seen": last_seen,
            "first_seen_utc": _to_utc(first_seen),
            "last_seen_utc": _to_utc(last_seen),
        })

    if nxdomain_packets:
        first_seen = _first_seen(nxdomain_packets)
        last_seen = _last_seen(nxdomain_packets)
        count = len(nxdomain_packets)
        findings.append({
            "type": "dns_issue",
            "severity": "medium",
            "category": "dns",
            "title": "NXDOMAIN responses observed",
            "description": (
                "Some DNS lookups returned NXDOMAIN, indicating the requested "
                "name does not exist or the query path is incorrect."
            ),
            "affected_streams": count,
            "confidence": 0.8,
            "summary": f"{count} DNS responses returned NXDOMAIN.",
            "directional_hint": "Resolver -> Client",
            "impact_hint": "Application may fail before connection setup due to invalid or unresolved hostnames",
            "recommended_actions": [
                "Validate queried hostnames and search domains",
                "Check split-DNS / internal DNS behavior",
                "Confirm application is requesting the correct FQDN",
            ],
            "first_seen": first_seen,
            "last_seen": last_seen,
            "first_seen_utc": _to_utc(first_seen),
            "last_seen_utc": _to_utc(last_seen),
        })

    if servfail_packets:
        first_seen = _first_seen(servfail_packets)
        last_seen = _last_seen(servfail_packets)
        count = len(servfail_packets)
        findings.append({
            "type": "dns_issue",
            "severity": "high" if count >= 3 else "medium",
            "category": "dns",
            "title": "SERVFAIL responses observed",
            "description": (
                "Some DNS lookups returned SERVFAIL, suggesting resolver-side "
                "processing problems or upstream resolution failure."
            ),
            "affected_streams": count,
            "confidence": 0.84,
            "summary": f"{count} DNS responses returned SERVFAIL.",
            "directional_hint": "Resolver -> Client",
            "impact_hint": "Resolution path instability likely affected application setup",
            "recommended_actions": [
                "Check resolver logs and upstream forwarders",
                "Validate recursion / forwarding health",
                "Inspect DNS infrastructure for backend failures",
            ],
            "first_seen": first_seen,
            "last_seen": last_seen,
            "first_seen_utc": _to_utc(first_seen),
            "last_seen_utc": _to_utc(last_seen),
        })

    if slow_responses:
        first_seen = _first_seen(slow_responses)
        last_seen = _last_seen(slow_responses)
        count = len(slow_responses)
        findings.append({
            "type": "dns_issue",
            "severity": "medium",
            "category": "dns",
            "title": "Slow DNS responses detected",
            "description": (
                "Some DNS queries completed but with high latency, which can delay "
                "application connectivity and appear as app slowness."
            ),
            "affected_streams": count,
            "confidence": 0.78,
            "summary": f"{count} DNS responses exceeded 500 ms.",
            "directional_hint": "Client <-> Resolver",
            "impact_hint": "Application slowness may be caused by delayed name resolution",
            "recommended_actions": [
                "Check resolver performance and backend dependency latency",
                "Compare response times across resolvers",
                "Inspect path latency between clients and resolvers",
            ],
            "evidence_frames": _top_frames(slow_responses),
            "first_seen": first_seen,
            "last_seen": last_seen,
            "first_seen_utc": _to_utc(first_seen),
            "last_seen_utc": _to_utc(last_seen),
        })

    if repeated_queries:
        findings.append({
            "type": "dns_issue",
            "severity": "low",
            "category": "dns",
            "title": "Repeated DNS queries observed",
            "description": (
                "The same DNS names were queried repeatedly, which can indicate "
                "retry behavior, timeouts, or application retry loops."
            ),
            "affected_streams": sum(x["count"] for x in repeated_queries),
            "confidence": 0.68,
            "summary": f"{len(repeated_queries)} DNS names were queried 3 or more times.",
            "directional_hint": "Client -> Resolver",
            "impact_hint": "Retry behavior may indicate missing responses, timeout, or poor caching",
            "recommended_actions": [
                "Check whether retries are caused by missing or slow DNS responses",
                "Inspect application retry behavior",
                "Review resolver caching effectiveness",
            ],
            "top_qnames": repeated_queries[:5],
        })

    return findings
