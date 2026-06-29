from collections import defaultdict
from datetime import datetime, timezone


def _to_utc(ts):
    try:
        return datetime.fromtimestamp(float(ts), tz=timezone.utc).isoformat()
    except Exception:
        return None


def analyze_tls_packets(packets):
    findings = []

    if not packets:
        return findings

    tls_packets = []
    for p in packets:
        proto = str(p.get("protocol") or p.get("_ws.col.Protocol") or "").upper()
        if "TLS" in proto or "SSL" in proto:
            tls_packets.append(p)

    if not tls_packets:
        return findings

    alerts = []
    handshake_failures = []
    version_map = defaultdict(int)
    sni_missing = 0
    handshake_latencies = []

    flows = defaultdict(list)

    for p in tls_packets:
        src = p.get("src")
        dst = p.get("dst")
        ts = float(p.get("time") or 0)

        flow = (src, dst)
        flows[flow].append((ts, p))

        info = str(p.get("info") or "").lower()

        if "alert" in info:
            alerts.append(p)

        if "handshake failure" in info:
            handshake_failures.append(p)

        version = p.get("tls_version") or p.get("ssl_record_version")
        if version:
            version_map[str(version)] += 1

        if "client hello" in info:
            if "server name" not in info and "sni" not in info:
                sni_missing += 1

    # Detect slow TLS handshakes
    for flow, pkts in flows.items():
        pkts = sorted(pkts, key=lambda x: x[0])
        client_hello = None
        server_hello = None

        for ts, p in pkts:
            info = str(p.get("info") or "").lower()
            if "client hello" in info:
                client_hello = ts
            if "server hello" in info and client_hello:
                server_hello = ts
                latency = (server_hello - client_hello) * 1000
                if latency > 500:
                    handshake_latencies.append(latency)
                break

    if alerts:
        findings.append({
            "type": "tls_issue",
            "category": "tls",
            "severity": "high",
            "title": "TLS alerts detected",
            "confidence": 0.85,
            "summary": f"{len(alerts)} TLS alert packets observed",
            "impact_hint": "TLS negotiation likely failed due to protocol/certificate mismatch"
        })

    if handshake_failures:
        findings.append({
            "type": "tls_issue",
            "category": "tls",
            "severity": "high",
            "title": "TLS handshake failures detected",
            "confidence": 0.9,
            "summary": f"{len(handshake_failures)} handshake failures observed",
            "impact_hint": "Client and server could not agree on TLS parameters"
        })

    if len(version_map) > 1:
        findings.append({
            "type": "tls_issue",
            "category": "tls",
            "severity": "medium",
            "title": "TLS version mismatch observed",
            "confidence": 0.75,
            "summary": f"Multiple TLS versions detected: {dict(version_map)}",
            "impact_hint": "Version negotiation mismatch may cause connection failures"
        })

    if sni_missing > 0:
        findings.append({
            "type": "tls_issue",
            "category": "tls",
            "severity": "medium",
            "title": "Missing SNI in TLS Client Hello",
            "confidence": 0.7,
            "summary": f"{sni_missing} Client Hello packets without SNI",
            "impact_hint": "Virtual hosting may fail without SNI"
        })

    if handshake_latencies:
        findings.append({
            "type": "tls_issue",
            "category": "tls",
            "severity": "medium",
            "title": "Slow TLS handshakes detected",
            "confidence": 0.78,
            "summary": f"{len(handshake_latencies)} handshakes exceeded 500 ms",
            "impact_hint": "TLS negotiation latency may impact application performance"
        })

    return findings
