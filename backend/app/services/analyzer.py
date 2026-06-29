import json
from collections import Counter, defaultdict
from pathlib import Path
from app.core.paths import DATA_DIR

from scapy.all import rdpcap, LLC, STP, Raw, DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP, LLC, STP
from scapy.layers.inet6 import IPv6
from app.analyzers.dns_analyzer import analyze_dns_packets
from app.analyzers.tls_analyzer import analyze_tls_packets

BASE_DIR = DATA_DIR
RESULTS_DIR = BASE_DIR / "results"


def sanitize_for_json(value):
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="ignore")
        except Exception:
            return value.hex()

    if isinstance(value, dict):
        return {str(k): sanitize_for_json(v) for k, v in value.items()}

    if isinstance(value, (list, tuple, set)):
        return [sanitize_for_json(v) for v in value]

    return value

RESULTS_DIR.mkdir(parents=True, exist_ok=True)



STP_DST_MACS = {
    "01:80:c2:00:00:00",  # IEEE STP/RSTP/MST
    "01:00:0c:cc:cc:cd",  # Cisco PVST+/RPVST+/UplinkFast
    "01:00:0c:cc:cc:ce",  # Cisco shared STP variants seen in some captures
}

def stp_packet_metadata(pkt):
    try:
        src_mac = None
        dst_mac = None

        if pkt.haslayer(Ether):
            try:
                src_mac = str(pkt[Ether].src).lower()
            except Exception:
                src_mac = None
            try:
                dst_mac = str(pkt[Ether].dst).lower()
            except Exception:
                dst_mac = None

        llc_bpdu = False
        if pkt.haslayer(LLC):
            try:
                dsap = getattr(pkt[LLC], "dsap", None)
                ssap = getattr(pkt[LLC], "ssap", None)
                llc_bpdu = (dsap == 0x42 and ssap == 0x42)
            except Exception:
                llc_bpdu = False

        family = None

        if pkt.haslayer(STP):
            family = "stp"
        elif dst_mac == "01:80:c2:00:00:00" or llc_bpdu:
            family = "stp"
        elif dst_mac in {"01:00:0c:cc:cc:cd", "01:00:0c:cc:cc:ce"}:
            family = "cisco_pvst"
        else:
            return None

        root_id = None
        root_mac = None

        if pkt.haslayer(STP):
            try:
                root_id = getattr(pkt[STP], "rootid", None)
            except Exception:
                root_id = None
            try:
                root_mac = getattr(pkt[STP], "rootmac", None)
            except Exception:
                root_mac = None

        return {
            "family": family,
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "root_id": root_id,
            "root_mac": root_mac,
        }
    except Exception:
        return None

def detect_protocol(pkt) -> str:
    try:
        if stp_packet_metadata(pkt):
            return "STP"
        if pkt.haslayer(TCP):
            return "TCP"
        if pkt.haslayer(UDP):
            return "UDP"
        if pkt.haslayer(ICMP):
            return "ICMP"
        if pkt.haslayer("ARP"):
            return "ARP"
        if pkt.haslayer(IP):
            return "IP"
        if pkt.haslayer(IPv6):
            return "IPv6"
        return "OTHER"
    except Exception:
        return "OTHER"

def extract_ip_addresses(pkt):
    src_ip = None
    dst_ip = None

    if pkt.haslayer(IP):
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
    elif pkt.haslayer(IPv6):
        src_ip = pkt[IPv6].src
        dst_ip = pkt[IPv6].dst

    return src_ip, dst_ip


def get_transport_ports(pkt):
    src_port = None
    dst_port = None

    if pkt.haslayer(TCP):
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
    elif pkt.haslayer(UDP):
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport

    return src_port, dst_port


def make_stream_key(src_ip, src_port, dst_ip, dst_port, proto):
    left = (src_ip or "", src_port or 0)
    right = (dst_ip or "", dst_port or 0)
    ordered = tuple(sorted([left, right], key=lambda x: (str(x[0]), int(x[1]))))
    return f"{proto}|{ordered[0][0]}:{ordered[0][1]}|{ordered[1][0]}:{ordered[1][1]}"


def try_extract_tls_sni_from_payload(payload: bytes):
    """
    Best-effort TLS ClientHello SNI parser.
    Returns hostname string or None.
    """
    try:
        if not payload or len(payload) < 10:
            return None

        # TLS record type: Handshake (22 / 0x16)
        if payload[0] != 0x16:
            return None

        # Need at least TLS record header
        if len(payload) < 5:
            return None

        record_len = int.from_bytes(payload[3:5], "big")
        if len(payload) < 5 + record_len:
            # best-effort, may still continue if partial record contains enough
            pass

        # Handshake type: ClientHello (1)
        if len(payload) < 6 or payload[5] != 0x01:
            return None

        # Skip TLS record header (5) + handshake type (1) + handshake length (3)
        p = 9

        # Client version (2)
        if len(payload) < p + 2:
            return None
        p += 2

        # Random (32)
        if len(payload) < p + 32:
            return None
        p += 32

        # Session ID
        if len(payload) < p + 1:
            return None
        session_id_len = payload[p]
        p += 1 + session_id_len

        # Cipher suites
        if len(payload) < p + 2:
            return None
        cipher_suites_len = int.from_bytes(payload[p:p+2], "big")
        p += 2 + cipher_suites_len

        # Compression methods
        if len(payload) < p + 1:
            return None
        comp_methods_len = payload[p]
        p += 1 + comp_methods_len

        # Extensions length
        if len(payload) < p + 2:
            return None
        extensions_len = int.from_bytes(payload[p:p+2], "big")
        p += 2

        end_ext = min(len(payload), p + extensions_len)

        while p + 4 <= end_ext:
            ext_type = int.from_bytes(payload[p:p+2], "big")
            ext_len = int.from_bytes(payload[p+2:p+4], "big")
            p += 4

            if p + ext_len > len(payload):
                return None

            # server_name extension
            if ext_type == 0x0000:
                ext_data = payload[p:p+ext_len]

                # server_name_list length (2)
                if len(ext_data) < 2:
                    return None

                q = 2
                while q + 3 <= len(ext_data):
                    name_type = ext_data[q]
                    name_len = int.from_bytes(ext_data[q+1:q+3], "big")
                    q += 3

                    if q + name_len > len(ext_data):
                        return None

                    if name_type == 0:
                        server_name = ext_data[q:q+name_len].decode("utf-8", errors="ignore").strip()
                        return server_name or None

                    q += name_len

            p += ext_len

        return None

    except Exception:
        return None



def identify_application(sni, endpoint_a_port, endpoint_b_port, protocol):
    if protocol != "TCP":
        if endpoint_a_port == 53 or endpoint_b_port == 53:
            return "DNS"
        return "Unknown"

    port_candidates = {endpoint_a_port, endpoint_b_port}

    if sni:
        sni_l = sni.lower()

        if "wbx2.com" in sni_l or "webex" in sni_l:
            return "Cisco Webex"
        if "microsoft.com" in sni_l or "office.com" in sni_l or "office365" in sni_l or "teams" in sni_l:
            return "Microsoft 365"
        if "google" in sni_l or "gstatic" in sni_l or "googleapis" in sni_l:
            return "Google"
        if "amazonaws.com" in sni_l or ".aws." in sni_l:
            return "AWS"
        if "zoom" in sni_l:
            return "Zoom"
        if "facebook" in sni_l or "whatsapp" in sni_l or "meta" in sni_l:
            return "Meta"
        if "cloudflare" in sni_l:
            return "Cloudflare"
        if "okta" in sni_l:
            return "Okta"
        if "slack" in sni_l:
            return "Slack"
        if "github" in sni_l:
            return "GitHub"
        if "cisco" in sni_l:
            return "Cisco"

        if 443 in port_candidates:
            return "HTTPS"
        return "TCP App"

    if 443 in port_candidates:
        return "HTTPS (Unknown)"
    if 80 in port_candidates:
        return "HTTP"
    if 22 in port_candidates:
        return "SSH"
    if 25 in port_candidates or 587 in port_candidates:
        return "SMTP"
    if 993 in port_candidates:
        return "IMAPS"
    if 995 in port_candidates:
        return "POP3S"
    if 53 in port_candidates:
        return "DNS"
    if 3389 in port_candidates:
        return "RDP"
    if 3306 in port_candidates:
        return "MySQL"
    if 5432 in port_candidates:
        return "PostgreSQL"

    return "Unknown"


def analyze_pcap(job_id: str, filename: str, file_path: str) -> dict:
    packets = rdpcap(file_path)
    packets = sorted(packets, key=lambda p: float(p.time))

    total_packets = len(packets)
    total_bytes = 0
    protocol_counter = Counter()
    src_counter = Counter()
    dst_counter = Counter()

    start_time = None
    end_time = None

    for pkt in packets:
        pkt_len = len(pkt)
        total_bytes += pkt_len

        pkt_time = float(pkt.time)
        if start_time is None:
            start_time = pkt_time
        end_time = pkt_time

        proto = detect_protocol(pkt)
        # STP classification patch
        try:
            is_stp = pkt.haslayer(STP) or (
                pkt.haslayer(LLC)
                and pkt.haslayer(Ether)
                and str(pkt[Ether].dst).lower().startswith("01:80:c2")
            )
            if is_stp:
                proto = "STP"
        except Exception:
            pass
        protocol_counter[proto] += 1

        src_ip, dst_ip = extract_ip_addresses(pkt)
        # STP classification after extract_ip_addresses
        proto = "STP" if (
            pkt.haslayer(STP)
            or (
                pkt.haslayer(LLC)
                and pkt.haslayer(Ether)
                and str(pkt[Ether].dst).lower().startswith("01:80:c2")
            )
        ) else detect_protocol(pkt)
        if src_ip:
            src_counter[src_ip] += 1
        if dst_ip:
            dst_counter[dst_ip] += 1

    duration_seconds = 0.0
    if start_time is not None and end_time is not None:
        duration_seconds = round(end_time - start_time, 6)

    summary = {
        "job_id": job_id,
        "filename": filename,
        "status": "completed",
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "duration_seconds": duration_seconds,
        "start_time": start_time,
        "end_time": end_time,
        "protocols": dict(protocol_counter.most_common()),
        "top_src_ips": dict(src_counter.most_common(10)),
        "top_dst_ips": dict(dst_counter.most_common(10)),
    }

    result_dir = RESULTS_DIR / job_id
    result_dir.mkdir(parents=True, exist_ok=True)

    summary_file = result_dir / "summary.json"
    with open(summary_file, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    extract_packets(job_id, packets)
    streams = extract_streams(job_id, packets)
    save_findings(job_id, streams)
    save_root_causes(job_id, streams)
    save_root_causes_v2(job_id, streams)
    save_timeline_analysis(job_id, streams)

    return summary


def extract_packets(job_id: str, packets):
    packet_list = []

    sorted_packets = sorted(packets, key=lambda p: float(p.time))
    base_time = None

    for i, pkt in enumerate(sorted_packets):
        pkt_time = float(pkt.time)

        if base_time is None:
            base_time = pkt_time

        rel_time = round(pkt_time - base_time, 6)
        length = len(pkt)

        src_ip, dst_ip = extract_ip_addresses(pkt)
        proto = detect_protocol(pkt)

        info = ""
        payload = None
        payload_text = None
        try:
            if pkt.haslayer(Raw):
                raw_bytes = bytes(pkt[Raw].load)
                payload = raw_bytes[:2048].hex()
                payload_text = raw_bytes[:2048].decode("utf-8", errors="ignore")
                if payload_text:
                    payload_text = payload_text.replace("\x00", "")
        except Exception:
            payload = None
            payload_text = None

        if proto == "STP":
            stp_meta = stp_packet_metadata(pkt)
            if stp_meta:
                if stp_meta.get("root_id") is not None and stp_meta.get("root_mac"):
                    info = f"Conf. Root = {stp_meta['root_id']}/{stp_meta['root_mac']}"
                elif stp_meta.get("family") == "cisco_pvst":
                    info = "Cisco PVST+/RPVST+/UplinkFast BPDU"
                else:
                    info = "STP BPDU"

                if src_ip is None:
                    src_ip = stp_meta.get("src_mac")
                if dst_ip is None:
                    dst_ip = stp_meta.get("dst_mac")


        # ---- HTTP detection ----
        try:
            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw]).decode(errors="ignore")

                lines = payload.split("\r\n")
                if lines:
                    first_line = lines[0]

                    if first_line.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ")):
                        proto = "HTTP"
                        info = first_line[:100]

                        for line in lines:
                            if line.lower().startswith("host:"):
                                info += " | " + line.strip()
                                break

                    elif first_line.startswith("HTTP/"):
                        proto = "HTTP"
                        info = first_line[:100]

        except Exception:
            pass

        # ---- DNS detection ----
        if pkt.haslayer(UDP) and (pkt[UDP].sport == 53 or pkt[UDP].dport == 53):
            info = "DNS"
        elif pkt.haslayer(TCP) and (pkt[TCP].sport == 53 or pkt[TCP].dport == 53):
            info = "DNS"

        # ---- TLS detection ----
        elif pkt.haslayer(TCP):
            try:
                payload = bytes(pkt[TCP].payload)
                if len(payload) >= 3:
                    content_type = payload[0]
                    version_major = payload[1]

                    if content_type in (20, 21, 22, 23) and version_major == 3:
                        if content_type == 22:
                            info = "TLS Handshake"
                        elif content_type == 23:
                            info = "TLS Application Data"
                        else:
                            info = "TLS"
                    else:
                        info = f"TCP Flags: {pkt[TCP].flags}"
                else:
                    info = f"TCP Flags: {pkt[TCP].flags}"
            except Exception:
                info = f"TCP Flags: {pkt[TCP].flags}"

        # ---- Existing fallback ----
        elif pkt.haslayer(TCP):
            info = f"TCP Flags: {pkt[TCP].flags}"
        elif pkt.haslayer(UDP):
            info = "UDP"
        elif pkt.haslayer(ICMP):
            info = "ICMP"

        tcp_seq = None
        tcp_ack = None
        tcp_window = None
        src_port = None
        dst_port = None

        if pkt.haslayer(TCP):
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            tcp_seq = int(pkt[TCP].seq)
            tcp_ack = int(pkt[TCP].ack)
            tcp_window = int(pkt[TCP].window)
        elif pkt.haslayer(UDP):
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport

        packet_list.append(sanitize_for_json({
                "frame": i + 1,
                "time": rel_time,
                "src": src_ip,
                "dst": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": proto,
                "length": length,
                "info": info,
            "payload": payload,
            "payload_text": payload_text,
                "tcp_seq": tcp_seq,
                "tcp_ack": tcp_ack,
                "tcp_window": tcp_window,
            }))

    result_dir = RESULTS_DIR / job_id
    result_dir.mkdir(parents=True, exist_ok=True)

    packet_file = result_dir / "packets.json"
    with open(packet_file, "w", encoding="utf-8") as f:
        json.dump(packet_list, f, indent=2)

    return packet_list


def load_packets(job_id: str):
    packet_file = RESULTS_DIR / job_id / "packets.json"
    if not packet_file.exists():
        return None

    with open(packet_file, "r", encoding="utf-8") as f:
        return json.load(f)



TLS_VERSION_MAP = {
    0: "SSL 3.0",
    1: "TLS 1.0",
    2: "TLS 1.1",
    3: "TLS 1.2",
    4: "TLS 1.3",
}

TLS_ALERT_DESCRIPTIONS = {
    0: "close_notify",
    10: "unexpected_message",
    20: "bad_record_mac",
    21: "decryption_failed",
    22: "record_overflow",
    40: "handshake_failure",
    42: "bad_certificate",
    46: "certificate_unknown",
    47: "illegal_parameter",
    48: "unknown_ca",
    49: "access_denied",
    70: "protocol_version",
    71: "insufficient_security",
    80: "internal_error",
    109: "missing_extension",
    110: "unsupported_extension",
    112: "unrecognized_name",
    116: "certificate_required",
    120: "no_application_protocol",
}

def parse_tls_payload(payload: bytes):
    if not payload or len(payload) < 5:
        return None

    content_type = payload[0]
    version_major = payload[1]
    version_minor = payload[2]

    if version_major != 3:
        return None
    if content_type not in (20, 21, 22, 23):
        return None

    meta = {
        "tls_detected": True,
        "tls_version": TLS_VERSION_MAP.get(version_minor, f"TLS 3.{version_minor}"),
        "record_type": {
            20: "change_cipher_spec",
            21: "alert",
            22: "handshake",
            23: "application_data",
        }[content_type],
    }

    if content_type == 21 and len(payload) >= 7:
        level = payload[5]
        desc = payload[6]
        meta["alert_level"] = "fatal" if level == 2 else "warning"
        meta["alert_description"] = TLS_ALERT_DESCRIPTIONS.get(desc, f"alert_{desc}")

    return meta





def interpret_tcp_with_bif(stream):
    max_bif = stream.get("max_bytes_in_flight") or 0
    avg_bif = stream.get("avg_bytes_in_flight") or 0
    retrans = stream.get("retransmission_count") or 0
    dup_ack = stream.get("duplicate_ack_count") or 0
    zero_win = stream.get("zero_window_count") or 0
    throughput = stream.get("throughput_bps") or 0
    rtt = stream.get("handshake_rtt_ms")
    bif_status = stream.get("bif_status") or "unknown"

    efficiency = round(avg_bif / max_bif, 4) if max_bif > 0 else 0

    stream["bif_efficiency"] = efficiency

    if max_bif == 0:
        return (
            "No meaningful data in flight was observed. The stream may be idle, control-only, very short-lived, or the capture may be incomplete."
        )

    if zero_win > 0:
        return (
            "Receiver-limited behavior detected. The receiver advertised zero window, meaning the sender was blocked by receiver-side buffering or slow application reads."
        )

    if retrans > 0 and dup_ack > 0:
        if efficiency < 0.30:
            return (
                "TCP repeatedly builds data in flight but cannot sustain it. Retransmissions and duplicate ACKs confirm packet loss, reordering, or congestion; the low BIF efficiency suggests congestion-window collapse and unstable delivery."
            )
        return (
            "Packet loss or reordering is present, but the stream still sustains some in-flight data. This suggests intermittent loss rather than a complete throughput collapse."
        )

    if bif_status == "ack_missing_or_not_observed" and max_bif > 0:
        return (
            "Data is in flight but ACK progress is not clearly visible. This may indicate capture asymmetry, delayed ACK visibility, or missing reverse-direction packets."
        )

    if max_bif < 5000 and retrans == 0 and zero_win == 0:
        return (
            "Application-limited behavior likely. Bytes in flight stayed low without retransmissions or receiver-window pressure, so the sender/application did not fill the available pipe."
        )

    if efficiency > 0.70 and retrans == 0 and zero_win == 0:
        return (
            "Stable TCP behavior. Data in flight is consistently maintained, indicating efficient use of the available network path."
        )

    if efficiency < 0.30:
        return (
            "Bursty or unstable transmission pattern. The stream reaches a higher BIF briefly but does not sustain it, suggesting application pacing or intermittent network constraints."
        )

    return (
        "Moderate TCP utilization. No dominant limiter is strongly indicated from BIF, retransmission, duplicate ACK, and receiver-window evidence."
    )


def tcp_engineer_action_hint(stream):
    retrans = stream.get("retransmission_count") or 0
    dup_ack = stream.get("duplicate_ack_count") or 0
    zero_win = stream.get("zero_window_count") or 0
    max_bif = stream.get("max_bytes_in_flight") or 0
    avg_bif = stream.get("avg_bytes_in_flight") or 0
    efficiency = (avg_bif / max_bif) if max_bif > 0 else 0

    if zero_win > 0:
        return "Check receiver host CPU, socket buffers, application read rate, and endpoint resource pressure."

    if retrans > 50 or dup_ack > 500:
        return "Check packet drops, QoS policy, WAN congestion, interface errors, wireless loss, or middlebox instability."

    if retrans > 0 or dup_ack > 0:
        return "Check for intermittent packet loss, reordering, or path instability."

    if max_bif < 5000:
        return "Check whether the application is sending enough data, using small requests, or waiting between bursts."

    if efficiency < 0.30:
        return "Check for bursty application behavior or TCP backoff caused by intermittent network constraints."

    return "No immediate TCP transport action indicated from current evidence."



def classify_tcp_limiter(stream):
    if stream.get("protocol") != "TCP":
        return "not_applicable", "Limiter classification applies only to TCP streams.", []

    max_bif = stream.get("max_bytes_in_flight") or 0
    avg_bif = stream.get("avg_bytes_in_flight") or 0
    retrans = stream.get("retransmission_count") or 0
    dup_ack = stream.get("duplicate_ack_count") or 0
    zero_win = stream.get("zero_window_count") or 0
    throughput = stream.get("throughput_bps") or 0
    handshake_rtt = stream.get("handshake_rtt_ms")

    evidence = [
        f"max_bytes_in_flight={max_bif}",
        f"avg_bytes_in_flight={avg_bif}",
        f"retransmissions={retrans}",
        f"duplicate_acks={dup_ack}",
        f"zero_windows={zero_win}",
        f"throughput_bps={throughput}",
    ]

    if zero_win > 0:
        return (
            "receiver_limited",
            "Receiver advertised zero window, suggesting receive-side buffer pressure or slow application reads.",
            evidence,
        )

    if retrans > 0 and dup_ack > 0 and max_bif > 0:
        return (
            "network_loss_or_congestion",
            "Retransmissions and duplicate ACKs occurred while data was in flight, suggesting packet loss, reordering, or congestion.",
            evidence,
        )

    if handshake_rtt is not None and handshake_rtt > 300 and retrans == 0 and zero_win == 0:
        return (
            "setup_latency",
            "TCP setup RTT is high while no strong data-transfer limiter is visible.",
            evidence,
        )

    if max_bif < 4096 and retrans == 0 and zero_win == 0:
        return (
            "application_limited",
            "Bytes in flight stayed very low without loss or receiver-window pressure, suggesting the application/sender did not fill the pipe.",
            evidence,
        )

    if throughput > 0 and max_bif > 65535 and retrans == 0 and zero_win == 0:
        return (
            "healthy_bulk_transfer",
            "Stream kept a meaningful amount of data in flight without obvious loss or receiver pressure.",
            evidence,
        )

    return (
        "inconclusive",
        "No single limiter is strongly indicated from current TCP evidence.",
        evidence,
    )


def extract_streams(job_id: str, packets):
    streams = {}

    sorted_packets = sorted(packets, key=lambda p: float(p.time))
    seen_seq_by_stream_dir = defaultdict(set)
    seen_ack_by_stream_dir = defaultdict(list)
    # ---- Bytes-in-flight tracking ----
    highest_seq_by_dir = defaultdict(int)
    initial_seq_by_dir = {}
    highest_ack_by_dir = defaultdict(int)
    bif_samples_by_stream = defaultdict(list)
    bif_status_by_stream = defaultdict(str)

    for pkt in sorted_packets:
        proto = detect_protocol(pkt)
        if proto == "STP":
            pkt_time = float(pkt.time)
            stp_meta = stp_packet_metadata(pkt) or {}

            family = stp_meta.get("family", "stp")
            root_id = stp_meta.get("root_id")
            root_mac = stp_meta.get("root_mac") or stp_meta.get("dst_mac") or "unknown"
            src_mac = stp_meta.get("src_mac") or "unknown"

            if root_id is None:
                if family == "cisco_pvst":
                    root_id = "pvst"
                else:
                    root_id = "unknown"

            stream_key = f"STP|{family}|root:{root_id}|mac:{root_mac}"

            if stream_key not in streams:
                streams[stream_key] = {
                    "stream_id": stream_key,
                    "protocol": "STP",
                    "endpoint_a_ip": src_mac,
                    "endpoint_a_port": 0,
                    "endpoint_b_ip": root_mac,
                    "endpoint_b_port": 0,
                    "packet_count": 0,
                    "byte_count": 0,
                    "start_time": pkt_time,
                    "end_time": pkt_time,
                    "duration_seconds": 0.0,
                    "packets_a_to_b": 0,
                    "packets_b_to_a": 0,
                    "bytes_a_to_b": 0,
                    "bytes_b_to_a": 0,
                    "tcp_flags_seen": [],
                    "syn_seen": False,
                    "synack_seen": False,
                    "ack_seen": False,
                    "rst_seen": False,
                    "fin_seen": False,
                    "handshake_status": "not_applicable",
                    "stream_health": "control_plane",
                    "notes": [],
                    "retransmission_count": 0,
                    "has_retransmissions": False,
                    "duplicate_ack_count": 0,
                    "zero_window_count": 0,
                    "syn_time": None,
                    "synack_time": None,
                    "handshake_rtt_ms": None,
                    "throughput_bps": 0.0,
                "max_bytes_in_flight": 0,
                "avg_bytes_in_flight": 0,
                "bytes_in_flight_samples": [],
                "first_client_data_time": None,
                "first_server_data_time": None,
                "first_server_data_ms": None,
                "tcp_limiter": "unknown",
                "tcp_limiter_reason": "",
                "tcp_limiter_evidence": [],
                "bif_efficiency": 0,
                "tcp_bif_interpretation": "",
                "tcp_engineer_action_hint": "",
                "tcp_limiter": "unknown",
                "tcp_limiter_reason": "",
                "tcp_limiter_evidence": [],
                "bif_efficiency": 0,
                "tcp_bif_interpretation": "",
                "tcp_engineer_action_hint": "",
                "max_bytes_in_flight": 0,
                "avg_bytes_in_flight": 0,
                "bytes_in_flight_samples": [],
                    "stream_category": "layer2_control_plane",
                    "stream_summary": "Spanning Tree BPDU exchange observed.",
                    "stream_confidence": 0.95,
                    "stream_label": f"{family.upper()} Root {root_id}/{root_mac}",
                    "tls_sni": None,
                    "application": "Spanning Tree",
                }

            stream = streams[stream_key]
            stream["packet_count"] += 1
            stream["byte_count"] += len(pkt)
            stream["end_time"] = pkt_time
            stream["packets_a_to_b"] += 1
            stream["bytes_a_to_b"] += len(pkt)
            continue

        if proto not in {"TCP", "UDP"}:
            continue

        src_ip, dst_ip = extract_ip_addresses(pkt)
        src_port, dst_port = get_transport_ports(pkt)

        if not src_ip or not dst_ip or src_port is None or dst_port is None:
            continue

        stream_key = make_stream_key(src_ip, src_port, dst_ip, dst_port, proto)
        pkt_time = float(pkt.time)
        pkt_len = len(pkt)

        if stream_key not in streams:
            streams[stream_key] = {
                "stream_id": stream_key,
                "protocol": proto,
                "endpoint_a_ip": src_ip,
                "endpoint_a_port": src_port,
                "endpoint_b_ip": dst_ip,
                "endpoint_b_port": dst_port,
                "packet_count": 0,
                "byte_count": 0,
                "start_time": pkt_time,
                "end_time": pkt_time,
                "duration_seconds": 0.0,
                "packets_a_to_b": 0,
                "packets_b_to_a": 0,
                "bytes_a_to_b": 0,
                "bytes_b_to_a": 0,
                "tcp_flags_seen": [],
                "syn_seen": False,
                "synack_seen": False,
                "ack_seen": False,
                "rst_seen": False,
                "fin_seen": False,
                "handshake_status": "unknown",
                "stream_health": "unknown",
                "notes": [],
                "retransmission_count": 0,
                "has_retransmissions": False,
                "duplicate_ack_count": 0,
                "zero_window_count": 0,
                "syn_time": None,
                "synack_time": None,
                "handshake_rtt_ms": None,
                "throughput_bps": 0.0,
                "stream_category": "unknown",
                "stream_summary": "",
                "stream_confidence": 0.0,
                "stream_label": "",
                "tls_sni": None,
                "application": "Unknown",
            }

        stream = streams[stream_key]
        stream["packet_count"] += 1
        stream["byte_count"] += pkt_len
        stream["end_time"] = pkt_time

        if src_ip == stream["endpoint_a_ip"] and src_port == stream["endpoint_a_port"]:
            stream["packets_a_to_b"] += 1
            stream["bytes_a_to_b"] += pkt_len
        else:
            stream["packets_b_to_a"] += 1
            stream["bytes_b_to_a"] += pkt_len

        # TLS SNI extraction (best effort, only once per stream)
        if (
            stream["tls_sni"] is None
            and pkt.haslayer(TCP)
            and (src_port == 443 or dst_port == 443)
        ):
              try:
                payload = bytes(pkt[TCP].payload)
                sni = try_extract_tls_sni_from_payload(payload)
                if sni:
                    stream["tls_sni"] = sni
                    stream["notes"].append(f"TLS SNI observed: {sni}")
              except Exception:
                pass

        if proto == "TCP" and pkt.haslayer(TCP):
            flags_obj = pkt[TCP].flags
            flags = str(flags_obj)

            syn = bool(flags_obj & 0x02)
            ack = bool(flags_obj & 0x10)
            rst = bool(flags_obj & 0x04)
            fin = bool(flags_obj & 0x01)

            seq_num = int(pkt[TCP].seq)
            ack_num = int(pkt[TCP].ack)
            window_size = int(pkt[TCP].window)

            direction_key = f"{stream_key}|{src_ip}:{src_port}->{dst_ip}:{dst_port}"

            # Ensure payload_len always exists

            if pkt[TCP].payload is not None:
                payload_len = len(bytes(pkt[TCP].payload))


            # ---- Bytes-in-flight calculation ----
            if payload_len > 0:
                highest_seq_by_dir[direction_key] = max(
                    highest_seq_by_dir[direction_key],
                    seq_num + payload_len
                )

            reverse_key = f"{stream_key}|{dst_ip}:{dst_port}->{src_ip}:{src_port}"

            if ack:
                highest_ack_by_dir[reverse_key] = max(
                    highest_ack_by_dir[reverse_key],
                    ack_num
                )


            # ---- Normalize using initial sequence numbers ----
            if direction_key not in initial_seq_by_dir:
                initial_seq_by_dir[direction_key] = seq_num
            else:
                initial_seq_by_dir[direction_key] = min(initial_seq_by_dir[direction_key], seq_num)

            seq_base = initial_seq_by_dir[direction_key]

            # ACKs for this direction are in the same sequence space as this direction,
            # so the ACK baseline must use seq_base, not reverse_key.
            seq_max = max(0, highest_seq_by_dir[direction_key] - seq_base)
            ack_max = max(0, highest_ack_by_dir[direction_key] - seq_base)

            bytes_in_flight = max(0, seq_max - ack_max)

            if ack_max == 0 and seq_max > 0:
                bif_status_by_stream[stream_key] = "ack_missing_or_not_observed"
            elif ack_max < seq_max:
                bif_status_by_stream[stream_key] = "unacked_data_in_flight"
            else:
                bif_status_by_stream[stream_key] = "acked_or_idle"

            bif_samples_by_stream[stream_key].append(bytes_in_flight)

            # FIRST_SERVER_DATA_METRIC
            try:
                payload_len_for_ttfb = int(payload_len or 0)
                pkt_time_for_ttfb = float(pkt_time)

                if payload_len_for_ttfb > 0:
                    src_for_ttfb = src_ip
                    client_ip_for_ttfb = stream.get("endpoint_a_ip")
                    server_ip_for_ttfb = stream.get("endpoint_b_ip")

                    if src_for_ttfb == client_ip_for_ttfb and stream.get("first_client_data_time") is None:
                        stream["first_client_data_time"] = pkt_time_for_ttfb

                    if src_for_ttfb == server_ip_for_ttfb and stream.get("first_server_data_time") is None:
                        stream["first_server_data_time"] = pkt_time_for_ttfb

                        base_time = stream.get("first_client_data_time") or stream.get("start_time")
                        if base_time is not None:
                            stream["first_server_data_ms"] = round((pkt_time_for_ttfb - float(base_time)) * 1000, 3)
            except Exception:
                pass

            # Update BIF metrics inline so stream output always has values
            bif_samples = bif_samples_by_stream.get(stream_key, [])
            if bif_samples:
                stream["max_bytes_in_flight"] = int(max(bif_samples))
                stream["avg_bytes_in_flight"] = round(sum(bif_samples) / len(bif_samples), 2)
                stream["bytes_in_flight_samples"] = [int(x) for x in bif_samples]
                stream["bif_status"] = bif_status_by_stream.get(stream_key, "unknown")

                limiter, limiter_reason, limiter_evidence = classify_tcp_limiter(stream)
                stream["tcp_limiter"] = limiter
                stream["tcp_limiter_reason"] = limiter_reason
                stream["tcp_limiter_evidence"] = limiter_evidence

                # -------- BIF-based interpretation (engineer-friendly) --------
                max_bif = stream.get("max_bytes_in_flight", 0) or 0
                avg_bif = stream.get("avg_bytes_in_flight", 0) or 0
                retrans = stream.get("retransmission_count", 0) or 0
                dup_ack = stream.get("duplicate_ack_count", 0) or 0
                zero_win = stream.get("zero_window_count", 0) or 0
                throughput = stream.get("throughput_bps", 0) or 0
                bif_efficiency = round(avg_bif / max_bif, 4) if max_bif > 0 else 0

                bif_interpretation = ""
                action_hint = ""

                if max_bif <= 0:
                    bif_interpretation = (
                        "No meaningful bytes-in-flight observed. This may indicate an idle/control-only stream, very short transfer, or incomplete bidirectional capture."
                    )
                    action_hint = "Verify capture location and confirm both traffic directions are visible."

                elif zero_win > 0:
                    bif_interpretation = (
                        "Receiver-limited behavior detected. The receiver advertised zero window, so the sender may be blocked by receiver-side buffers or slow application reads."
                    )
                    action_hint = "Check receiver host CPU, memory, socket buffers, and application read performance."

                elif retrans > 0 and dup_ack > 0:
                    if bif_efficiency < 0.30:
                        bif_interpretation = (
                            "TCP builds data in flight but cannot sustain it. Retransmissions and duplicate ACKs indicate packet loss, reordering, or congestion, while low BIF efficiency suggests repeated congestion-window collapse."
                        )
                        action_hint = "Check WAN loss, QoS drops, interface errors, wireless instability, firewall/proxy drops, or congested links."
                    else:
                        bif_interpretation = (
                            "Packet loss or reordering is present, but the stream still sustains some in-flight data. This suggests intermittent loss rather than complete throughput collapse."
                        )
                        action_hint = "Check for intermittent packet loss, path reordering, or middlebox instability."

                elif max_bif < 5000 and retrans == 0 and zero_win == 0:
                    bif_interpretation = (
                        "Application-limited behavior likely. Bytes in flight stayed low without retransmissions or receiver-window pressure, so the sender/application did not fill the available pipe."
                    )
                    action_hint = "Check application request size, think time, server response behavior, or small object transfers."

                elif bif_efficiency > 0.70 and retrans == 0 and zero_win == 0:
                    bif_interpretation = (
                        "Stable TCP behavior. Data in flight is consistently maintained without obvious loss or receiver pressure, indicating efficient use of the available network path."
                    )
                    action_hint = "No immediate TCP transport action indicated."

                elif bif_efficiency < 0.30:
                    bif_interpretation = (
                        "Bursty or unstable transmission pattern. The stream briefly reaches higher BIF but does not sustain it, suggesting application pacing or intermittent network constraints."
                    )
                    action_hint = "Correlate with application timing, RTT, retransmissions, and proxy/firewall behavior."

                else:
                    bif_interpretation = (
                        "Moderate TCP utilization. No dominant limiter is strongly indicated from BIF, retransmission, duplicate ACK, and receiver-window evidence."
                    )
                    action_hint = "Correlate with RTT, throughput, application timing, and endpoint behavior."

                stream["bif_efficiency"] = bif_efficiency
                stream["tcp_bif_interpretation"] = bif_interpretation
                stream["tcp_engineer_action_hint"] = action_hint
                stream["tcp_bif_interpretation"] = interpret_tcp_with_bif(stream)
                stream["tcp_engineer_action_hint"] = tcp_engineer_action_hint(stream)


            if pkt[TCP].payload is not None:
                payload_len = len(bytes(pkt[TCP].payload))

            if flags not in stream["tcp_flags_seen"]:
                stream.setdefault("tls_detected", False)
                stream.setdefault("tls_versions_seen", [])
                stream.setdefault("tls_record_types_seen", [])
                stream.setdefault("tls_alert_count", 0)
                stream.setdefault("tls_fatal_alert_count", 0)
                stream.setdefault("tls_warning_alert_count", 0)
                stream.setdefault("tls_alert_descriptions", [])
                stream.setdefault("tls_handshake_count", 0)
                stream.setdefault("tls_application_data_count", 0)
                stream.setdefault("tls_change_cipher_spec_count", 0)
                stream.setdefault("tls_nonstandard_port", False)

                try:
                    tcp_payload = bytes(pkt[TCP].payload)
                    tls_meta = parse_tls_payload(tcp_payload)
                    if tls_meta:
                        stream["tls_detected"] = True

                        tls_version = tls_meta.get("tls_version")
                        if tls_version and tls_version not in stream["tls_versions_seen"]:
                            stream["tls_versions_seen"].append(tls_version)

                        record_type = tls_meta.get("record_type")
                        if record_type and record_type not in stream["tls_record_types_seen"]:
                            stream["tls_record_types_seen"].append(record_type)

                        if record_type == "handshake":
                            stream["tls_handshake_count"] += 1
                        elif record_type == "application_data":
                            stream["tls_application_data_count"] += 1
                        elif record_type == "change_cipher_spec":
                            stream["tls_change_cipher_spec_count"] += 1
                        elif record_type == "alert":
                            stream["tls_alert_count"] += 1
                            alert_level = tls_meta.get("alert_level")
                            if alert_level == "fatal":
                                stream["tls_fatal_alert_count"] += 1
                            elif alert_level == "warning":
                                stream["tls_warning_alert_count"] += 1

                            alert_desc = tls_meta.get("alert_description")
                            if alert_desc and alert_desc not in stream["tls_alert_descriptions"]:
                                stream["tls_alert_descriptions"].append(alert_desc)

                        ports = {stream.get("endpoint_a_port"), stream.get("endpoint_b_port")}
                        if 443 not in ports:
                            stream["tls_nonstandard_port"] = True
                except Exception:
                    pass

                stream["tcp_flags_seen"].append(flags)

            is_control = syn or fin
            if payload_len > 0 or is_control:
                seq_marker = (seq_num, payload_len, flags)
                if seq_marker in seen_seq_by_stream_dir[direction_key]:
                    stream["retransmission_count"] += 1
                    stream["has_retransmissions"] = True
                else:
                    seen_seq_by_stream_dir[direction_key].add(seq_marker)

            if ack and not syn and not fin and not rst and payload_len == 0:
                seen_ack_by_stream_dir[direction_key].append(ack_num)
                if len(seen_ack_by_stream_dir[direction_key]) >= 2:
                    if seen_ack_by_stream_dir[direction_key][-1] == seen_ack_by_stream_dir[direction_key][-2]:
                        stream["duplicate_ack_count"] += 1

            if window_size == 0:
                stream["zero_window_count"] += 1

            if syn and not ack and stream["syn_time"] is None:
                stream["syn_time"] = pkt_time

            if syn and ack and stream["synack_time"] is None:
                stream["synack_time"] = pkt_time

            if (
                stream["syn_time"] is not None
                and stream["synack_time"] is not None
                and stream["handshake_rtt_ms"] is None
            ):
                if stream["synack_time"] >= stream["syn_time"]:
                    stream["handshake_rtt_ms"] = round(
                        (stream["synack_time"] - stream["syn_time"]) * 1000, 3
                    )

            if syn and not ack:
                stream["syn_seen"] = True
            if syn and ack:
                stream["synack_seen"] = True
            if ack and not syn:
                stream["ack_seen"] = True
            if rst:
                stream["rst_seen"] = True
            if fin:
                stream["fin_seen"] = True

    stream_list = []
    for stream in streams.values():
        stream["duration_seconds"] = round(stream["end_time"] - stream["start_time"], 6)
        if stream["duration_seconds"] > 0:
            stream["throughput_bps"] = round(
                (stream["byte_count"] * 8) / stream["duration_seconds"], 2
            )
        else:
            stream["throughput_bps"] = 0.0

        if stream["protocol"] == "STP":
            stream["stream_label"] = stream.get("stream_label") or (
                f"STP Root {stream['endpoint_a_port']}/{stream['endpoint_b_ip']}"
            )
            stream["application"] = "Spanning Tree"
        else:
            label_core = (
                f"{stream['endpoint_a_ip']}:{stream['endpoint_a_port']} ↔ "
                f"{stream['endpoint_b_ip']}:{stream['endpoint_b_port']}"
            )
            if stream.get("tls_sni"):
                stream["stream_label"] = f"{stream['tls_sni']} ({label_core})"
            else:
                stream["stream_label"] = label_core

            stream["application"] = identify_application(
            stream.get("tls_sni"),
            stream.get("endpoint_a_port"),
            stream.get("endpoint_b_port"),
            stream.get("protocol"),
        )

        if stream["protocol"] == "TCP":
            if stream["syn_seen"] and stream["synack_seen"] and stream["ack_seen"]:
                stream["handshake_status"] = "handshake_complete"
            elif stream["syn_seen"] and not stream["synack_seen"]:
                stream["handshake_status"] = "syn_seen_no_synack"
                stream["notes"].append("Connection attempt seen, but no SYN-ACK observed.")
            elif stream["synack_seen"] and not stream["ack_seen"]:
                stream["handshake_status"] = "synack_seen_no_ack"
                stream["notes"].append("SYN-ACK seen, but final ACK not observed.")
            elif stream["ack_seen"] and not stream["syn_seen"]:
                stream["handshake_status"] = "midstream_or_partial_capture"
                stream["notes"].append(
                    "ACK/data seen without initial SYN. Capture may have started midstream."
                )
            else:
                stream["handshake_status"] = "unknown"

            if stream["packets_b_to_a"] == 0:
                stream["stream_health"] = "one_sided"
                stream["notes"].append("Traffic seen only in one direction.")
            elif stream["has_retransmissions"]:
                stream["stream_health"] = "loss_or_retransmission"
            elif stream["rst_seen"]:
                stream["stream_health"] = "reset_seen"
                stream["notes"].append("TCP reset observed in the stream.")
            elif stream["fin_seen"]:
                stream["stream_health"] = "graceful_close_seen"
                stream["notes"].append("TCP FIN observed in the stream.")
            else:
                stream["stream_health"] = "bidirectional"

            if stream["has_retransmissions"]:
                stream["notes"].append(
                    f"Probable retransmissions detected: {stream['retransmission_count']}"
                )

            if stream["duplicate_ack_count"] > 0:
                stream["notes"].append(
                    f"Duplicate ACKs detected: {stream['duplicate_ack_count']}"
                )

            if stream["zero_window_count"] > 0:
                stream["notes"].append(
                    f"Zero-window events detected: {stream['zero_window_count']}"
                )

            if stream["handshake_rtt_ms"] is not None:
                stream["notes"].append(
                    f"Estimated handshake RTT: {stream['handshake_rtt_ms']} ms"
                )

            stream["stream_category"] = "no_strong_anomaly"
            stream["stream_summary"] = (
                "No strong TCP anomaly detected from currently visible evidence."
            )
            stream["stream_confidence"] = 0.35

            if (
                stream["packets_b_to_a"] == 0
                and stream["handshake_status"] == "midstream_or_partial_capture"
            ):
                stream["stream_category"] = "partial_capture"
                stream["stream_summary"] = (
                    "Likely partial or asymmetric capture; stream appears mid-connection "
                    "and only one direction is visible."
                )
                stream["stream_confidence"] = 0.95
            elif stream["packets_b_to_a"] == 0:
                stream["stream_category"] = "one_sided_capture"
                stream["stream_summary"] = (
                    "Likely incomplete visibility; traffic is visible in only one direction."
                )
                stream["stream_confidence"] = 0.9
            elif stream["handshake_status"] == "syn_seen_no_synack":
                stream["stream_category"] = "failed_connection_setup"
                stream["stream_summary"] = (
                    "Connection setup likely failed; SYN was seen without a SYN-ACK response."
                )
                stream["stream_confidence"] = 0.82
            elif stream["zero_window_count"] > 0:
                stream["stream_category"] = "receiver_pressure"
                stream["stream_summary"] = (
                    "Receiver-side or application backpressure indicated by zero-window events."
                )
                stream["stream_confidence"] = 0.84
            elif (
                stream["retransmission_count"] > 0
                and stream["duplicate_ack_count"] > 0
            ):
                stream["stream_category"] = "probable_packet_loss"
                stream["stream_summary"] = (
                    "Probable packet loss or unstable delivery indicated by retransmissions "
                    "and duplicate ACKs."
                )
                stream["stream_confidence"] = 0.86
            elif stream["retransmission_count"] > 0:
                stream["stream_category"] = "possible_packet_loss"
                stream["stream_summary"] = (
                    "Possible packet loss or retransmission behavior observed in this stream."
                )
                stream["stream_confidence"] = 0.72
            elif stream["duplicate_ack_count"] > 0:
                stream["stream_category"] = "possible_out_of_order_or_loss"
                stream["stream_summary"] = (
                    "Duplicate ACK behavior suggests missing or out-of-order TCP segments."
                )
                stream["stream_confidence"] = 0.7
            elif stream["rst_seen"]:
                stream["stream_category"] = "connection_reset"
                stream["stream_summary"] = (
                    "TCP reset observed; the connection may have been rejected or abruptly terminated."
                )
                stream["stream_confidence"] = 0.68
            elif stream["duration_seconds"] > 10 and stream["throughput_bps"] < 10000:
                stream["stream_category"] = "slow_low_throughput"
                stream["stream_summary"] = (
                    "Long-lived stream with low throughput; possible application slowness "
                    "or inefficient exchange."
                )
                stream["stream_confidence"] = 0.6
        else:
            stream["handshake_status"] = "not_applicable"
            stream["stream_health"] = "not_applicable"
            stream["stream_category"] = "not_applicable"
            stream["stream_summary"] = (
                "TCP-specific analysis is not applicable to this protocol."
            )
            stream["stream_confidence"] = 0.0

        stream_list.append(stream)

    stream_list.sort(key=lambda s: s["packet_count"], reverse=True)

    stream_list = enrich_streams_with_criticality(stream_list)

    result_dir = RESULTS_DIR / job_id
    result_dir.mkdir(parents=True, exist_ok=True)

    stream_file = result_dir / "streams.json"
    with open(stream_file, "w", encoding="utf-8") as f:
        json.dump(stream_list, f, indent=2)



    # BYTES_IN_FLIGHT_FINALIZER
    for s_key, stream in streams.items():
        samples = bif_samples_by_stream.get(s_key, [])
        if samples:
            stream["max_bytes_in_flight"] = int(max(samples))
            stream["avg_bytes_in_flight"] = round(sum(samples) / len(samples), 2)
            stream["bytes_in_flight_samples"] = [int(x) for x in samples[:50]]
        else:
            stream["max_bytes_in_flight"] = 0
            stream["avg_bytes_in_flight"] = 0
            stream["bytes_in_flight_samples"] = []

    return stream_list


def load_streams(job_id: str):
    stream_file = RESULTS_DIR / job_id / "streams.json"
    if not stream_file.exists():
        return None

    with open(stream_file, "r", encoding="utf-8") as f:
        return json.load(f)


def top_stream_refs(stream_subset, limit=5):
    top = sorted(
        stream_subset,
        key=lambda s: (
            s.get("criticality_score", 0)
            + s.get("retransmission_count", 0)
            + s.get("duplicate_ack_count", 0)
            + s.get("zero_window_count", 0)
            + s.get("packet_count", 0)
        ),
        reverse=True,
    )[:limit]

    return {
        "stream_ids": [s.get("stream_id") for s in top],
        "stream_labels": [s.get("stream_label") for s in top],
    }


def normalize_timeline_output(timeline):
    if not timeline or not timeline.get("first_issue_seen"):
        return timeline

    base = float(timeline["first_issue_seen"])

    def rel(t):
        if t is None:
            return None
        return round(float(t) - base, 2)

    timeline["first_issue_seen"] = 0
    timeline["last_issue_seen"] = rel(timeline["last_issue_seen"])

    if timeline.get("peak_issue_window"):
        timeline["peak_issue_window"]["window_start_seconds"] = rel(
            base + timeline["peak_issue_window"]["window_start_seconds"]
        )
        timeline["peak_issue_window"]["window_end_seconds"] = rel(
            base + timeline["peak_issue_window"]["window_end_seconds"]
        )

    for b in timeline.get("timeline_buckets", []):
        b["offset_seconds"] = rel(base + b["offset_seconds"])

    return timeline




def generate_findings(streams):
    findings = []

    try:
        packets = load_packets(CURRENT_JOB_ID) if 'CURRENT_JOB_ID' in globals() else []
    except Exception:
        packets = []

    findings.extend(analyze_arp(packets, streams))
    findings.extend(analyze_dhcp(packets, streams))
    findings.extend(analyze_stp(packets, streams))
    findings.extend(analyze_http(packets, streams))

    if not streams:
        return findings

    total_streams = len(streams)

    one_sided = [s for s in streams if s.get("packets_b_to_a", 0) == 0]
    syn_only = [s for s in streams if s.get("handshake_status") == "syn_seen_no_synack"]
    midstream = [
        s for s in streams if s.get("handshake_status") == "midstream_or_partial_capture"
    ]
    resets = [s for s in streams if s.get("rst_seen")]
    retrans = [s for s in streams if s.get("retransmission_count", 0) > 0]
    dup_acks = [s for s in streams if s.get("duplicate_ack_count", 0) > 0]
    zero_window = [s for s in streams if s.get("zero_window_count", 0) > 0]

    # TLS deep analysis
    tls_streams = [
        s for s in streams
        if s.get("protocol") == "TLS"
        or s.get("tls_detected")
        or s.get("tls_handshake_count", 0) > 0
        or len(s.get("tls_versions_seen", [])) > 0
    ]

    weak_tls_10 = [s for s in tls_streams if "TLS 1.0" in (s.get("tls_versions_seen") or [])]
    legacy_tls_11 = [s for s in tls_streams if "TLS 1.1" in (s.get("tls_versions_seen") or [])]
    tls_alerts = [s for s in tls_streams if s.get("tls_alert_count", 0) > 0]
    tls_fatal_alerts = [s for s in tls_streams if s.get("tls_fatal_alert_count", 0) > 0]
    tls_handshake_only = [
        s for s in tls_streams
        if s.get("tls_handshake_count", 0) > 0 and s.get("tls_application_data_count", 0) == 0
    ]
    tls_reset_after_handshake = [
        s for s in tls_streams
        if s.get("rst_seen") and s.get("tls_handshake_count", 0) > 0
    ]
    tls_nonstandard_port = [
        s for s in tls_streams
        if 443 not in {s.get("endpoint_a_port"), s.get("endpoint_b_port")}
    ]
    tls_version_mismatch = [
        s for s in tls_streams
        if len(s.get("tls_versions_seen", [])) > 1
    ]
    tls_missing_sni = [
        s for s in tls_streams
        if s.get("tls_handshake_count", 0) > 0 and not s.get("tls_sni")
    ]
    tls_slow_handshakes = [
        s for s in tls_streams
        if s.get("handshake_rtt_ms") is not None and s.get("handshake_rtt_ms", 0) > 300
    ]
    tls_certificate_issues = [
        s for s in tls_streams
        if any(
            a in (s.get("tls_alert_descriptions") or [])
            for a in ["bad_certificate", "certificate_unknown", "unknown_ca", "certificate_required"]
        )
    ]

    if weak_tls_10:
        refs = top_stream_refs(weak_tls_10) or {}
        findings.append(
            {
                "type": "security_issue",
                "severity": "high",
                "title": "Weak TLS 1.0 detected",
                "description": "TLS 1.0 traffic detected on one or more streams. TLS 1.0 is deprecated and insecure.",
                "affected_streams": len(weak_tls_10),
                **refs,
            }
        )

    if legacy_tls_11:
        refs = top_stream_refs(legacy_tls_11) or {}
        findings.append(
            {
                "type": "security_issue",
                "severity": "medium",
                "title": "Legacy TLS 1.1 detected",
                "description": "TLS 1.1 traffic detected on one or more streams. TLS 1.1 is legacy and should be retired.",
                "affected_streams": len(legacy_tls_11),
                **refs,
            }
        )

    if tls_certificate_issues:
        refs = top_stream_refs(tls_certificate_issues) or {}
        findings.append(
            {
                "type": "tls_issue",
                "severity": "high",
                "title": "TLS certificate issues detected",
                "description": "TLS alerts indicate certificate-related problems such as unknown CA, bad certificate, or certificate requirement failure.",
                "affected_streams": len(tls_certificate_issues),
                **refs,
            }
        )

    if tls_fatal_alerts:
        refs = top_stream_refs(tls_fatal_alerts) or {}
        findings.append(
            {
                "type": "tls_issue",
                "severity": "high",
                "title": "Fatal TLS alerts observed",
                "description": "One or more TLS streams emitted fatal alerts, suggesting handshake failure or forced termination.",
                "affected_streams": len(tls_fatal_alerts),
                **refs,
            }
        )
    elif tls_alerts:
        refs = top_stream_refs(tls_alerts) or {}
        findings.append(
            {
                "type": "tls_issue",
                "severity": "medium",
                "title": "TLS alerts observed",
                "description": "One or more TLS streams emitted alerts. Review the affected streams for negotiation issues.",
                "affected_streams": len(tls_alerts),
                **refs,
            }
        )

    if tls_version_mismatch:
        refs = top_stream_refs(tls_version_mismatch) or {}
        findings.append(
            {
                "type": "tls_issue",
                "severity": "medium",
                "title": "TLS version mismatch detected",
                "description": "Multiple TLS versions observed in the same stream, which may indicate fallback, downgrade, or negotiation inconsistency.",
                "affected_streams": len(tls_version_mismatch),
                **refs,
            }
        )

    if tls_missing_sni:
        refs = top_stream_refs(tls_missing_sni) or {}
        findings.append(
            {
                "type": "tls_issue",
                "severity": "medium",
                "title": "Missing SNI on TLS streams",
                "description": "TLS handshake was observed without SNI on one or more streams. This may cause issues on virtual-hosted HTTPS services.",
                "affected_streams": len(tls_missing_sni),
                **refs,
            }
        )

    if tls_slow_handshakes:
        refs = top_stream_refs(tls_slow_handshakes) or {}
        findings.append(
            {
                "type": "tls_issue",
                "severity": "medium",
                "title": "Slow TLS handshakes detected",
                "description": "One or more TLS streams showed elevated handshake RTT, which may indicate latency, inspection overhead, or server-side delay.",
                "affected_streams": len(tls_slow_handshakes),
                **refs,
            }
        )

    if tls_handshake_only:
        refs = top_stream_refs(tls_handshake_only) or {}
        findings.append(
            {
                "type": "tls_issue",
                "severity": "medium",
                "title": "TLS handshake without application data",
                "description": "TLS handshake records were seen, but no TLS application data followed. This may indicate failed negotiation, probing, or early termination.",
                "affected_streams": len(tls_handshake_only),
                **refs,
            }
        )

    if tls_reset_after_handshake:
        refs = top_stream_refs(tls_reset_after_handshake) or {}
        findings.append(
            {
                "type": "tls_issue",
                "severity": "medium",
                "title": "TLS streams reset after handshake",
                "description": "TLS handshake activity was observed, followed by TCP reset on one or more streams.",
                "affected_streams": len(tls_reset_after_handshake),
                **refs,
            }
        )

    if tls_nonstandard_port:
        refs = top_stream_refs(tls_nonstandard_port) or {}
        findings.append(
            {
                "type": "tls_observation",
                "severity": "low",
                "title": "TLS observed on non-standard port",
                "description": "TLS traffic was detected on a port other than 443.",
                "affected_streams": len(tls_nonstandard_port),
                **refs,
            }
        )

    low_throughput_long = [
        s
        for s in streams
        if s.get("duration_seconds", 0) > 10 and s.get("throughput_bps", 0) < 10000
    ]

    high_rtt = [
        s
        for s in streams
        if s.get("handshake_rtt_ms") is not None and s.get("handshake_rtt_ms", 0) > 300
    ]

    if len(one_sided) / total_streams > 0.5:
        refs = top_stream_refs(one_sided) or {}
        findings.append(
            {
                "type": "capture_issue",
                "severity": "high",
                "title": "One-sided traffic detected",
                "description": (
                    "Majority of streams have traffic only in one direction. "
                    "Capture may be incomplete or asymmetric."
                ),
                "affected_streams": len(one_sided),
                **refs,
            }
        )

    if len(syn_only) > 0:
        refs = top_stream_refs(syn_only) or {}
        findings.append(
            {
                "type": "tcp_issue",
                "severity": "medium",
                "title": "Unanswered SYN packets",
                "description": (
                    "Some streams show SYN without SYN-ACK, suggesting connection setup failure "
                    "or filtering."
                ),
                "affected_streams": len(syn_only),
                **refs,
            }
        )

    if len(midstream) / total_streams > 0.5:
        refs = top_stream_refs(midstream) or {}
        findings.append(
            {
                "type": "capture_issue",
                "severity": "medium",
                "title": "Capture started midstream",
                "description": (
                    "Many streams appear mid-connection, indicating capture started after sessions "
                    "were already established."
                ),
                "affected_streams": len(midstream),
                **refs,
            }
        )

    if len(resets) > 0:
        refs = top_stream_refs(resets) or {}
        findings.append(
            {
                "type": "tcp_issue",
                "severity": "low",
                "title": "TCP resets observed",
                "description": "Some streams contain TCP RST packets.",
                "affected_streams": len(resets),
                **refs,
            }
        )

    if len(retrans) > 0:
        refs = top_stream_refs(retrans) or {}
        findings.append(
            {
                "type": "performance_issue",
                "severity": "medium",
                "title": "Probable TCP retransmissions detected",
                "description": (
                    "Repeated sequence patterns suggest retransmissions due to loss, reordering, "
                    "or poor delivery conditions."
                ),
                "affected_streams": len(retrans),
                **refs,
            }
        )

    if len(dup_acks) > 0:
        refs = top_stream_refs(dup_acks) or {}
        findings.append(
            {
                "type": "performance_issue",
                "severity": "medium",
                "title": "Duplicate ACK patterns detected",
                "description": (
                    "Duplicate ACKs suggest missing or delayed TCP segments and may indicate packet "
                    "loss or reordering."
                ),
                "affected_streams": len(dup_acks),
                **refs,
            }
        )

    if len(zero_window) > 0:
        refs = top_stream_refs(zero_window) or {}
        findings.append(
            {
                "type": "endpoint_issue",
                "severity": "medium",
                "title": "Zero-window events detected",
                "description": (
                    "Some TCP receivers advertised a zero window, suggesting endpoint receive-side "
                    "pressure or slow application reads."
                ),
                "affected_streams": len(zero_window),
                **refs,
            }
        )

    if len(high_rtt) > 0:
        refs = top_stream_refs(high_rtt) or {}
        findings.append(
            {
                "type": "latency_issue",
                "severity": "low",
                "title": "High TCP handshake RTT detected",
                "description": "Some streams show elevated SYN to SYN-ACK delay.",
                "affected_streams": len(high_rtt),
                **refs,
            }
        )

    if len(low_throughput_long) > 0:
        refs = top_stream_refs(low_throughput_long) or {}
        findings.append(
            {
                "type": "performance_issue",
                "severity": "low",
                "title": "Long-duration low-throughput streams detected",
                "description": (
                    "Some streams lasted a long time but transferred very little data, suggesting "
                    "stalling or underutilization."
                ),
                "affected_streams": len(low_throughput_long),
                **refs,
            }
        )

    return findings



def analyze_arp(packets, streams):
    findings = []

    arp_requests = []
    arp_replies = []
    ip_to_macs = {}

    for pkt in packets:
        if pkt.get("protocol") != "ARP":
            continue

        info = str(pkt.get("info", ""))
        src = pkt.get("src")
        dst = pkt.get("dst")

        # Track IP -> MAC-ish sender identity using src field available in parsed packets
        if src:
            ip_to_macs.setdefault(src, set()).add(str(pkt.get("src_mac", src)))

        if "who has" in info.lower() or "request" in info.lower():
            arp_requests.append((src, dst))
        elif "is at" in info.lower() or "reply" in info.lower():
            arp_replies.append((src, dst))

    duplicate_ips = [ip for ip, macs in ip_to_macs.items() if len(macs) > 1]

    if duplicate_ips:
        findings.append({
            "type": "arp_issue",
            "severity": "high",
            "title": "Duplicate IP detected",
            "description": f"Multiple sender identities were observed for the same IP(s): {duplicate_ips[:5]}",
            "affected_streams": len(duplicate_ips),
        })

    if len(arp_requests) > 100:
        findings.append({
            "type": "arp_issue",
            "severity": "medium",
            "title": "ARP request storm detected",
            "description": f"High number of ARP requests observed: {len(arp_requests)}",
            "affected_streams": len(arp_requests),
        })

    requested_targets = set(dst for _, dst in arp_requests if dst)
    replied_sources = set(src for src, _ in arp_replies if src)
    unanswered = requested_targets - replied_sources

    if unanswered:
        findings.append({
            "type": "arp_issue",
            "severity": "medium",
            "title": "Unanswered ARP requests",
            "description": f"No ARP reply seen for target IP(s): {list(unanswered)[:5]}",
            "affected_streams": len(unanswered),
        })

    return findings


def analyze_dhcp(packets, streams):
    findings = []

    dhcp_packets = []
    client_to_server = 0
    server_to_client = 0
    servers = set()

    for pkt in packets:
        src_port = pkt.get("src_port")
        dst_port = pkt.get("dst_port")
        src = pkt.get("src")
        dst = pkt.get("dst")

        is_dhcp = src_port in (67, 68) or dst_port in (67, 68)
        if not is_dhcp:
            continue

        dhcp_packets.append(pkt)

        if src_port == 68 and dst_port == 67:
            client_to_server += 1
        elif src_port == 67 and dst_port == 68:
            server_to_client += 1
            if src:
                servers.add(src)

    if not dhcp_packets:
        return findings

    # Always surface that DHCP traffic exists
    findings.append({
        "type": "dhcp_observation",
        "severity": "low",
        "title": "DHCP traffic observed",
        "description": f"DHCP-related UDP traffic detected ({len(dhcp_packets)} packets over ports 67/68).",
        "affected_streams": len(dhcp_packets),
    })

    # Heuristic issue detection from direction patterns
    if client_to_server > 0 and server_to_client == 0:
        findings.append({
            "type": "dhcp_issue",
            "severity": "high",
            "title": "No DHCP server responses observed",
            "description": "Client-to-server DHCP traffic was seen, but no server-to-client responses were observed.",
            "affected_streams": client_to_server,
        })

    elif client_to_server > server_to_client:
        findings.append({
            "type": "dhcp_issue",
            "severity": "medium",
            "title": "Incomplete DHCP exchange detected",
            "description": "More client DHCP messages than server responses were observed, which may indicate offer/ack loss or server-side issues.",
            "affected_streams": client_to_server - server_to_client,
        })

    if len(servers) > 1:
        findings.append({
            "type": "dhcp_issue",
            "severity": "medium",
            "title": "Multiple DHCP servers detected",
            "description": f"Multiple DHCP responder IPs were observed: {list(servers)[:5]}",
            "affected_streams": len(servers),
        })

    return findings


def analyze_stp(packets, streams):
    findings = []

    stp_packets = []
    roots = set()
    families = set()

    for pkt in packets:
        proto = str(pkt.get("protocol", "")).upper()
        info = str(pkt.get("info", "")).lower()

        is_stp = (
            proto == "STP"
            or "bpdu" in info
            or "conf. root" in info
            or "uplinkfast" in info
            or "pvst" in info
            or "spanning tree" in info
        )

        if not is_stp:
            continue

        stp_packets.append(pkt)

        if "conf. root" in info:
            roots.add(info)

        if "uplinkfast" in info or "pvst" in info:
            families.add("cisco_pvst")
        else:
            families.add("stp")

    if not stp_packets:
        return findings

    findings.append({
        "type": "stp_observation",
        "severity": "low",
        "title": "STP traffic observed",
        "description": f"Spanning Tree / BPDU traffic detected ({len(stp_packets)} packets).",
        "affected_streams": len(stp_packets),
    })

    if len(roots) > 1:
        findings.append({
            "type": "stp_issue",
            "severity": "high",
            "title": "Multiple STP root indicators detected",
            "description": "Multiple distinct STP root indicators were observed. This may suggest instability or inconsistent root election.",
            "affected_streams": len(roots),
        })

    if len(stp_packets) > 200:
        findings.append({
            "type": "stp_issue",
            "severity": "medium",
            "title": "High STP BPDU activity",
            "description": f"High STP/BPDU packet count observed: {len(stp_packets)}",
            "affected_streams": len(stp_packets),
        })

    return findings

    findings.append({
        "type": "stp_observation",
        "severity": "low",
        "title": "STP traffic observed",
        "description": f"Spanning Tree / BPDU traffic detected ({len(stp_packets)} packets).",
        "affected_streams": len(stp_packets),
    })

    if len(roots) > 1:
        findings.append({
            "type": "stp_issue",
            "severity": "high",
            "title": "Multiple STP root indicators detected",
            "description": "Multiple distinct STP root-related indicators were observed. This may suggest instability or inconsistent root election.",
            "affected_streams": len(roots),
        })

    if len(stp_packets) > 200:
        findings.append({
            "type": "stp_issue",
            "severity": "medium",
            "title": "High STP BPDU activity",
            "description": f"High STP/BPDU packet count observed: {len(stp_packets)}",
            "affected_streams": len(stp_packets),
        })

    return findings


def analyze_http(packets, streams):
    findings = []

    http_streams = []
    plain_http_streams = []
    slow_http_streams = []
    large_http_streams = []
    suspected_http_error_streams = []

    for s in streams:
        ports = {s.get("endpoint_a_port"), s.get("endpoint_b_port")}
        label = str(s.get("stream_label", "")).lower()
        app = str(s.get("application", "")).lower()
        summary = str(s.get("stream_summary", "")).lower()
        reason = str(s.get("criticality_reason", "")).lower()
        impact = str(s.get("impact_hint", "")).lower()

        hay = " ".join([label, app, summary, reason, impact])

        is_http = (
            80 in ports
            or "http" in hay
            or "web" in hay
        )

        if not is_http:
            continue

        http_streams.append(s)

        if 80 in ports:
            plain_http_streams.append(s)

        if s.get("handshake_rtt_ms") is not None and s.get("handshake_rtt_ms", 0) > 300:
            slow_http_streams.append(s)

        total_bytes = (s.get("bytes_a_to_b", 0) or 0) + (s.get("bytes_b_to_a", 0) or 0)
        if total_bytes > 1000000:
            large_http_streams.append(s)

        if any(token in hay for token in ["404", "500", "502", "503", "504", "4xx", "5xx", "error", "failed"]):
            suspected_http_error_streams.append(s)

    # Packet-level fallback for minimally decoded captures
    http_packets = []
    for pkt in packets:
        proto = str(pkt.get("protocol", "")).upper()
        info = str(pkt.get("info", "")).lower()
        src_port = pkt.get("src_port")
        dst_port = pkt.get("dst_port")

        is_http_pkt = (
            src_port in (80, 8080, 8000)
            or dst_port in (80, 8080, 8000)
            or "http" in info
            or "get " in info
            or "post " in info
            or "head " in info
            or "put " in info
            or "delete " in info
            or "host:" in info
        )

        if is_http_pkt:
            http_packets.append(pkt)

    if not http_streams and not http_packets:
        return findings

    if http_streams:
        refs = top_stream_refs(http_streams) or {}
        findings.append({
            "type": "http_observation",
            "severity": "low",
            "title": "HTTP traffic observed",
            "description": f"HTTP-like traffic detected on {len(http_streams)} stream(s).",
            "affected_streams": len(http_streams),
            **refs,
        })
    else:
        findings.append({
            "type": "http_observation",
            "severity": "low",
            "title": "HTTP traffic observed",
            "description": f"HTTP-like packet activity detected ({len(http_packets)} packet(s)).",
            "affected_streams": len(http_packets),
        })

    if plain_http_streams:
        refs = top_stream_refs(plain_http_streams) or {}
        findings.append({
            "type": "http_issue",
            "severity": "low",
            "title": "Plain HTTP observed",
            "description": "Traffic on TCP port 80 was detected. Consider HTTPS if confidentiality is required.",
            "affected_streams": len(plain_http_streams),
            **refs,
        })

    if slow_http_streams:
        refs = top_stream_refs(slow_http_streams) or {}
        findings.append({
            "type": "http_issue",
            "severity": "medium",
            "title": "Slow HTTP transactions suspected",
            "description": "Some HTTP-like streams show elevated setup latency.",
            "affected_streams": len(slow_http_streams),
            **refs,
        })

    if large_http_streams:
        refs = top_stream_refs(large_http_streams) or {}
        findings.append({
            "type": "http_observation",
            "severity": "low",
            "title": "Large HTTP transfers detected",
            "description": "Some HTTP-like streams transferred large amounts of data.",
            "affected_streams": len(large_http_streams),
            **refs,
        })

    if suspected_http_error_streams:
        refs = top_stream_refs(suspected_http_error_streams) or {}
        findings.append({
            "type": "http_issue",
            "severity": "medium",
            "title": "HTTP error responses suspected",
            "description": "HTTP-related stream metadata suggests 4xx/5xx style failures on one or more streams.",
            "affected_streams": len(suspected_http_error_streams),
            **refs,
        })

    return findings

def save_findings(job_id: str, streams):
    global CURRENT_JOB_ID
    CURRENT_JOB_ID = job_id
    findings = generate_findings(streams)

    packets = load_packets(job_id)

    dns_findings = analyze_dns_packets(packets)
    if dns_findings:
        findings.extend(dns_findings)

    tls_findings = analyze_tls_packets(packets)
    if tls_findings:
        findings.extend(tls_findings)

    result_dir = RESULTS_DIR / job_id
    result_dir.mkdir(parents=True, exist_ok=True)

    findings_file = result_dir / "findings.json"
    with open(findings_file, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2)

    return findings


def load_findings(job_id: str):
    findings_file = RESULTS_DIR / job_id / "findings.json"
    if not findings_file.exists():
        return None

    with open(findings_file, "r", encoding="utf-8") as f:
        return json.load(f)


def generate_root_causes(job_id: str, streams):
    root_causes = []

    # Ensure findings available for correlation
    findings = generate_findings(streams)

    # --- DNS Root Cause Correlation ---
    dns_findings_local = [f for f in findings if f.get("category") == "dns"]

    # --- DNS Root Cause Correlation ---
    dns_findings_local = [f for f in findings if f.get("category") == "dns"]

    for df in dns_findings_local:
        title = df.get("title", "").lower()

        if "unanswered dns" in title:
            root_causes.append({
                "severity": "high",
                "category": "dns",
                "title": "Likely DNS resolver unreachable",
                "confidence": 0.85,
                "summary": "DNS queries are not receiving responses, indicating resolver reachability or filtering issue."
            })

        elif "servfail" in title:
            root_causes.append({
                "severity": "high",
                "category": "dns",
                "title": "Likely DNS resolver failure",
                "confidence": 0.82,
                "summary": "DNS server is returning SERVFAIL, indicating backend resolution or recursion issue."
            })

        elif "slow dns" in title:
            root_causes.append({
                "severity": "medium",
                "category": "dns",
                "title": "DNS latency impacting application performance",
                "confidence": 0.75,
                "summary": "Slow DNS responses likely contributing to perceived application slowness."
            })

        elif "nxdomain" in title:
            root_causes.append({
                "severity": "medium",
                "category": "dns",
                "title": "Invalid hostname or DNS misconfiguration",
                "confidence": 0.7,
                "summary": "NXDOMAIN responses indicate incorrect or non-existent domain queries."
            })


    tls_findings_local = analyze_tls_packets(load_packets(job_id))

    for tf in tls_findings_local:
        title = tf.get("title", "").lower()

        if "handshake failures" in title:
            root_causes.append({
                "severity": "high",
                "category": "tls",
                "title": "Likely TLS handshake negotiation failure",
                "confidence": 0.88,
                "summary": "TLS handshakes are failing, likely due to protocol, cipher, certificate, or interception mismatch."
            })

        elif "tls alerts" in title:
            root_causes.append({
                "severity": "high",
                "category": "tls",
                "title": "Likely TLS policy or certificate rejection",
                "confidence": 0.84,
                "summary": "TLS alert packets suggest the session was actively rejected during negotiation."
            })

        elif "version mismatch" in title:
            root_causes.append({
                "severity": "medium",
                "category": "tls",
                "title": "Likely TLS version incompatibility",
                "confidence": 0.76,
                "summary": "Multiple TLS versions or mismatched negotiation behavior may be causing connection setup failures."
            })

        elif "missing sni" in title:
            root_causes.append({
                "severity": "medium",
                "category": "tls",
                "title": "Likely SNI-related virtual host failure",
                "confidence": 0.72,
                "summary": "Missing SNI in Client Hello may cause failures on virtual-hosted HTTPS services."
            })

        elif "slow tls handshakes" in title:
            root_causes.append({
                "severity": "medium",
                "category": "tls",
                "title": "TLS negotiation latency impacting application performance",
                "confidence": 0.78,
                "summary": "Slow TLS handshakes likely contributed to application slowness or delayed session establishment."
            })


    if not streams:
        return root_causes

    total_streams = len(streams)

    one_sided = [s for s in streams if s.get("packets_b_to_a", 0) == 0]
    midstream = [
        s for s in streams if s.get("handshake_status") == "midstream_or_partial_capture"
    ]
    syn_only = [s for s in streams if s.get("handshake_status") == "syn_seen_no_synack"]
    retrans = [s for s in streams if s.get("retransmission_count", 0) > 0]
    dup_acks = [s for s in streams if s.get("duplicate_ack_count", 0) > 0]
    zero_window = [s for s in streams if s.get("zero_window_count", 0) > 0]
    resets = [s for s in streams if s.get("rst_seen")]

    one_sided_ratio = len(one_sided) / total_streams if total_streams else 0
    midstream_ratio = len(midstream) / total_streams if total_streams else 0
    retrans_ratio = len(retrans) / total_streams if total_streams else 0
    dup_ack_ratio = len(dup_acks) / total_streams if total_streams else 0
    zero_window_ratio = len(zero_window) / total_streams if total_streams else 0
    syn_only_ratio = len(syn_only) / total_streams if total_streams else 0

    if one_sided_ratio > 0.5 or midstream_ratio > 0.5:
        confidence = round(
            min(0.99, 0.55 + one_sided_ratio * 0.3 + midstream_ratio * 0.2), 2
        )
        refs = top_stream_refs(one_sided + midstream) or {}
        root_causes.append(
            {
                "category": "capture_problem",
                "severity": "high",
                "title": "Likely incomplete or asymmetric capture",
                "confidence": confidence,
                "summary": (
                    "Most traffic is visible in only one direction and/or many streams "
                    "started midstream."
                ),
                "evidence": [
                    f"{len(one_sided)} one-sided streams",
                    f"{len(midstream)} midstream/partial-capture streams",
                ],
                **refs,
            }
        )

    if retrans_ratio > 0.1 or dup_ack_ratio > 0.1:
        confidence = round(
            min(0.95, 0.45 + retrans_ratio * 0.3 + dup_ack_ratio * 0.25), 2
        )
        refs = top_stream_refs(retrans + dup_acks) or {}
        root_causes.append(
            {
                "category": "network_loss",
                "severity": "medium",
                "title": "Likely packet loss or path instability",
                "confidence": confidence,
                "summary": (
                    "Repeated sequence numbers and duplicate ACK patterns suggest "
                    "missing or delayed TCP segments."
                ),
                "evidence": [
                    f"{len(retrans)} streams with retransmissions",
                    f"{len(dup_acks)} streams with duplicate ACK patterns",
                ],
                **refs,
            }
        )

    if zero_window_ratio > 0.05:
        confidence = round(min(0.9, 0.4 + zero_window_ratio * 0.5), 2)
        refs = top_stream_refs(zero_window) or {}
        root_causes.append(
            {
                "category": "endpoint_pressure",
                "severity": "medium",
                "title": "Likely receiver-side or application slowness",
                "confidence": confidence,
                "summary": (
                    "Zero-window events suggest the receiving endpoint or application "
                    "could not consume data fast enough."
                ),
                "evidence": [f"{len(zero_window)} streams with zero-window events"],
                **refs,
            }
        )

    if syn_only_ratio > 0.05:
        confidence = round(min(0.9, 0.35 + syn_only_ratio * 0.6), 2)
        refs = top_stream_refs(syn_only) or {}
        root_causes.append(
            {
                "category": "connection_setup_failure",
                "severity": "medium",
                "title": "Likely failed connection establishment",
                "confidence": confidence,
                "summary": (
                    "Some connection attempts sent SYN packets without completing the "
                    "TCP handshake."
                ),
                "evidence": [f"{len(syn_only)} streams with SYN but no SYN-ACK"],
                **refs,
            }
        )

    if len(resets) > 0:
        confidence = round(min(0.85, 0.25 + (len(resets) / total_streams) * 0.5), 2)
        refs = top_stream_refs(resets) or {}
        root_causes.append(
            {
                "category": "connection_reset",
                "severity": "low",
                "title": "Some connections were actively reset",
                "confidence": confidence,
                "summary": "TCP reset packets were observed in some streams.",
                "evidence": [f"{len(resets)} streams with TCP resets"],
                **refs,
            }
        )

    return root_causes


def save_root_causes(job_id: str, streams):
    root_causes = generate_root_causes(job_id, streams)

    result_dir = RESULTS_DIR / job_id
    result_dir.mkdir(parents=True, exist_ok=True)

    root_causes_file = result_dir / "root_causes.json"
    with open(root_causes_file, "w", encoding="utf-8") as f:
        json.dump(root_causes, f, indent=2)

    return root_causes


def load_root_causes(job_id: str):
    root_causes_file = RESULTS_DIR / job_id / "root_causes.json"
    if not root_causes_file.exists():
        return None

    with open(root_causes_file, "r", encoding="utf-8") as f:
        return json.load(f)


def packet_belongs_to_stream(packet, stream):
    if packet.get("protocol") != stream.get("protocol"):
        return False

    src = packet.get("src")
    dst = packet.get("dst")
    src_port = packet.get("src_port")
    dst_port = packet.get("dst_port")

    a_ip = stream.get("endpoint_a_ip")
    a_port = stream.get("endpoint_a_port")
    b_ip = stream.get("endpoint_b_ip")
    b_port = stream.get("endpoint_b_port")

    forward = src == a_ip and dst == b_ip and src_port == a_port and dst_port == b_port
    reverse = src == b_ip and dst == a_ip and src_port == b_port and dst_port == a_port

    return forward or reverse


def load_packets_for_stream(job_id: str, stream_id: str):
    packets = load_packets(job_id)
    streams = load_streams(job_id)

    if not packets or not streams:
        return None

    target_stream = None
    for stream in streams:
        if stream.get("stream_id") == stream_id:
            target_stream = stream
            break

    if target_stream is None:
        return None

    filtered = [pkt for pkt in packets if packet_belongs_to_stream(pkt, target_stream)]

    return {
        "stream": target_stream,
        "packets": filtered[:1000],
    }


def load_summary(job_id: str) -> dict | None:
    summary_file = RESULTS_DIR / job_id / "summary.json"
    if not summary_file.exists():
        return None

    with open(summary_file, "r", encoding="utf-8") as f:
        return json.load(f)

def score_stream_criticality(stream: dict):
    score = 0
    reasons = []

    handshake = stream.get("handshake_status")
    health = stream.get("stream_health")

    retrans = int(stream.get("retransmission_count") or 0)
    dupacks = int(stream.get("duplicate_ack_count") or 0)
    zerowin = int(stream.get("zero_window_count") or 0)
    rtt = stream.get("handshake_rtt_ms")
    throughput = stream.get("throughput_bps") or 0
    flags = set(stream.get("tcp_flags_seen") or [])

    if handshake == "syn_seen_no_synack":
        score += 5
        reasons.append("SYN seen but no SYN-ACK")

    if retrans > 0:
        score += min(5, max(1, retrans // 2))
        reasons.append(f"Retransmissions: {retrans}")

    if "R" in flags:
        score += 4
        reasons.append("RST observed")

    if zerowin > 0:
        score += min(4, max(2, zerowin))
        reasons.append(f"Zero-window: {zerowin}")

    if dupacks > 0:
        score += min(3, max(1, dupacks // 3))
        reasons.append(f"Duplicate ACKs: {dupacks}")

    if health == "one_sided":
        score += 2
        reasons.append("One-sided traffic")

    if rtt:
        try:
            r = float(rtt)
            if r > 100:
                score += 3
                reasons.append(f"High RTT: {r} ms")
            elif r > 50:
                score += 2
                reasons.append(f"Elevated RTT: {r} ms")
        except:
            pass

    if score >= 10:
        severity = "high"
    elif score >= 5:
        severity = "medium"
    elif score > 0:
        severity = "low"
    else:
        severity = "info"

    return {
        "criticality_score": score,
        "criticality_severity": severity,
        "criticality_reason": "; ".join(reasons) if reasons else "No major issue indicators",
    }



def derive_directional_hint(stream: dict):
    a_to_b = int(stream.get("packets_a_to_b") or 0)
    b_to_a = int(stream.get("packets_b_to_a") or 0)

    if a_to_b > 0 and b_to_a == 0:
        return "A -> B only"
    if b_to_a > 0 and a_to_b == 0:
        return "B -> A only"

    if a_to_b == 0 and b_to_a == 0:
        return "No directional evidence"

    high = max(a_to_b, b_to_a)
    low = min(a_to_b, b_to_a)

    if low == 0:
        return "One-sided"

    ratio = high / low if low else 9999

    if ratio >= 4:
        return "Mostly A -> B" if a_to_b > b_to_a else "Mostly B -> A"

    return "Bidirectional"


def derive_impact_hint(stream: dict):
    handshake = stream.get("handshake_status")
    retrans = int(stream.get("retransmission_count") or 0)
    dupacks = int(stream.get("duplicate_ack_count") or 0)
    zerowin = int(stream.get("zero_window_count") or 0)
    flags = set(stream.get("tcp_flags_seen") or [])
    health = stream.get("stream_health")
    duration = float(stream.get("duration_seconds") or 0)
    throughput = float(stream.get("throughput_bps") or 0)

    if handshake == "syn_seen_no_synack":
        return "Connection setup failure likely"

    if zerowin > 0:
        return "Receiver-side slowness likely"

    if retrans > 0 and dupacks > 0:
        return "Packet loss or unstable delivery likely"

    if retrans > 0:
        return "Possible packet loss or retransmission issue"

    if "R" in flags or stream.get("rst_seen"):
        return "Connection reset by endpoint or network device"

    if health == "one_sided" and handshake == "midstream_or_partial_capture":
        return "Partial capture or asymmetric visibility likely"

    if health == "one_sided":
        return "One-sided traffic; possible filtering or return-path issue"

    if duration > 10 and throughput < 10000:
        return "Low throughput or application slowness possible"

    return "No major impact suggested"


def enrich_streams_with_criticality(streams):
    enriched = []

    for s in streams:
        item = dict(s)
        item.update(score_stream_criticality(item))
        item["directional_hint"] = derive_directional_hint(item)
        item["impact_hint"] = derive_impact_hint(item)
        enriched.append(item)

    enriched.sort(
        key=lambda x: (
            -x.get("criticality_score", 0),
            -x.get("retransmission_count", 0),
            -x.get("packet_count", 0),
        )
    )

    return enriched



def _top_destinations_from_streams(streams, limit=5):
    counts = {}
    for s in streams:
        key = f'{s.get("endpoint_b_ip", "-")}:{s.get("endpoint_b_port", "-")}'
        counts[key] = counts.get(key, 0) + 1
    return [
        {"destination": dest, "count": count}
        for dest, count in sorted(counts.items(), key=lambda x: x[1], reverse=True)[:limit]
    ]


def _recommended_actions_for_category(category: str):
    mapping = {
        "connection_setup_failure": [
            "Check firewall or ACL drops for SYN traffic",
            "Verify destination service is listening on the target port",
            "Validate routing and return-path symmetry",
        ],
        "network_loss_or_instability": [
            "Check packet loss, interface errors, and path stability",
            "Review congested links and WAN path behavior",
            "Inspect retransmission-heavy destinations and intermediate devices",
        ],
        "receiver_pressure": [
            "Review receiver application responsiveness",
            "Check host resource pressure and TCP receive window behavior",
            "Inspect storage or application read bottlenecks",
        ],
        "connection_reset": [
            "Check whether the endpoint or security device is resetting sessions",
            "Review idle timeout and policy enforcement behavior",
            "Inspect application-side resets and TLS/session teardown",
        ],
        "capture_asymmetry": [
            "Validate SPAN/TAP placement and capture directionality",
            "Check whether only one side of the flow is visible",
            "Confirm there is no asymmetric routing missing from the capture point",
        ],
    }
    return mapping.get(category, ["Review affected endpoints and validate packet path and application behavior"])


def build_root_cause_engine_v2(streams):
    critical = [s for s in streams if (s.get("criticality_score") or 0) > 0]

    groups = {
        "connection_setup_failure": [],
        "network_loss_or_instability": [],
        "receiver_pressure": [],
        "connection_reset": [],
        "capture_asymmetry": [],
    }

    for s in critical:
        impact = (s.get("impact_hint") or "").lower()
        directional = (s.get("directional_hint") or "").lower()
        reason = (s.get("criticality_reason") or "").lower()

        if "connection setup failure" in impact:
            groups["connection_setup_failure"].append(s)
        elif "receiver-side slowness" in impact:
            groups["receiver_pressure"].append(s)
        elif "reset" in impact:
            groups["connection_reset"].append(s)
        elif "partial capture" in impact or "asymmetric" in impact:
            groups["capture_asymmetry"].append(s)
        elif "packet loss" in impact or "retransmission" in impact or "duplicate ack" in reason:
            groups["network_loss_or_instability"].append(s)
        elif "one-sided" in directional:
            groups["capture_asymmetry"].append(s)

    results = []

    labels = {
        "connection_setup_failure": "Likely failed connection establishment",
        "network_loss_or_instability": "Likely packet loss or unstable delivery",
        "receiver_pressure": "Likely receiver-side pressure or application slowness",
        "connection_reset": "Likely active connection reset behavior",
        "capture_asymmetry": "Likely incomplete or asymmetric visibility",
    }

    for category, items in groups.items():
        if not items:
            continue

        total_score = sum(int(s.get("criticality_score") or 0) for s in items)
        avg_score = total_score / max(len(items), 1)
        confidence = round(min(0.95, 0.35 + (avg_score / 15.0) + (len(items) / max(len(critical), 1)) * 0.25), 2)

        top_dests = _top_destinations_from_streams(items, limit=5)

        results.append({
            "category": category,
            "title": labels[category],
            "confidence": confidence,
            "affected_streams": len(items),
            "top_impacted_destinations": top_dests,
            "recommended_actions": _recommended_actions_for_category(category),
            "example_reasons": sorted(
                {s.get("criticality_reason", "-") for s in items if s.get("criticality_reason")},
                key=len
            )[:5],
        })

    results.sort(key=lambda r: (r["confidence"], r["affected_streams"]), reverse=True)
    return results


def save_root_causes_v2(job_id: str, streams):
    result_dir = RESULTS_DIR / job_id
    result_dir.mkdir(parents=True, exist_ok=True)

    output = build_root_cause_engine_v2(streams)
    with open(result_dir / "root_causes_v2.json", "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


def load_root_causes_v2(job_id: str):
    path = RESULTS_DIR / job_id / "root_causes_v2.json"
    if not path.exists():
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)





def classify_stream_issue_type(stream: dict):
    impact = (stream.get("impact_hint") or "").lower()
    reason = (stream.get("criticality_reason") or "").lower()
    severity = (stream.get("criticality_severity") or "").lower()

    if "connection setup failure" in impact or "syn seen but no syn-ack" in reason:
        return "connection_setup_failure"
    if "receiver-side slowness" in impact or "zero-window" in reason:
        return "receiver_pressure"
    if "packet loss" in impact or "retransmission" in impact or "duplicate ack" in reason:
        return "network_loss_or_instability"
    if "reset" in impact or "rst observed" in reason:
        return "connection_reset"
    if "partial capture" in impact or "asymmetric" in impact or "one-sided traffic" in reason:
        return "capture_asymmetry"
    if severity in {"high", "medium", "low"}:
        return "other_critical"
    return "informational"


def normalize_timeline_output(timeline: dict):
    if not timeline or timeline.get("first_issue_seen") is None:
        return timeline

    base = float(timeline["first_issue_seen"])

    timeline["first_issue_seen"] = 0
    if timeline.get("last_issue_seen") is not None:
        timeline["last_issue_seen"] = round(float(timeline["last_issue_seen"]) - base, 2)

    peak = timeline.get("peak_issue_window")
    if peak:
        peak["window_start_seconds"] = round(float(peak.get("window_start_seconds", 0)), 2)
        peak["window_end_seconds"] = round(float(peak.get("window_end_seconds", 0)), 2)

    for b in timeline.get("timeline_buckets", []):
        b["offset_seconds"] = round(float(b.get("offset_seconds", 0)), 2)

    return timeline


def build_timeline_analysis(streams, bucket_seconds=10):
    critical = [
        s for s in streams
        if (s.get("criticality_score") or 0) > 0 and s.get("start_time") is not None
    ]

    if not critical:
        return {
            "bucket_seconds": bucket_seconds,
            "first_issue_seen": None,
            "last_issue_seen": None,
            "peak_issue_window": None,
            "dominant_issue_type_in_peak": None,
            "total_critical_streams": 0,
            "timeline_buckets": [],
        }

    first_seen = min(float(s.get("start_time")) for s in critical)
    last_seen = max(float(s.get("end_time") or s.get("start_time")) for s in critical)

    buckets = {}
    for s in critical:
        start_time = float(s.get("start_time"))
        offset = start_time - first_seen
        bucket_start = int(offset // bucket_seconds) * bucket_seconds
        issue_type = classify_stream_issue_type(s)

        if bucket_start not in buckets:
            buckets[bucket_start] = {
                "offset_seconds": bucket_start,
                "critical_streams": 0,
                "issue_type_counts": {},
            }

        buckets[bucket_start]["critical_streams"] += 1
        buckets[bucket_start]["issue_type_counts"][issue_type] = (
            buckets[bucket_start]["issue_type_counts"].get(issue_type, 0) + 1
        )

    timeline_buckets = []
    for offset in sorted(buckets.keys()):
        item = buckets[offset]
        dominant = None
        if item["issue_type_counts"]:
            dominant = sorted(
                item["issue_type_counts"].items(),
                key=lambda x: x[1],
                reverse=True,
            )[0][0]

        timeline_buckets.append({
            "offset_seconds": item["offset_seconds"],
            "critical_streams": item["critical_streams"],
            "dominant_issue_type": dominant,
            "issue_type_counts": item["issue_type_counts"],
        })

    peak_bucket = sorted(
        timeline_buckets,
        key=lambda x: (x["critical_streams"], x["offset_seconds"]),
        reverse=True,
    )[0]

    result = {
        "bucket_seconds": bucket_seconds,
        "first_issue_seen": first_seen,
        "last_issue_seen": last_seen,
        "peak_issue_window": {
            "offset_seconds": peak_bucket["offset_seconds"],
            "window_start_seconds": peak_bucket["offset_seconds"],
            "window_end_seconds": peak_bucket["offset_seconds"] + bucket_seconds,
            "critical_streams": peak_bucket["critical_streams"],
        },
        "dominant_issue_type_in_peak": peak_bucket["dominant_issue_type"],
        "total_critical_streams": len(critical),
        "timeline_buckets": timeline_buckets,
    }

    return normalize_timeline_output(result)


def save_timeline_analysis(job_id: str, streams):
    result_dir = RESULTS_DIR / job_id
    result_dir.mkdir(parents=True, exist_ok=True)

    output = build_timeline_analysis(streams, bucket_seconds=10)
    with open(result_dir / "timeline_analysis.json", "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)


def load_timeline_analysis(job_id: str):
    path = RESULTS_DIR / job_id / "timeline_analysis.json"
    if not path.exists():
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def parse_http_payload(payload_text: str):
    if not payload_text:
        return None

    lines = payload_text.splitlines()
    if not lines:
        return None

    first = lines[0].strip()
    headers = {}

    for line in lines[1:]:
        if not line.strip():
            break
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()

    methods = ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH")
    if any(first.startswith(m + " ") for m in methods):
        parts = first.split()
        return {
            "type": "request",
            "method": parts[0] if len(parts) > 0 else None,
            "path": parts[1] if len(parts) > 1 else None,
            "host": headers.get("host"),
            "user_agent": headers.get("user-agent"),
            "status_code": None,
            "first_line": first,
        }

    if first.startswith("HTTP/"):
        parts = first.split()
        status_code = None
        if len(parts) > 1 and parts[1].isdigit():
            status_code = int(parts[1])

        return {
            "type": "response",
            "method": None,
            "path": None,
            "host": headers.get("host"),
            "user_agent": headers.get("user-agent"),
            "status_code": status_code,
            "first_line": first,
        }

    return None


def extract_http_records(job_id: str):
    packets = load_packets(job_id)
    if not packets:
        return []

    records = []

    for pkt in packets:
        protocol = str(pkt.get("protocol") or "").upper()
        src_port = pkt.get("src_port")
        dst_port = pkt.get("dst_port")
        info = str(pkt.get("info") or "")
        payload = pkt.get("payload_text") or pkt.get("payload") or ""

        looks_http_port = src_port in (80, 8080, 8000) or dst_port in (80, 8080, 8000)
        looks_http_text = (
            "HTTP/" in payload
            or payload.startswith("GET ")
            or payload.startswith("POST ")
            or payload.startswith("PUT ")
            or payload.startswith("DELETE ")
            or payload.startswith("HEAD ")
            or payload.startswith("OPTIONS ")
            or payload.startswith("PATCH ")
        )

        if not (looks_http_port or looks_http_text):
            continue

        parsed = parse_http_payload(payload)
        if not parsed:
            continue

        record = {
            "frame": pkt.get("frame"),
            "time": pkt.get("time"),
            "src": pkt.get("src"),
            "dst": pkt.get("dst"),
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": "HTTP",
            "info": info,
            "stream_id": pkt.get("stream_id"),
            **parsed,
        }
        records.append(record)

    return records


def _dns_qname_safe(dns_layer):
    try:
        if dns_layer.qd is None:
            return None
        qname = dns_layer.qd.qname
        if isinstance(qname, bytes):
            qname = qname.decode("utf-8", errors="ignore")
        return str(qname).rstrip(".")
    except Exception:
        return None


def _dns_qtype_safe(dns_layer):
    try:
        if dns_layer.qd is None:
            return None
        qtype = int(dns_layer.qd.qtype)
        qmap = {
            1: "A",
            2: "NS",
            5: "CNAME",
            6: "SOA",
            12: "PTR",
            15: "MX",
            16: "TXT",
            28: "AAAA",
            33: "SRV",
            65: "HTTPS",
        }
        return qmap.get(qtype, str(qtype))
    except Exception:
        return None




def _dns_answers_safe(dns_layer):
    answers = []
    try:
        ancount = int(getattr(dns_layer, "ancount", 0) or 0)
        for i in range(ancount):
            rr = dns_layer.an[i]
            rrname = getattr(rr, "rrname", None)
            if isinstance(rrname, bytes):
                rrname = rrname.decode("utf-8", errors="ignore").rstrip(".")
            elif rrname is not None:
                rrname = str(rrname).rstrip(".")

            rdata = getattr(rr, "rdata", None)
            if isinstance(rdata, bytes):
                rdata = rdata.decode("utf-8", errors="ignore").rstrip(".")
            elif rdata is not None:
                rdata = str(rdata).rstrip(".")

            answers.append({
                "name": rrname,
                "type": int(getattr(rr, "type", 0) or 0),
                "ttl": int(getattr(rr, "ttl", 0) or 0),
                "rdata": rdata,
            })
    except Exception:
        pass
    return answers

def _dns_rcode_text(rcode):
    mapping = {
        0: "NOERROR",
        1: "FORMERR",
        2: "SERVFAIL",
        3: "NXDOMAIN",
        4: "NOTIMP",
        5: "REFUSED",
    }
    return mapping.get(int(rcode), str(rcode))


def _dns_latency_class(latency_ms):
    if latency_ms is None:
        return "no_response"
    if latency_ms <= 50:
        return "fast"
    if latency_ms <= 150:
        return "moderate"
    if latency_ms <= 500:
        return "slow"
    return "very_slow"


def _dns_interpretation(latency_ms, rcode_text, answered):
    if not answered:
        return (
            "DNS query observed but no matching response was seen. "
            "Likely causes include packet loss, firewall/filtering, resolver timeout, asymmetric routing, or one-sided capture."
        )

    if latency_ms is None:
        return (
            "DNS response observed without the matching query. "
            "Likely causes include capture started late, asymmetric capture, SPAN direction mismatch, NAT/proxy transformation, or missing request path visibility."
        )

    if rcode_text == "SERVFAIL":
        return "DNS resolver returned SERVFAIL. Check resolver health, upstream forwarding, DNSSEC validation, or recursive lookup failures."

    if rcode_text == "NXDOMAIN":
        return "DNS returned NXDOMAIN. Check hostname typo, split-DNS policy, DNS suffix behavior, or stale application configuration."

    if rcode_text == "REFUSED":
        return "DNS resolver refused the query. Check resolver ACLs, policy, or client authorization."

    if latency_ms > 500:
        return f"Very slow DNS resolution ({latency_ms} ms). This can significantly delay application connection setup before TCP/TLS begins."

    if latency_ms > 150:
        return f"Slow DNS resolution ({latency_ms} ms). This may contribute to application startup or connection latency."

    return f"DNS response latency appears normal ({latency_ms} ms)."

def extract_dns_transactions(job_id: str):
    result_dir = RESULTS_DIR / job_id
    pcap_files = list(result_dir.glob("*.pcap")) + list(result_dir.glob("*.pcapng"))

    # DNS_JSON_FALLBACK: if raw PCAP is not copied into result dir, fallback to packet JSON.
    if not pcap_files:
        packets_json = load_packets(job_id)
        observations = []
        for pkt in packets_json or []:
            try:
                if not (
                    str(pkt.get("protocol", "")).upper() == "DNS"
                    or pkt.get("src_port") == 53
                    or pkt.get("dst_port") == 53
                ):
                    continue

                observations.append({
                    "transaction_id": None,
                    "query_name": None,
                    "query_type": None,
                    "client": pkt.get("src"),
                    "server": pkt.get("dst"),
                    "client_port": pkt.get("src_port"),
                    "server_port": pkt.get("dst_port"),
                    "query_time": pkt.get("time"),
                    "response_time": None,
                    "latency_ms": None,
                    "rcode": None,
                    "rcode_text": None,
                    "answered": None,
                    "answer_count": None,
                    "latency_class": "packet_observation_only",
                    "interpretation": "DNS packet observed, but raw PCAP is not available for transaction pairing. Store uploaded PCAP in the job directory to calculate query-response latency.",
                    "frame": pkt.get("frame"),
                    "info": pkt.get("info"),
                })
            except Exception:
                continue
        return observations

    packets = rdpcap(str(pcap_files[0]))
    packets = sorted(packets, key=lambda p: float(p.time))

    pending = {}
    transactions = []

    for pkt in packets:
        try:
            if not pkt.haslayer(DNS):
                continue

            dns = pkt[DNS]
            src_ip, dst_ip = extract_ip_addresses(pkt)
            src_port, dst_port = get_transport_ports(pkt)
            pkt_time = float(pkt.time)

            txid = int(dns.id)
            qname = _dns_qname_safe(dns)
            qtype = _dns_qtype_safe(dns)

            key = (txid, qname, qtype, src_ip, dst_ip)

            if int(dns.qr) == 0:
                pending[key] = {
                    "transaction_id": txid,
                    "query_name": qname,
                    "query_type": qtype,
                    "client": src_ip,
                    "server": dst_ip,
                    "client_port": src_port,
                    "server_port": dst_port,
                    "query_time": pkt_time,
                    "response_time": None,
                    "latency_ms": None,
                    "rcode": None,
                    "rcode_text": None,
                    "answered": False,
                    "answer_count": None,
                    "answers": [],
                    "answer_ips": [],
                    "latency_class": "no_response",
                    "interpretation": "DNS query did not receive a visible response in this capture. Possible DNS timeout, packet loss, blocked resolver, or one-sided capture.",
                }
                continue

            # Response: reverse endpoints compared to query
            response_key = (txid, qname, qtype, dst_ip, src_ip)
            query = pending.pop(response_key, None)

            rcode_text = _dns_rcode_text(int(dns.rcode))
            answer_count = int(getattr(dns, "ancount", 0))
            answers = _dns_answers_safe(dns)
            answer_ips = [
                a.get("rdata") for a in answers
                if a.get("type") in (1, 28) and a.get("rdata")
            ]

            if query:
                latency_ms = round((pkt_time - query["query_time"]) * 1000, 3)
                query.update({
                    "response_time": pkt_time,
                    "latency_ms": latency_ms,
                    "rcode": int(dns.rcode),
                    "rcode_text": rcode_text,
                    "answered": True,
                    "answer_count": answer_count,
                    "answers": answers,
                    "answer_ips": answer_ips,
                    "latency_class": _dns_latency_class(latency_ms),
                    "interpretation": _dns_interpretation(latency_ms, rcode_text, True),
                })
                transactions.append(query)
            else:
                transactions.append({
                    "transaction_id": txid,
                    "query_name": qname,
                    "query_type": qtype,
                    "client": dst_ip,
                    "server": src_ip,
                    "client_port": dst_port,
                    "server_port": src_port,
                    "query_time": None,
                    "response_time": pkt_time,
                    "latency_ms": None,
                    "rcode": int(dns.rcode),
                    "rcode_text": rcode_text,
                    "answered": True,
                    "answer_count": answer_count,
                    "answers": answers,
                    "answer_ips": answer_ips,
                    "latency_class": "response_without_query",
                    "interpretation": "DNS response observed without the matching query. This may indicate capture started late or only one direction was captured.",
                })

        except Exception:
            continue

    # Remaining unanswered queries
    transactions.extend(pending.values())

    transactions.sort(key=lambda x: x.get("query_time") or x.get("response_time") or 0)
    return transactions


def summarize_dns_health(job_id: str):
    records = extract_dns_transactions(job_id)

    total = len(records)
    answered = [r for r in records if r.get("answered") is True and r.get("latency_ms") is not None]
    no_response = [r for r in records if r.get("latency_class") == "no_response"]
    response_without_query = [r for r in records if r.get("latency_class") == "response_without_query"]
    slow = [r for r in records if r.get("latency_class") == "slow"]
    very_slow = [r for r in records if r.get("latency_class") == "very_slow"]
    failures = [r for r in records if r.get("rcode_text") in ("SERVFAIL", "NXDOMAIN", "REFUSED")]

    latencies = [r.get("latency_ms") for r in answered if isinstance(r.get("latency_ms"), (int, float))]

    avg_latency = round(sum(latencies) / len(latencies), 3) if latencies else None
    max_latency = round(max(latencies), 3) if latencies else None

    no_response_rate = round((len(no_response) / total) * 100, 2) if total else 0
    response_without_query_rate = round((len(response_without_query) / total) * 100, 2) if total else 0
    slow_rate = round(((len(slow) + len(very_slow)) / total) * 100, 2) if total else 0

    if total == 0:
        health = "no_dns_observed"
        summary = "No visible DNS traffic was found in this capture."
        action = "If DNS diagnosis is required, capture UDP/TCP port 53 traffic or verify whether the environment uses DoH/DoT."
    elif no_response_rate > 50 or response_without_query_rate > 30:
        health = "dns_visibility_or_response_problem"
        summary = (
            "DNS traffic is visible, but many queries/responses cannot be paired. "
            "This suggests DNS timeout/loss, asymmetric routing, one-sided capture, or SPAN direction issues."
        )
        action = "Check capture point, SPAN direction, resolver reachability, firewall rules, and whether DNS response path is asymmetric."
    elif len(very_slow) > 0 or slow_rate > 20:
        health = "slow_dns"
        summary = (
            "DNS responses are present but slow for a meaningful portion of transactions. "
            "DNS latency may delay application connection setup before TCP/TLS starts."
        )
        action = "Check DNS resolver load, forwarding path, upstream recursive DNS, packet loss to resolver, and resolver cache behavior."
    elif failures:
        health = "dns_resolution_errors"
        summary = "DNS responses include resolution failures such as SERVFAIL, NXDOMAIN, or REFUSED."
        action = "Check application hostname, split-DNS policy, resolver ACLs, DNSSEC validation, and upstream zone health."
    else:
        health = "dns_healthy"
        summary = "DNS query-response behavior appears healthy from this capture."
        action = "No DNS-specific action indicated from current evidence."

    top_domains = {}
    for r in records:
        q = r.get("query_name")
        if not q:
            continue
        top_domains.setdefault(q, {"query_name": q, "count": 0, "no_response": 0, "slow": 0, "failures": 0})
        top_domains[q]["count"] += 1
        if r.get("latency_class") == "no_response":
            top_domains[q]["no_response"] += 1
        if r.get("latency_class") in ("slow", "very_slow"):
            top_domains[q]["slow"] += 1
        if r.get("rcode_text") in ("SERVFAIL", "NXDOMAIN", "REFUSED"):
            top_domains[q]["failures"] += 1

    top_domains = sorted(top_domains.values(), key=lambda x: (x["no_response"], x["slow"], x["count"]), reverse=True)[:10]

    return {
        "total_dns_records": total,
        "answered_with_latency": len(answered),
        "no_response_count": len(no_response),
        "response_without_query_count": len(response_without_query),
        "slow_count": len(slow),
        "very_slow_count": len(very_slow),
        "failure_count": len(failures),
        "avg_latency_ms": avg_latency,
        "max_latency_ms": max_latency,
        "no_response_rate_pct": no_response_rate,
        "response_without_query_rate_pct": response_without_query_rate,
        "slow_rate_pct": slow_rate,
        "dns_health": health,
        "summary": summary,
        "engineer_action": action,
        "top_domains": top_domains,
    }


def correlate_dns_to_tcp(job_id: str, max_gap_seconds: float = 30.0):
    dns_records = extract_dns_transactions(job_id)
    streams = load_streams(job_id) or []

    tcp_streams = [
        s for s in streams
        if str(s.get("protocol", "")).upper() == "TCP"
    ]

    correlations = []

    for d in dns_records:
        query_name = d.get("query_name")
        response_time = d.get("response_time")
        answer_ips = d.get("answer_ips") or []

        if not query_name or not response_time or not answer_ips:
            continue

        for s in tcp_streams:
            start_time = s.get("start_time")
            if start_time is None:
                continue

            try:
                gap_ms = round((float(start_time) - float(response_time)) * 1000, 3)
            except Exception:
                continue

            if gap_ms < 0 or gap_ms > max_gap_seconds * 1000:
                continue

            endpoint_a = s.get("endpoint_a_ip")
            endpoint_b = s.get("endpoint_b_ip")

            matched_ip = None
            match_type = "none"

            if endpoint_a in answer_ips:
                matched_ip = endpoint_a
                match_type = "dns_answer_ip_to_tcp_endpoint"
            elif endpoint_b in answer_ips:
                matched_ip = endpoint_b
                match_type = "dns_answer_ip_to_tcp_endpoint"

            # Fallback: enterprise proxy/CDN cases where DNS answer IP may not equal final TCP endpoint
            if not matched_ip:
                sni = (s.get("tls_sni") or "").lower()
                app = (s.get("application") or "").lower()
                q = (query_name or "").lower()

                if q and sni and (q == sni or q in sni or sni in q):
                    matched_ip = endpoint_b or endpoint_a
                    match_type = "dns_name_to_tls_sni"
                elif q and app and q in app:
                    matched_ip = endpoint_b or endpoint_a
                    match_type = "dns_name_to_application_hint"

            # FINAL fallback: match by time proximity (DNS → TCP)
            if not matched_ip:
                try:
                    dns_time = float(c.get("response_time") or c.get("query_time") or 0)
                    tcp_time = float(s.get("start_time") or 0)

                    # if TCP starts within 2 seconds of DNS, assume relation
                    if dns_time and tcp_time and abs(tcp_time - dns_time) < 2:
                        matched_ip = endpoint_b or endpoint_a
                        match_type = "time_proximity_match"
                except Exception:
                    pass

            # FINAL fallback: domain + time proximity (handles missing SNI / proxy cases)
            if not matched_ip:
                try:
                    dns_time = float(c.get("response_time") or c.get("query_time") or 0)
                    tcp_time = float(s.get("start_time") or 0)
                    q = (query_name or "").lower()

                    # wider window: 5 seconds (enterprise realistic)
                    if dns_time and tcp_time and abs(tcp_time - dns_time) < 5:
                        matched_ip = endpoint_b or endpoint_a
                        match_type = "domain_time_fallback_match"

                except Exception:
                    pass

            if not matched_ip:
                continue

            dns_latency = d.get("latency_ms")
            dns_class = d.get("latency_class")

            if dns_latency is None:
                impact = "unknown"
                interpretation = "DNS response was linked to a TCP connection, but DNS latency could not be calculated."
            elif dns_latency > 500:
                impact = "high"
                interpretation = (
                    f"TCP connection started {gap_ms} ms after a very slow DNS response "
                    f"({dns_latency} ms). DNS likely contributed significant connection setup delay."
                )
            elif dns_latency > 150:
                impact = "medium"
                interpretation = (
                    f"TCP connection started {gap_ms} ms after a slow DNS response "
                    f"({dns_latency} ms). DNS may have contributed to application connection delay."
                )
            else:
                impact = "low"
                interpretation = (
                    f"TCP connection started {gap_ms} ms after DNS resolution. "
                    f"DNS latency ({dns_latency} ms) does not appear to be the primary delay contributor."
                )

            correlations.append({
                "query_name": query_name,
                "query_type": d.get("query_type"),
                "dns_server": d.get("server"),
                "dns_client": d.get("client"),
                "answer_ip": matched_ip,
                "match_type": match_type,
                "all_answer_ips": answer_ips,
                "dns_latency_ms": dns_latency,
                "dns_latency_class": dns_class,
                "dns_response_time": response_time,
                "tcp_stream_id": s.get("stream_id"),
                "tcp_start_time": start_time,
                "dns_to_tcp_gap_ms": gap_ms,
                "tcp_endpoint_a": endpoint_a,
                "tcp_endpoint_b": endpoint_b,
                "tcp_application": s.get("application"),
                "tcp_sni": s.get("tls_sni"),
                "tcp_health": s.get("health") or s.get("criticality_category"),
                "tcp_limiter": s.get("tcp_limiter"),
                "tcp_bif_interpretation": s.get("tcp_bif_interpretation"),
                "impact": impact,
                "interpretation": interpretation,
            })

    correlations.sort(
        key=lambda x: (
            {"high": 3, "medium": 2, "low": 1, "unknown": 0}.get(x.get("impact"), 0),
            x.get("dns_latency_ms") or 0,
            -x.get("dns_to_tcp_gap_ms", 0),
        ),
        reverse=True,
    )

    total = len(correlations)
    high = len([c for c in correlations if c.get("impact") == "high"])
    medium = len([c for c in correlations if c.get("impact") == "medium"])

    if total == 0:
        summary = "No DNS-to-TCP timing correlation found. This may mean DNS answers do not expose final TCP destination IPs, traffic uses proxy/CDN indirection, or TCP starts outside the correlation window."
        health = "no_correlation"
    elif high > 0:
        summary = "One or more TCP connections started after very slow DNS responses. DNS is likely contributing to connection setup delay for affected destinations."
        health = "dns_delay_impacts_tcp"
    elif medium > 0:
        summary = "Some TCP connections started after moderately slow DNS responses. DNS may contribute to perceived application startup delay."
        health = "dns_may_impact_tcp"
    else:
        summary = "DNS-to-TCP correlations were found, but DNS latency appears low for correlated TCP connections."
        health = "dns_tcp_correlation_healthy"

    return {
        "total_correlations": total,
        "high_impact_count": high,
        "medium_impact_count": medium,
        "dns_tcp_health": health,
        "summary": summary,
        "correlations": correlations[:5000],
    }



def _safe_num(value):
    try:
        if value is None:
            return None
        return float(value)
    except Exception:
        return None


def _latency_chain_phase_label(ms):
    if ms is None:
        return "unknown"
    if ms <= 50:
        return "fast"
    if ms <= 150:
        return "moderate"
    if ms <= 500:
        return "slow"
    return "very_slow"


def build_latency_chain(job_id: str):
    dns_tcp = correlate_dns_to_tcp(job_id)
    correlations = dns_tcp.get("correlations", []) or []
    streams = load_streams(job_id) or []

    stream_by_id = {
        s.get("stream_id"): s
        for s in streams
        if s.get("stream_id")
    }

    chains = []

    for c in correlations:
        stream_id = c.get("tcp_stream_id")
        stream = stream_by_id.get(stream_id, {})

        dns_latency = _safe_num(c.get("dns_latency_ms"))
        dns_to_tcp_gap = _safe_num(c.get("dns_to_tcp_gap_ms"))

        tcp_rtt = _safe_num(
            stream.get("handshake_rtt_ms")
            or stream.get("rtt_ms")
            or stream.get("tcp_rtt_ms")
        )

        tls_handshake_ms = _safe_num(
            stream.get("tls_handshake_duration_ms")
            or stream.get("tls_handshake_ms")
            or stream.get("handshake_duration_ms")
        )

        duration = _safe_num(stream.get("duration"))
        throughput = _safe_num(stream.get("throughput_bps"))
        first_server_data_ms = _safe_num(stream.get("first_server_data_ms"))
        retrans = stream.get("retransmission_count") or 0
        dup_ack = stream.get("duplicate_ack_count") or 0
        zero_win = stream.get("zero_window_count") or 0

        tcp_limiter = stream.get("tcp_limiter") or c.get("tcp_limiter")
        bif_text = stream.get("tcp_bif_interpretation") or c.get("tcp_bif_interpretation")

        phases = {
            "dns_resolution_ms": dns_latency,
            "dns_to_tcp_gap_ms": dns_to_tcp_gap,
            "tcp_handshake_rtt_ms": tcp_rtt,
            "tls_handshake_ms": tls_handshake_ms,
            "application_transfer_duration_s": duration,
            "first_server_data_ms": first_server_data_ms,
        }

        bottleneck = "unknown"
        severity = "low"
        explanation = []
        action = []

        if dns_latency is not None and dns_latency > 500:
            bottleneck = "dns_resolution"
            severity = "high"
            explanation.append(f"DNS resolution is very slow ({dns_latency} ms) before TCP starts.")
            action.append("Check DNS resolver load, forwarding path, upstream recursive DNS, DNSSEC, or packet loss to resolver.")
        elif dns_latency is not None and dns_latency > 150:
            bottleneck = "dns_resolution"
            severity = "medium"
            explanation.append(f"DNS resolution is slow ({dns_latency} ms) and may delay application startup.")
            action.append("Check resolver response time, cache behavior, forwarding path, and DNS server selection.")

        if dns_to_tcp_gap is not None and dns_to_tcp_gap > 3000:
            if severity != "high":
                severity = "medium"
            if bottleneck == "unknown":
                bottleneck = "application_wait_after_dns"
            explanation.append(f"TCP connection starts {dns_to_tcp_gap} ms after DNS response, suggesting application wait/retry/proxy delay after resolution.")
            action.append("Check application connection scheduling, proxy behavior, browser connection reuse, or delayed retry logic.")

        if tcp_rtt is not None and tcp_rtt > 300:
            severity = "high"
            bottleneck = "tcp_handshake_latency"
            explanation.append(f"TCP handshake RTT is high ({tcp_rtt} ms), indicating network path latency or SYN/SYN-ACK delay.")
            action.append("Check WAN latency, routing path, firewall SYN inspection, proxy path, or server proximity.")
        elif tcp_rtt is not None and tcp_rtt > 150 and severity == "low":
            severity = "medium"
            bottleneck = "tcp_handshake_latency"
            explanation.append(f"TCP handshake RTT is elevated ({tcp_rtt} ms).")
            action.append("Check routing path and network latency between client and destination.")

        if tls_handshake_ms is not None and tls_handshake_ms > 1000:
            severity = "high"
            bottleneck = "tls_handshake_latency"
            explanation.append(f"TLS handshake is very slow ({tls_handshake_ms} ms), which can delay secure application setup.")
            action.append("Check TLS inspection/proxy, certificate validation, server response delay, and packet loss during handshake.")
        elif tls_handshake_ms is not None and tls_handshake_ms > 300 and severity != "high":
            severity = "medium"
            bottleneck = "tls_handshake_latency"
            explanation.append(f"TLS handshake is slow ({tls_handshake_ms} ms).")
            action.append("Check TLS inspection, certificate chain retrieval, proxy latency, or server delay.")

        if tcp_limiter == "network_loss_or_congestion":
            severity = "high" if (retrans > 50 or dup_ack > 500) else max(severity, "medium", key=["low","medium","high"].index)
            bottleneck = "network_loss_or_congestion"
            explanation.append("TCP evidence indicates packet loss/reordering/congestion after DNS resolution.")
            if bif_text:
                explanation.append(bif_text)
            action.append("Check packet drops, QoS, WAN congestion, interface errors, firewall/proxy drops, or wireless instability.")

        elif tcp_limiter == "receiver_limited":
            if severity == "low":
                severity = "medium"
            bottleneck = "receiver_limited"
            explanation.append("Receiver-limited behavior observed after connection setup.")
            if zero_win:
                explanation.append(f"Zero-window events observed: {zero_win}.")
            action.append("Check receiving host CPU/memory/socket buffers and application read performance.")

        elif tcp_limiter == "application_limited" and bottleneck == "unknown":
            bottleneck = "application_limited"
            explanation.append("TCP transport does not appear fully utilized; application may not be sending enough data.")
            action.append("Check application think time, request size, connection reuse, and server response pacing.")

        if first_server_data_ms is not None and first_server_data_ms > 3000:
            severity = "high"
            bottleneck = "slow_server_or_application_response"
            explanation.append(f"First server/application data arrived after {first_server_data_ms} ms, indicating slow server response, proxy delay, or application processing delay.")
            action.append("Check server processing time, upstream proxy delay, application logs, backend dependency latency, or TLS inspection path.")
        elif first_server_data_ms is not None and first_server_data_ms > 1000 and severity != "high":
            severity = "medium"
            bottleneck = "slow_server_or_application_response"
            explanation.append(f"First server/application data arrived after {first_server_data_ms} ms.")
            action.append("Check server/application response time and proxy path latency.")

        if bottleneck == "unknown":
            bottleneck = "no_dominant_latency_bottleneck"
            explanation.append("No single dominant bottleneck is evident from DNS, TCP, TLS, and transfer signals.")
            action.append("Correlate with user transaction timing and server/application logs.")

        chains.append({
            "query_name": c.get("query_name"),
            "query_type": c.get("query_type"),
            "dns_server": c.get("dns_server"),
            "dns_latency_ms": dns_latency,
            "dns_latency_class": c.get("dns_latency_class"),
            "dns_to_tcp_gap_ms": dns_to_tcp_gap,
            "match_type": c.get("match_type"),
            "answer_ip": c.get("answer_ip"),
            "tcp_stream_id": stream_id,
            "tcp_application": stream.get("application") or c.get("tcp_application"),
            "tcp_sni": stream.get("tls_sni") or c.get("tcp_sni"),
            "tcp_start_time": stream.get("start_time") or c.get("tcp_start_time"),
            "tcp_rtt_ms": tcp_rtt,
            "tls_handshake_ms": tls_handshake_ms,
            "duration_s": duration,
            "throughput_bps": throughput,
            "first_server_data_ms": first_server_data_ms,
            "retransmissions": retrans,
            "duplicate_acks": dup_ack,
            "zero_windows": zero_win,
            "tcp_limiter": tcp_limiter,
            "phases": phases,
            "bottleneck": bottleneck,
            "severity": severity,
            "interpretation": " ".join(explanation),
            "engineer_action": " ".join(dict.fromkeys(action)),
        })

    severity_rank = {"high": 3, "medium": 2, "low": 1}
    chains.sort(
        key=lambda x: (
            severity_rank.get(x.get("severity"), 0),
            x.get("dns_latency_ms") or 0,
            x.get("dns_to_tcp_gap_ms") or 0,
        ),
        reverse=True,
    )

    high = len([x for x in chains if x.get("severity") == "high"])
    medium = len([x for x in chains if x.get("severity") == "medium"])

    if not chains:
        health = "no_latency_chain"
        summary = "No DNS→TCP→TLS→application latency chain could be built."
    elif high:
        health = "latency_chain_critical"
        summary = "High-severity latency chains were found across DNS/TCP/TLS/application phases."
    elif medium:
        health = "latency_chain_degraded"
        summary = "Moderate latency contributors were found across DNS/TCP/TLS/application phases."
    else:
        health = "latency_chain_healthy"
        summary = "No major latency bottleneck was identified in correlated DNS/TCP/TLS/application chains."

    return {
        "total_chains": len(chains),
        "high_count": high,
        "medium_count": medium,
        "latency_chain_health": health,
        "summary": summary,
        "chains": chains[:5000],
    }



def build_rca_summary(job_id: str):
    dns_summary = summarize_dns_health(job_id)
    latency_chain = build_latency_chain(job_id)
    streams = load_streams(job_id) or []

    chains = latency_chain.get("chains", []) or []

    tcp_streams = [s for s in streams if str(s.get("protocol", "")).upper() == "TCP"]

    issue_counts = {}
    affected_domains = {}
    evidence = []
    actions = []

    # MTU / PMTUD / MSS analysis
    try:
        from app.services.mtu_analyzer import analyze_mtu_for_job
        mtu_analysis = analyze_mtu_for_job(job_id)
        mtu_summary = mtu_analysis.get("summary", {}) if isinstance(mtu_analysis, dict) else {}
    except Exception as e:
        mtu_summary = {
            "mtu_health": "unknown",
            "summary": f"MTU analysis failed: {e}",
        }
    first_server_data_values = []
    slow_first_server_data_chains = 0

    def add_issue(issue):
        if not issue:
            return
        issue_counts[issue] = issue_counts.get(issue, 0) + 1

    def add_domain(domain, issue=None, severity=None):
        if not domain:
            return
        d = affected_domains.setdefault(domain, {
            "domain": domain,
            "count": 0,
            "issues": {},
            "max_severity": "low",
            "sample_interpretation": "",
            "sample_action": "",
        })
        d["count"] += 1
        if issue:
            d["issues"][issue] = d["issues"].get(issue, 0) + 1
        rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        if rank.get(severity or "low", 1) > rank.get(d["max_severity"], 1):
            d["max_severity"] = severity or "low"

    for c in chains:
        issue = c.get("bottleneck")
        severity = c.get("severity")
        domain = c.get("query_name")
        add_issue(issue)
        add_domain(domain, issue, severity)

        fsd = c.get("first_server_data_ms")
        if isinstance(fsd, (int, float)):
            first_server_data_values.append(fsd)
            if fsd > 1000:
                slow_first_server_data_chains += 1

        if domain in affected_domains:
            if c.get("interpretation") and not affected_domains[domain]["sample_interpretation"]:
                affected_domains[domain]["sample_interpretation"] = c.get("interpretation")
            if c.get("engineer_action") and not affected_domains[domain]["sample_action"]:
                affected_domains[domain]["sample_action"] = c.get("engineer_action")

    tcp_limiter_counts = {}
    retrans_total = 0
    dup_ack_total = 0
    zero_win_total = 0
    tcp_loss_streams = 0
    receiver_limited_streams = 0
    application_limited_streams = 0

    for s in tcp_streams:
        limiter = s.get("tcp_limiter") or "unknown"
        tcp_limiter_counts[limiter] = tcp_limiter_counts.get(limiter, 0) + 1

        retrans = s.get("retransmission_count") or 0
        dup_ack = s.get("duplicate_ack_count") or 0
        zero_win = s.get("zero_window_count") or 0

        retrans_total += retrans
        dup_ack_total += dup_ack
        zero_win_total += zero_win

        if limiter == "network_loss_or_congestion":
            tcp_loss_streams += 1
        elif limiter == "receiver_limited":
            receiver_limited_streams += 1
        elif limiter == "application_limited":
            application_limited_streams += 1

    dns_health = dns_summary.get("dns_health")
    latency_health = latency_chain.get("latency_chain_health")

    primary_issue = "no_dominant_issue"
    confidence = "low"

    if tcp_loss_streams > 0 or issue_counts.get("network_loss_or_congestion", 0) > 0:
        primary_issue = "network_loss_or_congestion"
        confidence = "high" if retrans_total > 50 or dup_ack_total > 500 else "medium"
    elif receiver_limited_streams > 0 or issue_counts.get("receiver_limited", 0) > 0:
        primary_issue = "receiver_limited"
        confidence = "medium"
    elif dns_health in ("slow_dns", "dns_visibility_or_response_problem", "dns_resolution_errors"):
        primary_issue = dns_health
        confidence = "medium"
    elif application_limited_streams > 0 or issue_counts.get("application_limited", 0) > 0:
        primary_issue = "application_limited"
        confidence = "medium"

    if dns_health == "slow_dns":
        evidence.append(
            f"DNS health is slow_dns: avg={dns_summary.get('avg_latency_ms')} ms, max={dns_summary.get('max_latency_ms')} ms, slow_rate={dns_summary.get('slow_rate_pct')}%."
        )
        actions.append("Check DNS resolver load, forwarding path, upstream recursive DNS, and cache behavior.")
    elif dns_health == "dns_visibility_or_response_problem":
        evidence.append(
            f"DNS visibility issue: no_response={dns_summary.get('no_response_rate_pct')}%, response_without_query={dns_summary.get('response_without_query_rate_pct')}%."
        )
        actions.append("Check capture point, SPAN direction, resolver reachability, and asymmetric DNS response path.")

    if retrans_total or dup_ack_total:
        evidence.append(
            f"TCP loss evidence: retransmissions={retrans_total}, duplicate_acks={dup_ack_total}, affected_loss_streams={tcp_loss_streams}."
        )
        actions.append("Check packet drops, QoS, WAN congestion, interface errors, firewall/proxy drops, or wireless instability.")

    if zero_win_total:
        evidence.append(f"Receiver pressure evidence: zero_window_events={zero_win_total}, receiver_limited_streams={receiver_limited_streams}.")
        actions.append("Check receiving host CPU/memory/socket buffers and application read performance.")

    mtu_health = mtu_summary.get("mtu_health")
    if mtu_health and mtu_health not in ("unknown", "no_clear_mtu_issue"):
        evidence.append(
            "MTU/MSS evidence: "
            + str(mtu_summary.get("summary", "-"))
            + f" confirmed={mtu_summary.get('confirmed_mtu_streams', 0)}, "
            + f"probable_blackhole={mtu_summary.get('probable_mtu_blackhole_streams', 0)}, "
            + f"mss_clamped_with_retrans={mtu_summary.get('mss_clamped_path_with_retransmissions_streams', 0)}, "
            + f"possible={mtu_summary.get('possible_mtu_issue_streams', 0)}, "
            + f"icmp_frag_needed={mtu_summary.get('icmp_frag_needed_count', 0)}."
        )

        if mtu_health == "confirmed_mtu_issue":
            actions.append("MTU: investigate path MTU immediately; ICMP Fragmentation Needed / Packet Too Big was observed. Check tunnel overhead, DF handling, firewall ICMP policy, and PMTUD.")
        elif mtu_health == "probable_mtu_blackhole":
            actions.append("MTU: validate PMTUD blackhole; check ICMP filtering, tunnel overhead, SD-WAN/VPN/Zscaler path MTU, and MSS clamping.")
        elif mtu_health == "mss_clamped_path_with_retransmissions":
            actions.append("MTU/MSS: MSS adjustment is visible, so verify MSS clamping is expected. Prioritize packet loss/congestion on the adjusted tunnel/proxy path before calling it a pure MTU blackhole.")
        else:
            actions.append("MTU: review packet size, DF bit, MSS values, ICMP filtering, and retransmission patterns.")

    if first_server_data_values:
        avg_fsd = round(sum(first_server_data_values) / len(first_server_data_values), 3)
        max_fsd = round(max(first_server_data_values), 3)
        if slow_first_server_data_chains:
            evidence.append(
                f"Server/application response evidence: slow_first_server_data_chains={slow_first_server_data_chains}, avg_first_server_data_ms={avg_fsd}, max_first_server_data_ms={max_fsd}."
            )
            actions.append("Check server/application processing delay, upstream proxy latency, TLS inspection, and backend dependency response times.")

    if latency_chain.get("high_count", 0) or latency_chain.get("medium_count", 0):
        evidence.append(
            f"Latency chain: high={latency_chain.get('high_count')}, medium={latency_chain.get('medium_count')}, total={latency_chain.get('total_chains')}."
        )

    if not evidence:
        evidence.append("No dominant DNS/TCP/TLS/application bottleneck was identified from current evidence.")
        actions.append("Correlate with user transaction timing, server logs, and capture location.")

    # Keep unique actions in insertion order
    actions = list(dict.fromkeys(actions))

    affected_domains_list = sorted(
        affected_domains.values(),
        key=lambda d: (
            {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(d.get("max_severity"), 1),
            d.get("count", 0),
        ),
        reverse=True,
    )[:20]

    issue_counts_sorted = dict(sorted(issue_counts.items(), key=lambda x: x[1], reverse=True))
    tcp_limiter_counts_sorted = dict(sorted(tcp_limiter_counts.items(), key=lambda x: x[1], reverse=True))

    if primary_issue == "network_loss_or_congestion":
        executive_summary = (
            "Primary degradation appears to be transport instability after connection setup. "
            "DNS may contribute for some destinations, but retransmissions, duplicate ACKs, and BIF behavior indicate packet loss/reordering/congestion is the dominant issue."
        )
    elif primary_issue == "receiver_limited":
        executive_summary = (
            "Primary degradation appears receiver-side. DNS and connection setup may be acceptable, but zero-window/receiver-limited behavior indicates endpoint or application receive-side pressure."
        )
    elif primary_issue in ("slow_dns", "dns_visibility_or_response_problem", "dns_resolution_errors"):
        executive_summary = (
            "Primary degradation appears DNS-related. DNS health signals indicate slow, failed, or partially visible resolution before transport setup."
        )
    elif primary_issue == "application_limited":
        executive_summary = (
            "Primary degradation appears application-limited. Transport evidence suggests the sender/application is not filling the available network path."
        )
    else:
        executive_summary = "No single dominant bottleneck is clearly indicated by DNS, TCP, TLS, and application-chain evidence."

    return {
        "primary_issue": primary_issue,
        "confidence": confidence,
        "executive_summary": executive_summary,
        "dns_status": dns_health,
        "latency_chain_status": latency_health,
        "tcp_limiter_counts": tcp_limiter_counts_sorted,
        "chain_bottleneck_counts": issue_counts_sorted,
        "affected_domains": affected_domains_list,
        "evidence": evidence,
        "engineer_actions": actions,
        "dns_summary": {
            "total_dns_records": dns_summary.get("total_dns_records"),
            "answered_with_latency": dns_summary.get("answered_with_latency"),
            "avg_latency_ms": dns_summary.get("avg_latency_ms"),
            "max_latency_ms": dns_summary.get("max_latency_ms"),
            "slow_rate_pct": dns_summary.get("slow_rate_pct"),
            "no_response_rate_pct": dns_summary.get("no_response_rate_pct"),
            "response_without_query_rate_pct": dns_summary.get("response_without_query_rate_pct"),
        },
        "latency_chain_summary": {
            "total_chains": latency_chain.get("total_chains"),
            "high_count": latency_chain.get("high_count"),
            "medium_count": latency_chain.get("medium_count"),
            "summary": latency_chain.get("summary"),
        },
        "mtu_summary": mtu_summary,
        "ttfb_summary": {
            "samples": len(first_server_data_values),
            "slow_first_server_data_chains": slow_first_server_data_chains,
            "avg_first_server_data_ms": round(sum(first_server_data_values) / len(first_server_data_values), 3) if first_server_data_values else None,
            "max_first_server_data_ms": round(max(first_server_data_values), 3) if first_server_data_values else None,
        },
        "tcp_summary": {
            "tcp_streams": len(tcp_streams),
            "retransmissions": retrans_total,
            "duplicate_acks": dup_ack_total,
            "zero_window_events": zero_win_total,
            "network_loss_streams": tcp_loss_streams,
            "receiver_limited_streams": receiver_limited_streams,
            "application_limited_streams": application_limited_streams,
        },
    }

