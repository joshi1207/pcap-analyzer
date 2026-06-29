import { useMemo, useState } from "react";
import axios from "axios";
import jsPDF from "jspdf";
import autoTable from "jspdf-autotable";

function __formatUtcStreamTs(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return "-";
  return new Date(n * 1000).toISOString().replace("T", " ").replace("Z", " UTC");
}

function __formatStreamStartOffset(value, allStreams) {
  const n = Number(value);
  if (!Number.isFinite(n)) return "-";

  const starts = (allStreams || [])
    .map((s) => Number(s.start_time))
    .filter((x) => Number.isFinite(x));

  if (starts.length === 0) return "-";

  const base = Math.min(...starts);
  return `+${(n - base).toFixed(2)}s`;
}


const API_BASE = import.meta.env.VITE_API_BASE_URL || "";

const severityColor = {
  high: "#ef4444",
  medium: "#f59e0b",
  low: "#3b82f6",
};

export default function App() {
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const waitForGtraceCompletion = async (jobId) => {
  for (let i = 0; i < 60; i += 1) {
    const jobResp = await fetch(`${API_BASE}/api/gtrace/jobs/${jobId}`);
    if (!jobResp.ok) throw new Error("Failed to check gtrace job status");
    const job = await jobResp.json();

    if (job.status === "completed" || job.status === "failed") {
      return job;
    }

    await sleep(2000);
  }

  throw new Error("Timed out waiting for polling-region gtrace result");
};

const fetchCompletedGtraceResult = async (jobId) => {
  const resultResp = await fetch(`${API_BASE}/api/gtrace/jobs/${jobId}/result`);
  if (!resultResp.ok) throw new Error("Failed to fetch completed gtrace result");
  return await resultResp.json();
};

  const [file, setFile] = useState(null);
  const [uploadResult, setUploadResult] = useState(null);
  const [jobResult, setJobResult] = useState(null);
  const [summaryResult, setSummaryResult] = useState(null);
  const [streamsResult, setStreamsResult] = useState([]);
  const [findingsResult, setFindingsResult] = useState([]);
  const [rootCausesResult, setRootCausesResult] = useState([]);
  const [rootCausesV2Result, setRootCausesV2Result] = useState([]);
  const [timelineResult, setTimelineResult] = useState(null);
  const [selectedStream, setSelectedStream] = useState(null);
  const [selectedStreamPackets, setSelectedStreamPackets] = useState([]);

  const [loading, setLoading] = useState(false);
  const [summaryLoading, setSummaryLoading] = useState(false);
  const [streamsLoading, setStreamsLoading] = useState(false);
  const [findingsLoading, setFindingsLoading] = useState(false);
  const [rootCausesLoading, setRootCausesLoading] = useState(false);
  const [streamDrilldownLoading, setStreamDrilldownLoading] = useState(false);
  const [error, setError] = useState("");

  const [showOverview, setShowOverview] = useState(true);
  const [showInterpretation, setShowInterpretation] = useState(true);
  const [showStreams, setShowStreams] = useState(true);
  const [streamSearch, setStreamSearch] = useState("");
  const [streamSeverityFilter, setStreamSeverityFilter] = useState("all");
  const [streamRowLimit, setStreamRowLimit] = useState("200");
  const [showDrilldown, setShowDrilldown] = useState(true);
  const [gtraceTarget, setGtraceTarget] = useState("");
  const [gtraceSourceRegion, setGtraceSourceRegion] = useState("local-default");
  const [gtraceProtocol, setGtraceProtocol] = useState("icmp");
  const [gtracePort, setGtracePort] = useState("");
  const [gtraceMaxHops, setGtraceMaxHops] = useState(10);
  const [gtracePackets, setGtracePackets] = useState(3);

  const [gtraceResult, setGtraceResult] = useState(null);
  const [gtraceLoading, setGtraceLoading] = useState(false);
  const [gtraceError, setGtraceError] = useState(null);
  const [gtraceHistory, setGtraceHistory] = useState([]);
  const [compareJobA, setCompareJobA] = useState("");
  const [compareJobB, setCompareJobB] = useState("");
  const [gtraceCompareResult, setGtraceCompareResult] = useState(null);
  const [gtraceCompareLoading, setGtraceCompareLoading] = useState(false);
  const [gtraceCompareError, setGtraceCompareError] = useState(null);
  const [httpRecords, setHttpRecords] = useState([]);
  const [httpLoading, setHttpLoading] = useState(false);
  const [httpError, setHttpError] = useState(null);
  const [rcaSummaryResult, setRcaSummaryResult] = useState(null);
  const [latencyChainResult, setLatencyChainResult] = useState(null);
  const [rcaLoading, setRcaLoading] = useState(false);
  const [rcaError, setRcaError] = useState(null);
  const [selectedRcaDomain, setSelectedRcaDomain] = useState("");
  const [selectedRcaStreamIds, setSelectedRcaStreamIds] = useState([]);
  const [showRcaDashboard, setShowRcaDashboard] = useState(true);
  const [exportPdfLoading, setExportPdfLoading] = useState(false);
  const [exportPdfError, setExportPdfError] = useState(null);
  const [showHttpPanel, setShowHttpPanel] = useState(true);

  const completedGtraceHistory = (gtraceHistory || []).filter(
    (t) => t && t.status === "completed"
  );

  const protocolCount = useMemo(() => {
    if (!summaryResult?.protocols) return 0;
    return Object.keys(summaryResult.protocols).length;
  }, [summaryResult]);

  const filteredStreams = useMemo(() => {
    const q = streamSearch.trim().toLowerCase();

    const selectedRcaStreamIdSet = new Set(selectedRcaStreamIds || []);

    let rows = streamsResult.filter((stream) => {
      if (selectedRcaStreamIdSet.size > 0 && !selectedRcaStreamIdSet.has(stream.stream_id)) {
        return false;
      }

      const severityOk =
        streamSeverityFilter === "all" ||
        (stream.criticality_severity || "info") === streamSeverityFilter;

      if (!severityOk) return false;

      if (!q) return true;

      const haystack = [
        stream.stream_id,
        stream.stream_label,
        stream.endpoint_a_ip,
        stream.endpoint_a_port,
        stream.endpoint_b_ip,
        stream.endpoint_b_port,
        stream.tls_sni,
        stream.application,
        stream.stream_summary,
        stream.criticality_reason,
        stream.impact_hint,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();

      return haystack.includes(q);
    });

    if (streamRowLimit !== "all") {
      rows = rows.slice(0, Number(streamRowLimit));
    }

    return rows;
  }, [streamsResult, streamSearch, streamSeverityFilter, streamRowLimit, selectedRcaStreamIds]);

  const getRcaSummary = async () => {
    if (!jobResult?.job_id && !uploadResult?.job_id) {
      setRcaError("Upload and analyze a PCAP first.");
      return;
    }

    const activeJobId = jobResult?.job_id || uploadResult?.job_id;
    setRcaLoading(true);
    setRcaError(null);

    try {
      const res = await fetch(`${API_BASE}/api/jobs/${activeJobId}/rca-summary`);
      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.detail || "Failed to fetch RCA summary");
      }

      setRcaSummaryResult(data);
      setLatencyChainResult(null);
    } catch (err) {
      setRcaError(err.message || "Failed to fetch RCA summary");
    } finally {
      setRcaLoading(false);
    }
  };


  const openImpactedStreamsForDomain = async (domain) => {
    const activeJobId = jobResult?.job_id || uploadResult?.job_id;

    setSelectedRcaDomain(domain);
    setStreamSearch("");
    setShowStreams(true);

    try {
      let chainData = latencyChainResult;

      if (activeJobId && !chainData) {
        const res = await fetch(`${API_BASE}/api/jobs/${activeJobId}/latency-chain`);
        const data = await res.json();

        if (res.ok) {
          chainData = data;
          setLatencyChainResult(data);
        }
      }

      const ids = Array.from(
        new Set(
          (chainData?.chains || [])
            .filter((c) =>
              ((c.query_name || "").toLowerCase()).includes((domain || "").toLowerCase())
            )
            .map((c) => c.tcp_stream_id)
            .filter(Boolean)
        )
      );

      setSelectedRcaStreamIds(ids);

      if (activeJobId && streamsResult.length === 0) {
        const streamsRes = await fetch(`${API_BASE}/api/jobs/${activeJobId}/streams`);
        const streamsData = await streamsRes.json();

        if (streamsRes.ok) {
          setStreamsResult(Array.isArray(streamsData) ? streamsData : []);
        }
      }
    } catch (err) {
      console.error("Failed RCA domain drilldown", err);
    }

    setTimeout(() => {
      document.getElementById("top-streams-section")?.scrollIntoView({
        behavior: "smooth",
        block: "start",
      });
    }, 100);
  };


  const resetStateForNewUpload = () => {
    setUploadResult(null);
    setJobResult(null);
    setSummaryResult(null);
    setStreamsResult([]);
    setFindingsResult([]);
    setRootCausesResult([]);
    setRootCausesV2Result([]);
    setTimelineResult(null);
    setRcaSummaryResult(null);
    setLatencyChainResult(null);
    setRcaError(null);
    setSelectedRcaDomain("");
    setSelectedRcaStreamIds([]);
    setShowRcaDashboard(true);
    setSelectedStream(null);
    setSelectedStreamPackets([]);
    setError("");

    setShowOverview(true);
    setShowInterpretation(true);
    setShowStreams(true);
    setShowDrilldown(true);
  };

  const handleUpload = async () => {
    if (!file) {
      setError("Please select a pcap or pcapng file.");
      return;
    }

    resetStateForNewUpload();
    setLoading(true);

    const formData = new FormData();
    formData.append("file", file);

    try {
      const res = await axios.post(`${API_BASE}/api/upload`, formData, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      setUploadResult(res.data);
    } catch (err) {
      setError(err?.response?.data?.detail || "Upload failed");
    } finally {
      setLoading(false);
    }
  };

  const fetchJob = async () => {
    if (!uploadResult?.job_id) return;
    try {
      const res = await axios.get(`${API_BASE}/api/jobs/${uploadResult.job_id}`);
      setJobResult(res.data);
    } catch (err) {
      setError(err?.response?.data?.detail || "Failed to fetch job");
    }
  };

  const fetchSummary = async () => {
    if (!uploadResult?.job_id) return;
    setSummaryLoading(true);
    try {
      const res = await axios.get(`${API_BASE}/api/jobs/${uploadResult.job_id}/summary`);
      setSummaryResult(res.data);
      setShowOverview(true);
    } catch (err) {
      setError(err?.response?.data?.detail || "Summary not ready yet");
    } finally {
      setSummaryLoading(false);
    }
  };

  const fetchStreams = async () => {
    if (!uploadResult?.job_id) return;
    setStreamsLoading(true);
    try {
      const res = await axios.get(`${API_BASE}/api/jobs/${uploadResult.job_id}/streams`);
      const sorted = [...res.data].sort((a, b) => {
        const scoreDiff = (b.criticality_score || 0) - (a.criticality_score || 0);
        if (scoreDiff !== 0) return scoreDiff;
        return (b.packet_count || 0) - (a.packet_count || 0);
      });
      setStreamsResult(sorted);
      setShowStreams(true);
    } catch (err) {
      setError(err?.response?.data?.detail || "Streams not ready yet");
    } finally {
      setStreamsLoading(false);
    }
  };

  const fetchFindings = async () => {
    if (!uploadResult?.job_id) return;
    setFindingsLoading(true);
    try {
      const res = await axios.get(`${API_BASE}/api/jobs/${uploadResult.job_id}/findings`);
      setFindingsResult(res.data);
      setShowInterpretation(true);
    } catch (err) {
      setError(err?.response?.data?.detail || "Findings not ready yet");
    } finally {
      setFindingsLoading(false);
    }
  };

  const fetchRootCauses = async () => {
    if (!uploadResult?.job_id) return;
    setRootCausesLoading(true);
    try {
      const res = await axios.get(`${API_BASE}/api/jobs/${uploadResult.job_id}/root-causes`);
      setRootCausesResult(res.data);

      try {
        const resV2 = await axios.get(`${API_BASE}/api/jobs/${uploadResult.job_id}/root-causes-v2`);
        setRootCausesV2Result(resV2.data);
      } catch (e) {
        setRootCausesV2Result([]);
      }

      try {
        const timelineRes = await axios.get(`${API_BASE}/api/jobs/${uploadResult.job_id}/timeline`);
        setTimelineResult(timelineRes.data);
      } catch (e) {
        setTimelineResult(null);
      }
      setShowInterpretation(true);
    } catch (err) {
      setError(err?.response?.data?.detail || "Root causes not ready yet");
    } finally {
      setRootCausesLoading(false);
    }
  };

  const fetchStreamDrilldown = async (stream) => {
    if (!uploadResult?.job_id || !stream?.stream_id) return;

    setStreamDrilldownLoading(true);
    try {
      const encodedStreamId = encodeURIComponent(stream.stream_id);
      const res = await axios.get(
        `${API_BASE}/api/jobs/${uploadResult.job_id}/streams/${encodedStreamId}/packets`
      );
      setSelectedStream(res.data.stream);
      setSelectedStreamPackets(res.data.packets || []);
      setShowDrilldown(true);
    } catch (err) {
      setError(err?.response?.data?.detail || "Failed to load stream drilldown");
    } finally {
      setStreamDrilldownLoading(false);
    }
  };


  const getHttpRecords = async () => {
    const activeJobId = uploadResult?.job_id;
    if (!activeJobId) return;

    setHttpLoading(true);
    setHttpError(null);

    try {
      console.log("Fetching HTTP for job:", activeJobId);
      const res = await fetch(`${API_BASE}/api/jobs/${activeJobId}/http`);
      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.detail || "Failed to fetch HTTP records");
      }

      setHttpRecords(Array.isArray(data) ? data : []);
    } catch (err) {
      setHttpError(err.message || "Failed to fetch HTTP records");
    } finally {
      setHttpLoading(false);
    }
  };

  const runGtrace = async () => {
    setGtraceLoading(true);
    setGtraceError(null);
    setGtraceResult(null);

    try {
      const res = await fetch(`${API_BASE}/api/gtrace/run`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          target: gtraceTarget,
          source_region: gtraceSourceRegion,
          protocol: gtraceProtocol,
          port: gtracePort || null,
          max_hops: Number(gtraceMaxHops),
          packets: Number(gtracePackets),
        }),
      });

      const data = await res.json();

        if (!res.ok) {
          throw new Error(data.detail || "Failed to run gtrace");
        }

        if (data.status === "queued" && data.execution_mode === "polling") {
          const job = await waitForGtraceCompletion(data.job_id);

          if (job.status !== "completed") {
            throw new Error(`Polling-region trace ended with status: ${job.status}`);
          }

          const finalResult = await fetchCompletedGtraceResult(data.job_id);

          setGtraceResult(finalResult);
          setGtraceHistory((prev) => {
            const next = [finalResult, ...prev.filter((item) => item.job_id !== finalResult.job_id)];
            return next.slice(0, 10);
          });

        } else {
          setGtraceResult(data);
          setGtraceHistory((prev) => {
            const next = [data, ...prev.filter((item) => item.job_id !== data.job_id)];
            return next.slice(0, 10);
          });
        }

    } catch (err) {
      setGtraceError(err.message || "Failed to run gtrace");
    } finally {
      setGtraceLoading(false);
    }
  };

  const findStreamByLabel = (label) => {
    if (!label) return null;

    return streamsResult.find((s) => {
      if (s.stream_label === label) return true;

      const forward = `${s.endpoint_a_ip}:${s.endpoint_a_port} ↔ ${s.endpoint_b_ip}:${s.endpoint_b_port}`;
      const reverse = `${s.endpoint_b_ip}:${s.endpoint_b_port} ↔ ${s.endpoint_a_ip}:${s.endpoint_a_port}`;

      return label === forward || label === reverse;
    }) || null;
  };


  const runGtraceCompare = async () => {
    setGtraceCompareLoading(true);
    setGtraceCompareError(null);
    setGtraceCompareResult(null);

    try {
      const firstTrace = (gtraceHistory || []).find((t) => t.job_id === compareJobA);
      const secondTrace = (gtraceHistory || []).find((t) => t.job_id === compareJobB);

      if (!firstTrace || !secondTrace) {
        setGtraceCompareError("Please select two valid traces.");
        return;
      }

      if (firstTrace.status !== "completed" || secondTrace.status !== "completed") {
        setGtraceCompareError("Both traces must be completed before comparison.");
        return;
      }

      const res = await fetch(`${API_BASE}/api/gtrace/compare`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          job_id_a: compareJobA,
          job_id_b: compareJobB,
        }),
      });

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.detail || "Failed to compare traces");
      }

      if (!data || typeof data !== "object") {
        throw new Error("No comparison data returned.");
      }

      setGtraceCompareResult(data);
    } catch (err) {
      setGtraceCompareError(err.message || "Failed to compare traces");
    } finally {
      setGtraceCompareLoading(false);
    }
  };


  const exportPdfReport = () => {
    setExportPdfLoading(true);
    setExportPdfError(null);

    try {
    const doc = new jsPDF({ orientation: "landscape", unit: "pt", format: "a4" });
    let y = 36;

    const safe = (v) => {
      if (v === null || v === undefined) return "-";

      return String(v)
        .replace(/→/g, "->")
        .replace(/←/g, "<-")
        .replace(/–/g, "-")
        .replace(/—/g, "-")
        .replace(/’/g, "'")
        .replace(/‘/g, "'")
        .replace(/“/g, '"')
        .replace(/”/g, '"')
        .replace(/•/g, "-")
        .replace(/≥/g, ">=")
        .replace(/≤/g, "<=");
    };

      const pdfUtc = (value) => {
        const n = Number(value);
        if (!Number.isFinite(n)) return "-";
        return new Date(n * 1000).toISOString().replace("T", " ").replace("Z", " UTC");
      };

      const pdfStartOffset = (value) => {
        const n = Number(value);
        if (!Number.isFinite(n) || !Array.isArray(streamsResult) || streamsResult.length === 0) return "-";

        const starts = streamsResult
          .map((s) => Number(s.start_time))
          .filter((x) => Number.isFinite(x));

        if (starts.length === 0) return "-";

        const base = Math.min(...starts);
        return `+${(n - base).toFixed(2)}s`;
      };


    const hasCompareSummary =
      gtraceCompareResult &&
      Array.isArray(gtraceCompareResult.summary) &&
      (gtraceCompareResult.summary || []).length > 0;

    const section = (title) => {
      if (y > 520) {
        doc.addPage();
        y = 40;
      }
      doc.setFontSize(13);
      doc.text(title, 40, y);
      y += 10;
    };

    const kvTable = (title, rows) => {
      section(title);
      autoTable(doc, {
        startY: y,
        head: [["Field", "Value"]],
        body: rows,
        margin: { left: 40, right: 40 },
        styles: { fontSize: 9, cellPadding: 6, overflow: "linebreak" },
        headStyles: { fillColor: [30, 41, 59] },
        theme: "grid",
      });
      y = doc.lastAutoTable.finalY + 18;
    };

    const dataTable = (title, head, body) => {
      section(title);

      const isCriticalStreams = title === "Critical Streams";

      autoTable(doc, {
        startY: y,
        head: [head],
        body,
        margin: { left: 40, right: 40 },
        styles: {
          fontSize: isCriticalStreams ? 7.5 : 8,
          cellPadding: isCriticalStreams ? 4 : 5,
          overflow: "linebreak",
          valign: "middle",
          lineColor: [220, 226, 236],
          lineWidth: 0.4,
        },
        headStyles: {
          fillColor:
            title === "High Severity Critical Streams"
              ? [153, 27, 27]
              : title === "Medium Severity Critical Streams"
              ? [161, 98, 7]
              : [30, 41, 59],
          halign: "center",
          valign: "middle",
          fontStyle: "bold",
        },
        bodyStyles: {
          valign: "middle",
        },
        alternateRowStyles: {
          fillColor: [248, 250, 252],
        },
        theme: "grid",
        rowPageBreak: "avoid",
        tableWidth: "auto",
          columnStyles: isCriticalStreams
            ? {
                0: { cellWidth: 42, halign: "center" },   // Protocol
                1: { cellWidth: 96 },                     // Endpoint A
                2: { cellWidth: 96 },                     // Endpoint B
                3: { cellWidth: 118 },                    // Start UTC
                4: { cellWidth: 118 },                    // End UTC
                5: { cellWidth: 54, halign: "center" },   // Start Offset
                6: { cellWidth: 64 },                     // SNI
                7: { cellWidth: 62 },                     // Application
                8: { cellWidth: 34, halign: "center" },   // Score
                9: { cellWidth: 44, halign: "center" },   // Severity
                10: { cellWidth: 124 },                   // Why Critical
                11: { cellWidth: 58, halign: "center" },  // Directional
                12: { cellWidth: 92 },                    // Impact Hint
              }
            : {},
      });
      y = doc.lastAutoTable.finalY + 18;
    };

    doc.setFontSize(18);
    doc.text("Network Diagnostics Report", 40, y);
    y += 18;
    doc.setFontSize(10);
    doc.text(`Generated: ${new Date().toLocaleString()}`, 40, y);
    y += 18;

    const executiveSummary = [];

    if (summaryResult) {
      executiveSummary.push(["Total packets", safe(summaryResult.total_packets)]);
      executiveSummary.push(["Total bytes", safe(summaryResult.total_bytes)]);
      executiveSummary.push(["Capture duration (s)", safe(summaryResult.duration_seconds)]);
    }

    if (Array.isArray(findingsResult) && findingsResult.length > 0) {
      executiveSummary.push(["Findings count", safe(findingsResult.length)]);
      executiveSummary.push(["Highest finding severity", safe(findingsResult[0]?.severity || "-")]);
    }

    if (Array.isArray(rootCausesResult) && rootCausesResult.length > 0) {
      executiveSummary.push(["Top probable root cause", safe(rootCausesResult[0]?.title || "-")]);
      executiveSummary.push(["Top root cause confidence", safe(rootCausesResult[0]?.confidence || "-")]);
    }

      if (Array.isArray(rootCausesV2Result) && rootCausesV2Result.length > 0) {
        dataTable(
          "Root Cause Engine v2",
          ["Category", "Title", "Confidence", "Affected Streams", "Top Destinations", "Recommended Actions"],
          rootCausesV2Result.map((r) => [
            safe(r.category),
            safe(r.title),
            safe(r.confidence),
            safe(r.affected_streams),
            safe((r.top_impacted_destinations || []).map((d) => `${d.destination} (${d.count})`).join("; ")),
            safe((r.recommended_actions || []).join("; ")),
          ])
        );
      }

        if (timelineResult) {
          const timelineBaseUtc =
            Array.isArray(streamsResult) && streamsResult.length > 0
              ? Math.min(
                  ...streamsResult
                    .map((s) => Number(s.start_time))
                    .filter((x) => Number.isFinite(x))
                )
              : null;

          const peakUtc =
            timelineResult.peak_issue_window && Number.isFinite(timelineBaseUtc)
              ? `${pdfUtc(timelineBaseUtc + Number(timelineResult.peak_issue_window.window_start_seconds || 0))} -> ${pdfUtc(timelineBaseUtc + Number(timelineResult.peak_issue_window.window_end_seconds || 0))}`
              : "-";

          kvTable("Timeline Summary", [
            ["First issue seen (offset)", safe(`${timelineResult.first_issue_seen}s`)],
            ["Last issue seen (offset)", safe(`${timelineResult.last_issue_seen}s`)],
            ["Capture start UTC anchor", Number.isFinite(timelineBaseUtc) ? pdfUtc(timelineBaseUtc) : "-"],
            ["Peak issue window (offset)", timelineResult.peak_issue_window
              ? safe(`${timelineResult.peak_issue_window.window_start_seconds}s - ${timelineResult.peak_issue_window.window_end_seconds}s (${timelineResult.peak_issue_window.critical_streams} critical streams)`)
              : "-"],
            ["Peak issue window (UTC)", peakUtc],
            ["Dominant issue type in peak", safe(timelineResult.dominant_issue_type_in_peak || "-")],
          ]);

          if (Array.isArray(timelineResult.timeline_buckets) && timelineResult.timeline_buckets.length > 0) {
            dataTable(
              "Timeline Buckets",
              ["Offset (s)", "Critical Streams", "Dominant Issue"],
              timelineResult.timeline_buckets.map((b) => [
                safe(b.offset_seconds),
                safe(b.critical_streams),
                safe(b.dominant_issue_type || "-"),
              ])
            );
          }
        }

    if (!hasCompareSummary && gtraceResult) {
      executiveSummary.push(["Path target", safe(gtraceResult.target)]);
      executiveSummary.push(["Path protocol", safe(gtraceResult.protocol)]);
      executiveSummary.push(["Path status", safe(gtraceResult.status)]);
      executiveSummary.push(["Destination reached", safe(gtraceResult.destination_reached)]);
      executiveSummary.push(["Reached hops", safe(gtraceResult.reached_hops)]);
    }

    if (hasCompareSummary) {
      executiveSummary.push(["Trace comparison", "Present"]);
      executiveSummary.push(["Compare summary items", safe(gtraceCompareResult.summary.length)]);
    }

    if (executiveSummary.length > 0) {
      kvTable("Executive Summary", executiveSummary);
    }

    if (summaryResult) {
      kvTable("PCAP Summary", [
        ["Total packets", safe(summaryResult.total_packets)],
        ["Total bytes", safe(summaryResult.total_bytes)],
        ["Duration (s)", safe(summaryResult.duration_seconds)],
      ]);
    }

    if (Array.isArray(findingsResult) && findingsResult.length > 0) {
      dataTable(
        "Findings",
        ["Severity", "Title", "Description", "Affected Streams"],
        findingsResult.map((f) => [
          safe(f.severity),
          safe(f.title),
          safe(f.description),
          safe(f.affected_streams),
        ])
      );
    }

    if (Array.isArray(rootCausesResult) && rootCausesResult.length > 0) {
      dataTable(
        "Probable Root Causes",
        ["Severity", "Category", "Title", "Confidence", "Summary"],
        rootCausesResult.map((r) => [
          safe(r.severity),
          safe(r.category),
          safe(r.title),
          safe(r.confidence),
          safe(r.summary),
        ])
      );
    }

      if (Array.isArray(streamsResult) && streamsResult.length > 0) {
        const criticalStreams = [...streamsResult]
          .filter((s) => (s.criticality_score || 0) > 0)
          .sort((a, b) => {
            const scoreDiff = (b.criticality_score || 0) - (a.criticality_score || 0);
            if (scoreDiff !== 0) return scoreDiff;
            return (b.packet_count || 0) - (a.packet_count || 0);
          });

        const makeCriticalRows = (items) =>
          items.map((s) => [
            safe(s.protocol),
            `${safe(s.endpoint_a_ip)}:${safe(s.endpoint_a_port)}`,
            `${safe(s.endpoint_b_ip)}:${safe(s.endpoint_b_port)}`,
            pdfUtc(s.start_time),
            pdfUtc(s.end_time),
            pdfStartOffset(s.start_time),
            safe(s.tls_sni || "-"),
            safe(s.application || "-"),
            safe(s.criticality_score ?? 0),
            safe((s.criticality_severity || "info").toUpperCase()),
            safe(s.criticality_reason || "-"),
            safe(s.directional_hint || "-"),
            safe(s.impact_hint || "-"),
          ]);

        const highCriticalStreams = criticalStreams.filter(
          (s) => (s.criticality_severity || "").toLowerCase() === "high"
        );
        const mediumCriticalStreams = criticalStreams.filter(
          (s) => (s.criticality_severity || "").toLowerCase() === "medium"
        );
        const lowCriticalStreams = criticalStreams.filter(
          (s) => (s.criticality_severity || "").toLowerCase() === "low"
        );

        const destinationCounts = {};
        criticalStreams.forEach((s) => {
          const key = `${s.endpoint_b_ip || "-"}:${s.endpoint_b_port || "-"}`;
          destinationCounts[key] = (destinationCounts[key] || 0) + 1;
        });

        const topImpactedDestination = Object.entries(destinationCounts)
          .sort((a, b) => b[1] - a[1])[0];

        if (highCriticalStreams.length > 0) {
          section("Critical Issue Alert");
          doc.setFontSize(12);
          doc.setTextColor(153, 27, 27);
          doc.text(
            `High severity streams detected: ${highCriticalStreams.length}. Immediate review recommended.`,
            40,
            y
          );
          y += 16;
          doc.setTextColor(0, 0, 0);
        }

        kvTable("Impact Overview", [
          ["Total critical streams", safe(criticalStreams.length)],
          ["High severity", safe(highCriticalStreams.length)],
          ["Medium severity", safe(mediumCriticalStreams.length)],
          ["Low severity", safe(lowCriticalStreams.length)],
          ["Top impacted destination", topImpactedDestination ? `${topImpactedDestination[0]} (${topImpactedDestination[1]} streams)` : "-"],
        ]);

        kvTable("Critical Streams Summary", [
          ["Total critical streams", safe(criticalStreams.length)],
          ["High severity", safe(highCriticalStreams.length)],
          ["Medium severity", safe(mediumCriticalStreams.length)],
          ["Low severity", safe(lowCriticalStreams.length)],
        ]);

        if (highCriticalStreams.length > 0) {
          dataTable(
            "High Severity Critical Streams",
            ["Protocol", "Endpoint A", "Endpoint B", "Start UTC", "End UTC", "Start Offset", "SNI", "Application", "Score", "Severity", "Why Critical", "Directional", "Impact Hint"],
            makeCriticalRows(highCriticalStreams)
          );
        }

        const groupedMediumPatterns = {};
        mediumCriticalStreams.forEach((s) => {
          const key = `${s.endpoint_b_ip || "-"}:${s.endpoint_b_port || "-"} | ${s.impact_hint || "-"} | ${s.directional_hint || "-"}`;
          groupedMediumPatterns[key] = (groupedMediumPatterns[key] || 0) + 1;
        });

        const topMediumPatterns = Object.entries(groupedMediumPatterns)
          .sort((a, b) => b[1] - a[1])
          .slice(0, 5)
          .map(([k, v]) => [k, v]);

        const mediumPatternCounts = groupedMediumPatterns;

        const mediumPrioritized = [...mediumCriticalStreams].sort((a, b) => {
          const keyA = `${a.endpoint_b_ip || "-"}:${a.endpoint_b_port || "-"} | ${a.impact_hint || "-"} | ${a.directional_hint || "-"}`;
          const keyB = `${b.endpoint_b_ip || "-"}:${b.endpoint_b_port || "-"} | ${b.impact_hint || "-"} | ${b.directional_hint || "-"}`;

          const scoreDiff = (b.criticality_score || 0) - (a.criticality_score || 0);
          if (scoreDiff !== 0) return scoreDiff;

          const patternDiff = (mediumPatternCounts[keyB] || 0) - (mediumPatternCounts[keyA] || 0);
          if (patternDiff !== 0) return patternDiff;

          return (b.packet_count || 0) - (a.packet_count || 0);
        });

        if (topMediumPatterns.length > 0) {
          dataTable(
            "Repeated Medium-Severity Patterns",
            ["Destination / Pattern", "Occurrences"],
            topMediumPatterns.map(([pattern, count]) => [safe(pattern), safe(count)])
          );
        }

        if (mediumCriticalStreams.length > 0) {
          kvTable("Medium Severity Display Scope", [
            ["Total medium severity streams", safe(mediumCriticalStreams.length)],
            ["Displayed in report", safe(Math.min(50, mediumCriticalStreams.length))],
            ["Selection logic", "Highest score, then repeated pattern frequency, then packet count"],
          ]);

          dataTable(
            "Medium Severity Critical Streams",
            ["Protocol", "Endpoint A", "Endpoint B", "Start UTC", "End UTC", "Start Offset", "SNI", "Application", "Score", "Severity", "Why Critical", "Directional", "Impact Hint"],
            makeCriticalRows(mediumPrioritized.slice(0, 50))
          );
        }

        if (lowCriticalStreams.length > 0) {
          dataTable(
            "Low Severity Critical Streams",
            ["Protocol", "Endpoint A", "Endpoint B", "Start UTC", "End UTC", "Start Offset", "SNI", "Application", "Score", "Severity", "Why Critical", "Directional", "Impact Hint"],
            makeCriticalRows(lowCriticalStreams)
          );
        }
      }

    if (!hasCompareSummary && gtraceResult) {
      kvTable("Path Analysis Summary", [
        ["Target", safe(gtraceResult.target)],
        ["Protocol", safe(gtraceResult.protocol)],
        ["Status", safe(gtraceResult.status)],
        ["Max hops", safe(gtraceResult.max_hops)],
        ["Packets", safe(gtraceResult.packets)],
        ["Destination reached", safe(gtraceResult.destination_reached)],
        ["Reached hops", safe(gtraceResult.reached_hops)],
        ["Max average RTT (ms)", safe(gtraceResult.max_avg_rtt_ms)],
        ["ASN path", Array.isArray(gtraceResult.asn_path) ? gtraceResult.asn_path.join(" -> ") : "-"],
      ]);
    }

    if (!hasCompareSummary && gtraceResult && Array.isArray(gtraceResult.path_summary) && gtraceResult.path_summary.length > 0) {
      dataTable(
        "Path Insights",
        ["Insight"],
        gtraceResult.path_summary.map((item) => [safe(item)])
      );
    }

    if (!hasCompareSummary && gtraceResult && Array.isArray(gtraceResult.parsed_hops) && gtraceResult.parsed_hops.length > 0) {
      dataTable(
        "Parsed Hops",
        ["Hop", "Host", "IP", "ASN", "ASN Org", "Country", "City", "Avg RTT", "Missing", "Notes"],
        gtraceResult.parsed_hops.slice(0, 25).map((h) => [
          safe(h.hop),
          safe(h.host || "-"),
          safe(h.ip || "-"),
          safe(h.asn || "-"),
          safe(h.asn_org || "-"),
          safe(h.country || "-"),
          safe(h.city || "-"),
          safe(h.avg_rtt_ms ?? "-"),
          safe(h.missing_probes ?? 0),
          Array.isArray(h.notes) ? h.notes.join(" | ") : "-",
        ])
      );
    }

    if (hasCompareSummary) {
      const pageWidth = doc.internal.pageSize.getWidth();
      const pageHeight = doc.internal.pageSize.getHeight();

      const ensureSpace = (needed = 80) => {
        if (y + needed > pageHeight - 36) {
          doc.addPage();
          y = 36;
        }
      };
      const blockLeft = 48;
      const blockRight = pageWidth - 48;
      const blockWidth = blockRight - blockLeft;
      const titleYPad = 18;
      const contentLeft = blockLeft + 22;
      const bulletX = blockLeft + 10;
      const maxTextWidth = blockWidth - 40;

      if (y > 500) {
        doc.addPage();
        y = 40;
      }

      doc.setDrawColor(220, 226, 236);
      doc.setFillColor(248, 250, 252);
      doc.roundedRect(blockLeft, y, blockWidth, 28 + (gtraceCompareResult.summary.length * 26), 8, 8, "S");

      doc.setFontSize(14);
      doc.setFont(undefined, "bold");
      doc.text("Compare summary", pageWidth / 2, y + titleYPad, { align: "center" });

      doc.setFontSize(10);
      doc.setFont(undefined, "normal");
      doc.text(
        `Trace A: ${safe(gtraceCompareResult.target_a || "-")}    |    Trace B: ${safe(gtraceCompareResult.target_b || "-")}`,
        pageWidth / 2,
        y + titleYPad + 16,
        { align: "center" }
      );

      y += 52;
      doc.setFontSize(11);
      doc.setFont(undefined, "normal");

      (gtraceCompareResult.summary || []).forEach((item) => {
        const cleanItem = safe(item);

        if (y > 520) {
          doc.addPage();
          y = 40;
          doc.setDrawColor(220, 226, 236);
          doc.roundedRect(blockLeft, y, blockWidth, 28 + (gtraceCompareResult.summary.length * 26), 8, 8, "S");
          doc.setFontSize(14);
          doc.setFont(undefined, "bold");
          doc.text("Compare summary", pageWidth / 2, y + titleYPad, { align: "center" });

          doc.setFontSize(10);
          doc.setFont(undefined, "normal");
          doc.text(
            `Trace A: ${safe(gtraceCompareResult.target_a || "-")}    |    Trace B: ${safe(gtraceCompareResult.target_b || "-")}`,
            pageWidth / 2,
            y + titleYPad + 16,
            { align: "center" }
          );

          y += 52;
          doc.setFontSize(11);
          doc.setFont(undefined, "normal");
        }

        const lines = doc.splitTextToSize(cleanItem, maxTextWidth);
        doc.text("•", bulletX, y);
        doc.text(lines, contentLeft, y);
        y += Math.max(20, lines.length * 15);
      });

      y += 10;
      doc.setDrawColor(210, 214, 220);
      doc.line(blockLeft, y, blockRight, y);
      y += 14;

      if (Array.isArray(gtraceCompareResult.hop_diffs) && (gtraceCompareResult.hop_diffs || []).length > 0) {
        dataTable(
          "Trace Compare Details",
          ["Hop", "IP A", "IP B", "ASN A", "ASN B", "Avg RTT A", "Avg RTT B", "Missing A", "Missing B", "Changed"],
          gtraceCompareResult.hop_diffs.slice(0, 25).map((h) => [
            safe(h.hop),
            safe(h.a_ip || "-"),
            safe(h.b_ip || "-"),
            safe(h.a_asn || "-"),
            safe(h.b_asn || "-"),
            safe(h.a_avg_rtt_ms ?? "-"),
            safe(h.b_avg_rtt_ms ?? "-"),
            safe(h.a_missing ?? "-"),
            safe(h.b_missing ?? "-"),
            h.changed ? "Yes" : "No",
          ])
        );
      }
    }


      const shortPdfText = (value, max = 240) => {
        const s = safe(value ?? "-");
        return s.length > max ? `${s.slice(0, max)}...` : s;
      };

      if (rcaSummaryResult) {
        const rcaPageWidth = doc.internal.pageSize.getWidth();
        const rcaPageHeight = doc.internal.pageSize.getHeight();
        if (y + 160 > rcaPageHeight - 36) {
          doc.addPage();
          y = 36;
        }

        doc.setFontSize(16);
        doc.setFont(undefined, "bold");
        doc.text("RCA Dashboard Summary", rcaPageWidth / 2, y, { align: "center" });
        y += 20;

        dataTable(
          "RCA Overview",
          ["Field", "Value"],
          [
            ["Primary issue", safe(rcaSummaryResult.primary_issue || "-")],
            ["Confidence", safe(rcaSummaryResult.confidence || "-")],
            ["DNS status", safe(rcaSummaryResult.dns_status || "-")],
            ["Latency chain", safe(rcaSummaryResult.latency_chain_status || "-")],
            ["Summary", shortPdfText(rcaSummaryResult.executive_summary || "-", 260)],
          ]
        );

        if (Array.isArray(rcaSummaryResult.evidence) && rcaSummaryResult.evidence.length > 0) {
          dataTable(
            "RCA Evidence",
            ["Evidence"],
            rcaSummaryResult.evidence.slice(0, 8).map((item) => [shortPdfText(item, 260)])
          );
        }

        if (Array.isArray(rcaSummaryResult.engineer_actions) && rcaSummaryResult.engineer_actions.length > 0) {
          dataTable(
            "Recommended Engineer Actions",
            ["Action"],
            rcaSummaryResult.engineer_actions.slice(0, 8).map((item) => [shortPdfText(item, 260)])
          );
        }

        if (rcaSummaryResult.tcp_summary) {
          const t = rcaSummaryResult.tcp_summary;
          dataTable(
            "TCP Evidence Summary",
            ["Metric", "Value"],
            [
              ["TCP streams", safe(t.tcp_streams ?? "-")],
              ["Retransmissions", safe(t.retransmissions ?? "-")],
              ["Duplicate ACKs", safe(t.duplicate_acks ?? "-")],
              ["Zero windows", safe(t.zero_window_events ?? "-")],
              ["Network-loss streams", safe(t.network_loss_streams ?? "-")],
              ["Receiver-limited streams", safe(t.receiver_limited_streams ?? "-")],
              ["Application-limited streams", safe(t.application_limited_streams ?? "-")],
            ]
          );
        }

        if (rcaSummaryResult.ttfb_summary) {
          const tt = rcaSummaryResult.ttfb_summary;
          dataTable(
            "First Server Data / TTFB Approximation",
            ["Metric", "Value"],
            [
              ["Samples", safe(tt.samples ?? "-")],
              ["Slow first-server-data chains", safe(tt.slow_first_server_data_chains ?? "-")],
              ["Avg first-server-data ms", safe(tt.avg_first_server_data_ms ?? "-")],
              ["Max first-server-data ms", safe(tt.max_first_server_data_ms ?? "-")],
            ]
          );
        }

        if (rcaSummaryResult.mtu_summary) {
          const m = rcaSummaryResult.mtu_summary;
          dataTable(
            "MTU / MSS / PMTUD Summary",
            ["Metric", "Value"],
            [
              ["Health", safe(m.mtu_health ?? "-")],
              ["Confirmed MTU streams", safe(m.confirmed_mtu_streams ?? "-")],
              ["Probable PMTUD blackhole streams", safe(m.probable_mtu_blackhole_streams ?? "-")],
              ["MSS-clamped with retransmissions", safe(m.mss_clamped_path_with_retransmissions_streams ?? "-")],
              ["Possible MTU streams", safe(m.possible_mtu_issue_streams ?? "-")],
              ["ICMP Fragmentation Needed / Packet Too Big", safe(m.icmp_frag_needed_count ?? "-")],
              ["Summary", shortPdfText(m.summary ?? "-", 260)],
            ]
          );
        }

        if (Array.isArray(rcaSummaryResult.affected_domains) && rcaSummaryResult.affected_domains.length > 0) {
          dataTable(
            "Top Affected Domains",
            ["Domain", "Count", "Severity", "Issues"],
            rcaSummaryResult.affected_domains.slice(0, 15).map((d) => [
              safe(d.domain || "-"),
              safe(d.count ?? "-"),
              safe(d.max_severity || "-"),
              shortPdfText(Object.entries(d.issues || {}).map(([k, v]) => `${k}: ${v}`).join(", ") || "-", 180),
            ])
          );
        }
      }

    doc.save("network_diagnostics_report.pdf");
    } catch (err) {
      console.error("PDF export failed", err);
      setExportPdfError(err?.message || "PDF export failed");
    } finally {
      setExportPdfLoading(false);
    }
  };

  const handleStreamLabelClick = (payload) => {
    let stream = null;

    if (payload && typeof payload === "object") {
      if (payload.stream_id) {
        stream = streamsResult.find((s) => s.stream_id === payload.stream_id) || null;
      }

      if (!stream && payload.label) {
        stream = findStreamByLabel(payload.label);
      }
    } else {
      stream = findStreamByLabel(payload);
    }

    if (stream) {
      fetchStreamDrilldown(stream);
    }
  };

  return (
    <div style={styles.page}>
      <div style={styles.shell}>
        <header style={styles.header}>
          <div>
            <div style={styles.eyebrow}>Network diagnostics</div>
            <h1 style={styles.title}>PCAP Analyzer</h1>
            <p style={styles.subtitle}>
              Upload a capture, review probable root causes, inspect streams, and drill into packet evidence.
            </p>
          </div>

          <div style={styles.uploadCard}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: "12px", marginBottom: "10px" }}>
              <div style={styles.uploadTitle}>Upload capture</div>
              <button onClick={exportPdfReport} disabled={exportPdfLoading} style={styles.secondaryButton}>
                  {exportPdfLoading ? "Exporting PDF..." : "Export PDF"}
                </button>
            </div>
            <input
              type="file"
              accept=".pcap,.pcapng"
              onChange={(e) => setFile(e.target.files?.[0] || null)}
              style={styles.fileInput}
            />
            <button onClick={handleUpload} disabled={loading} style={styles.primaryButton}>
              {loading ? "Uploading..." : "Upload file"}
            </button>
          </div>
        </header>

        {error && <div style={styles.errorBanner}>{error}</div>}
          {exportPdfError && <div style={styles.errorBanner}>{exportPdfError}</div>}

        {uploadResult && (
          <section style={styles.section}>
            <div style={styles.sectionHeader}>
              <div>
                <h2 style={styles.sectionTitle}>Analysis controls</h2>
                <p style={styles.sectionText}>
                  Job <strong>{uploadResult.job_id}</strong> · {uploadResult.filename}
                </p>
              </div>
              <div style={styles.badge}>
                {jobResult?.status || uploadResult.status}
              </div>
            </div>

            <div style={styles.actionRow}>
              <button onClick={fetchJob} style={styles.secondaryButton}>Check job</button>
              <button onClick={fetchSummary} style={styles.secondaryButton} disabled={summaryLoading}>
                {summaryLoading ? "Loading summary..." : "Get summary"}
              </button>
              <button onClick={fetchStreams} style={styles.secondaryButton} disabled={streamsLoading}>
                {streamsLoading ? "Loading streams..." : "Get streams"}
              </button>
              <button onClick={fetchFindings} style={styles.secondaryButton} disabled={findingsLoading}>
                {findingsLoading ? "Loading findings..." : "Get findings"}
              </button>
              <button onClick={getHttpRecords} style={styles.secondaryButton}>
                {httpLoading ? "Loading HTTP..." : "Get HTTP"}
              </button>


              <button
                onClick={getRcaSummary}
                disabled={rcaLoading || (!jobResult?.job_id && !uploadResult?.job_id)}
                style={styles.primaryButton}
              >
                {rcaLoading ? "Loading RCA..." : "Get RCA Summary"}
              </button>
            </div>
          </section>
        )}

        <section style={styles.section}>
          <SectionToolbar
            title="Path analysis (gtrace)"
            subtitle="Run a live path trace to a target using ICMP, TCP, or UDP."
            expanded={true}
            onToggle={() => {}}
            rightNode={<div style={styles.badgeMuted}>Live network path</div>}
          />

          <div style={styles.gtraceForm}>
            <input
              type="text"
              placeholder="Target (e.g. 8.8.8.8 or google.com)"
              value={gtraceTarget}
              onChange={(e) => setGtraceTarget(e.target.value)}
              style={styles.gtraceInputWide}
            />

            <select
              value={gtraceProtocol}
              onChange={(e) => {
                const proto = e.target.value;
                setGtraceProtocol(proto);
                if (proto === "icmp") setGtracePort("");
              }}
              style={styles.gtraceInput}
            >
              <option value="icmp">ICMP</option>
              <option value="tcp">TCP</option>
              <option value="udp">UDP</option>
            </select>

          <div style={{ display: "flex", flexDirection: "column" }}>
            <label style={styles.fieldLabel}>Source region</label>
            <select
              value={gtraceSourceRegion}
              onChange={(e) => setGtraceSourceRegion(e.target.value)}
              style={styles.input}
            >
              <option value="local-default">Local Default</option>
              <option value="in-india">India</option>
              <option value="de-germany">Germany</option>
              <option value="sg-singapore">Singapore</option>
              <option value="us-east">US East</option>
            </select>
          </div>

            <input
              type="number"
              placeholder="Port"
              value={gtracePort}
              onChange={(e) => setGtracePort(e.target.value)}
              disabled={gtraceProtocol === "icmp"}
              style={styles.gtraceInputSmall}
            />

            <input
              type="number"
              placeholder="Max hops"
              value={gtraceMaxHops}
              onChange={(e) => setGtraceMaxHops(e.target.value)}
              style={styles.gtraceInputSmall}
            />

            <input
              type="number"
              placeholder="Packets"
              value={gtracePackets}
              onChange={(e) => setGtracePackets(e.target.value)}
              style={styles.gtraceInputSmall}
            />

            <button onClick={runGtrace} disabled={gtraceLoading} style={styles.primaryButton}>
              {gtraceLoading ? "Running..." : "Run path analysis"}
            </button>
          </div>

          {gtraceError && (
            <div style={styles.errorBanner}>
              {gtraceError}
            </div>
          )}

          <div style={{ ...styles.gtraceResultCard, marginBottom: "20px" }}>
            <h3 style={styles.cardTitle}>Compare two traces</h3>

            <div style={styles.gtraceForm}>
              <select
                value={compareJobA}
                onChange={(e) => setCompareJobA(e.target.value)}
                style={styles.gtraceInputWide}
              >
                <option value="">Select first trace</option>
                {completedGtraceHistory.map((item) => (
                  <option key={`a-${item.job_id}`} value={item.job_id}>
                    {item.target} · {item.protocol} · {item.job_id}
                  </option>
                ))}
              </select>

              <select
                value={compareJobB}
                onChange={(e) => setCompareJobB(e.target.value)}
                style={styles.gtraceInputWide}
              >
                <option value="">Select second trace</option>
                {completedGtraceHistory.map((item) => (
                  <option key={`b-${item.job_id}`} value={item.job_id}>
                    {item.target} · {item.protocol} · {item.job_id}
                  </option>
                ))}
              </select>

              <button
                onClick={runGtraceCompare}
                disabled={gtraceCompareLoading || !compareJobA || !compareJobB}
                style={styles.primaryButton}
              >
                {gtraceCompareLoading ? "Comparing..." : "Compare traces"}
              </button>
            </div>

            {gtraceCompareError && (
              <div style={styles.errorBanner}>
                {gtraceCompareError}
              </div>
            )}

            {gtraceCompareResult && (
              <>
                <div style={styles.gtraceInsightCard}>
                  <h3 style={styles.cardTitle}>Compare summary</h3>
                  <ul style={{ ...(styles.notesList || {}), textAlign: "left" }}>
                    {(gtraceCompareResult.summary || []).map((item, idx) => (
                      <li key={idx} style={styles.noteItem}>{item}</li>
                    ))}
                  </ul>
                </div>

                {(!Array.isArray(gtraceCompareResult.hop_diffs) || gtraceCompareResult.hop_diffs.length === 0) && (
                  <div style={styles.noteCard}>No hop differences returned.</div>
                )}

                <div style={styles.tableWrapTall}>
                  <table style={styles.table}>
                    <thead>
                      <tr>
                        <th style={styles.thCompact}>Hop</th>
                        <th style={styles.th}>IP A</th>
                        <th style={styles.th}>IP B</th>
                        <th style={styles.th}>ASN A</th>
                        <th style={styles.th}>ASN B</th>
                        <th style={styles.thCompact}>Avg RTT A</th>
                        <th style={styles.thCompact}>Avg RTT B</th>
                        <th style={styles.thCompact}>Missing A</th>
                        <th style={styles.thCompact}>Missing B</th>
                        <th style={styles.thCompact}>Changed</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(gtraceCompareResult.hop_diffs || []).map((hop) => (
                        <tr
                          key={hop.hop}
                          style={{
                            ...styles.tr,
                            background: hop.changed ? "rgba(245, 158, 11, 0.08)" : "transparent",
                          }}
                        >
                          <td style={styles.tdCompact}>{hop.hop}</td>
                          <td style={styles.tdCompact}>{hop.a_ip || "-"}</td>
                          <td style={styles.tdCompact}>{hop.b_ip || "-"}</td>
                          <td style={styles.tdCompact}>{hop.a_asn || "-"}</td>
                          <td style={styles.tdCompact}>{hop.b_asn || "-"}</td>
                          <td style={styles.tdCompact}>{hop.a_avg_rtt_ms ?? "-"}</td>
                          <td style={styles.tdCompact}>{hop.b_avg_rtt_ms ?? "-"}</td>
                          <td style={styles.tdCompact}>{hop.a_missing ?? "-"}</td>
                          <td style={styles.tdCompact}>{hop.b_missing ?? "-"}</td>
                          <td style={styles.tdCompact}>{hop.changed ? "Yes" : "No"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </>
            )}
          </div>


          {gtraceResult && (
            <div style={styles.gtraceResultCard}>
              <div style={styles.gtraceMetaRow}>
                <div><strong>Target:</strong> {gtraceResult.target}</div>
                <div><strong>Protocol:</strong> {gtraceResult.protocol}</div>
                <div><strong>Status:</strong> {gtraceResult.status}</div>
              </div>
                <div><strong>Source region:</strong> {gtraceResult.source_region || "-"}</div>
                <div><strong>Probe:</strong> {gtraceResult.probe_id || "-"}</div>
                <div><strong>Probe IP:</strong> {gtraceResult.probe_public_ip || "-"}</div>

              {gtraceResult.port && (
                <div style={styles.gtraceMetaRow}>
                  <div><strong>Port:</strong> {gtraceResult.port}</div>
                  <div><strong>Max hops:</strong> {gtraceResult.max_hops}</div>
                  <div><strong>Packets:</strong> {gtraceResult.packets}</div>
                </div>
              )}

              {!gtraceResult.port && (
                <div style={styles.gtraceMetaRow}>
                  <div><strong>Max hops:</strong> {gtraceResult.max_hops}</div>
                  <div><strong>Packets:</strong> {gtraceResult.packets}</div>
                  <div><strong>Return code:</strong> {String(gtraceResult.returncode)}</div>
                </div>
              )}

              {Array.isArray(gtraceResult.path_summary) && gtraceResult.path_summary.length > 0 && (
                <div style={styles.gtraceInsightCard}>
                  <h3 style={styles.cardTitle}>Path insights</h3>
                  <ul style={{ ...(styles.notesList || {}), textAlign: "left" }}>
                    {gtraceResult.path_summary.map((item, idx) => (
                      <li key={idx} style={styles.noteItem}>{item}</li>
                    ))}
                  </ul>
                </div>
              )}

              {Array.isArray(gtraceResult.parsed_hops) && gtraceResult.parsed_hops.length > 0 && (
                <div style={styles.tableWrapTall}>
                  <table style={styles.table}>
                    <thead>
                      <tr>
                        <th style={styles.thCompact}>Hop</th>
                        <th style={styles.th}>Host</th>
                        <th style={styles.thCompact}>IP</th>
                        <th style={styles.thCompact}>ASN</th>
                        <th style={styles.th}>ASN Org</th>
                        <th style={styles.thCompact}>Country</th>
                        <th style={styles.thCompact}>City</th>
                        <th style={styles.th}>RTTs (ms)</th>
                        <th style={styles.thCompact}>Avg RTT</th>
                        <th style={styles.thCompact}>Missing</th>
                        <th style={styles.th}>Notes</th>
                      </tr>
                    </thead>
                    <tbody>
                      {gtraceResult.parsed_hops.map((hop) => (
                        <tr key={hop.hop} style={styles.tr}>
                          <td style={styles.tdCompact}>{hop.hop}</td>
                          <td style={styles.td}>{hop.host || "-"}</td>
                          <td style={styles.tdCompact}>{hop.ip || "-"}</td>
                          <td style={styles.tdCompact}>{hop.asn || "-"}</td>
                          <td style={styles.td}>{hop.asn_org || "-"}</td>
                          <td style={styles.tdCompact}>{hop.country || "-"}</td>
                          <td style={styles.tdCompact}>{hop.city || "-"}</td>
                          <td style={styles.td}>{Array.isArray(hop.rtts_ms) ? hop.rtts_ms.join(", ") : "-"}</td>
                          <td style={styles.tdCompact}>{hop.avg_rtt_ms ?? "-"}</td>
                          <td style={styles.tdCompact}>{hop.missing_probes ?? 0}</td>
                          <td style={styles.tdWide}>{Array.isArray(hop.notes) && hop.notes.length ? hop.notes.join(" | ") : "-"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              <div style={styles.gtraceOutputWrap}>
                <pre style={styles.gtracePre}>{gtraceResult.stdout || gtraceResult.stderr || "No output"}</pre>
              </div>
            </div>
          )}
        </section>


        {summaryResult && (
          <section style={styles.section}>
            <SectionToolbar
              title="Capture overview"
              subtitle="High-level summary of the uploaded file."
              expanded={showOverview}
              onToggle={() => setShowOverview((v) => !v)}
            />

            {showOverview && (
              <>
                <div style={styles.metricGrid}>
                  <MetricCard label="Total packets" value={summaryResult.total_packets} />
                  <MetricCard label="Total bytes" value={summaryResult.total_bytes} />
                  <MetricCard label="Duration (s)" value={summaryResult.duration_seconds} />
                  <MetricCard label="Protocols seen" value={protocolCount} />
                </div>

                <div style={styles.twoColGrid}>
                  <InfoCard title="Protocols">
                    <SimpleList data={summaryResult.protocols} />
                  </InfoCard>
                  <InfoCard title="Top source IPs">
                    <SimpleList data={summaryResult.top_src_ips} />
                  </InfoCard>
                  <InfoCard title="Top destination IPs">
                    <SimpleList data={summaryResult.top_dst_ips} />
                  </InfoCard>
                  {jobResult && (
                    <InfoCard title="Job details">
                      <div style={styles.jobMeta}><span>Job ID</span><strong>{jobResult.job_id}</strong></div>
                      <div style={styles.jobMeta}><span>Filename</span><strong>{jobResult.filename}</strong></div>
                      <div style={styles.jobMeta}><span>Status</span><strong>{jobResult.status}</strong></div>
                      <div style={styles.jobMetaColumn}>
                        <span>Stored path</span>
                        <code style={styles.codeBlock}>{jobResult.stored_path}</code>
                      </div>
                    </InfoCard>
                  )}
                </div>
              </>
            )}
          </section>
        )}

        {(rootCausesResult.length > 0 || findingsResult.length > 0) && (
          <section style={styles.section}>
            <SectionToolbar
              title="Interpretation"
              subtitle="Probable causes first, then the supporting findings underneath."
              expanded={showInterpretation}
              onToggle={() => setShowInterpretation((v) => !v)}
            />

            {showInterpretation && (
              <div style={styles.analysisGrid}>
                <div>
                  <h3 style={styles.subSectionTitle}>Probable root causes</h3>
                  {rootCausesResult.length > 0 ? (
                    rootCausesResult.map((cause, index) => (
                      <CauseCard key={index} item={cause} onStreamClick={handleStreamLabelClick} />
                    ))
                  ) : (
                    <EmptyCard text="No root causes loaded yet." />
                  )}
                </div>

                <div>
                  <h3 style={styles.subSectionTitle}>Findings</h3>
                  {findingsResult.length > 0 ? (
                    findingsResult.map((finding, index) => (
                      <FindingCard key={index} item={finding} onStreamClick={handleStreamLabelClick} />
                    ))
                  ) : (
                    <EmptyCard text="No findings loaded yet." />
                  )}
                </div>
              </div>
            )}
          </section>
        )}

        {timelineResult && (
        <section style={{ marginTop: 24, padding: 16, border: "1px solid #555" }}>
          <h2>Timeline Analysis</h2>
          <div style={{ display: "grid", gap: 8 }}>
            <div>First issue seen: {String(timelineResult.first_issue_seen ?? "-")}</div>
            <div>Last issue seen: {String(timelineResult.last_issue_seen ?? "-")}</div>
            <div>
              Peak issue window: {timelineResult.peak_issue_window
                ? `${timelineResult.peak_issue_window.window_start_seconds}s - ${timelineResult.peak_issue_window.window_end_seconds}s (${timelineResult.peak_issue_window.critical_streams} critical streams)`
                : "-"}
            </div>
            <div>Dominant issue type in peak: {timelineResult.dominant_issue_type_in_peak || "-"}</div>
          </div>

          {Array.isArray(timelineResult.timeline_buckets) && timelineResult.timeline_buckets.length > 0 && (
            <div style={{ marginTop: 12, overflowX: "auto" }}>
              <table style={styles.table}>
                <thead>
                  <tr>
                    <th style={styles.thCompact}>Offset (s)</th>
                    <th style={styles.thCompact}>Critical Streams</th>
                    <th style={styles.th}>Dominant Issue</th>
                  </tr>
                </thead>
                <tbody>
                  {timelineResult.timeline_buckets.map((b, idx) => (
                    <tr key={idx} style={styles.tr}>
                      <td style={styles.tdCompact}>{b.offset_seconds}</td>
                      <td style={styles.tdCompact}>{b.critical_streams}</td>
                      <td style={styles.tdWide}>{b.dominant_issue_type || "-"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}

        {rcaError && (
          <div style={styles.errorBanner}>{rcaError}</div>
        )}

        {rcaSummaryResult && (
          <section style={styles.section}>
            <SectionToolbar
              title="RCA Dashboard"
              subtitle="Compact engineering diagnosis built from DNS, TCP, BIF, latency-chain, and stream evidence."
              expanded={showRcaDashboard}
              onToggle={() => setShowRcaDashboard((v) => !v)}
            />

            <div style={{ display: showRcaDashboard ? "grid" : "none", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 16, marginBottom: 18 }}>
              <div style={styles.gtraceInsightCard}>
                <h3 style={styles.cardTitle}>Primary issue</h3>
                <div style={{ fontSize: 18, fontWeight: 700, marginBottom: 8 }}>
                  {rcaSummaryResult.primary_issue || "-"}
                </div>
                <div style={{ marginBottom: 8 }}>Confidence: <b>{rcaSummaryResult.confidence || "-"}</b></div>
                <div>{rcaSummaryResult.executive_summary || "-"}</div>
              </div>

              <div style={styles.gtraceInsightCard}>
                <h3 style={styles.cardTitle}>Evidence</h3>
                <ul style={{ ...(styles.notesList || {}), textAlign: "left", margin: 0 }}>
                  {(rcaSummaryResult.evidence || []).map((item, idx) => (
                    <li key={idx} style={styles.noteItem}>{item}</li>
                  ))}
                </ul>
              </div>


              <div style={styles.gtraceInsightCard}>
                <h3 style={styles.cardTitle}>MTU / MSS / PMTUD Evidence</h3>
                <p style={styles.sectionText}>
                  Evaluates ICMP Fragmentation Needed, DF-bit behavior, MSS clamping, retransmissions, and possible offload artifacts.
                </p>
                <div>Health: <b>{rcaSummaryResult.mtu_summary?.mtu_health || "-"}</b></div>
                <div>Confirmed MTU streams: <b>{rcaSummaryResult.mtu_summary?.confirmed_mtu_streams ?? "-"}</b></div>
                <div>Probable blackhole streams: <b>{rcaSummaryResult.mtu_summary?.probable_mtu_blackhole_streams ?? "-"}</b></div>
                <div>MSS-clamped with retransmissions: <b>{rcaSummaryResult.mtu_summary?.mss_clamped_path_with_retransmissions_streams ?? "-"}</b></div>
                <div>ICMP frag-needed/PTB: <b>{rcaSummaryResult.mtu_summary?.icmp_frag_needed_count ?? "-"}</b></div>
                <p style={styles.sectionText}>
                  {rcaSummaryResult.mtu_summary?.summary || "-"}
                </p>
              </div>

              <div style={styles.gtraceInsightCard}>
                <h3 style={styles.cardTitle}>Engineer actions</h3>
                <ul style={{ ...(styles.notesList || {}), textAlign: "left", margin: 0 }}>
                  {(rcaSummaryResult.engineer_actions || []).map((item, idx) => (
                    <li key={idx} style={styles.noteItem}>{item}</li>
                  ))}
                </ul>
              </div>
            </div>

            <div style={{ ...styles.tableWrapTall, display: showRcaDashboard ? undefined : "none" }}>
              <table style={styles.table}>
                <thead>
                  <tr>
                    <th style={styles.th}>Domain</th>
                    <th style={styles.thCompact}>Count</th>
                    <th style={styles.thCompact}>Severity</th>
                    <th style={styles.th}>Issues</th>
                    <th style={styles.th}>Interpretation</th>
                    <th style={styles.th}>Action</th>
                    <th style={styles.thCompact}>Drilldown</th>
                  </tr>
                </thead>
                <tbody>
                  {(rcaSummaryResult.affected_domains || []).map((domain) => (
                    <tr key={domain.domain} style={styles.tr}>
                      <td style={styles.tdCompact}>{domain.domain || "-"}</td>
                      <td style={styles.tdCompact}>{domain.count ?? "-"}</td>
                      <td style={styles.tdCompact}>{domain.max_severity || "-"}</td>
                      <td style={styles.tdWide}>
                        {Object.entries(domain.issues || {}).map(([k, v]) => `${k}: ${v}`).join(", ") || "-"}
                      </td>
                      <td style={styles.tdWide}>{domain.sample_interpretation || "-"}</td>
                      <td style={styles.tdWide}>{domain.sample_action || "-"}</td>
                      <td style={styles.tdCompact}>
                        <button onClick={() => openImpactedStreamsForDomain(domain.domain)} style={styles.primaryButton}>
                          Open streams
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {selectedRcaDomain && latencyChainResult && (
              <div style={{ ...styles.gtraceInsightCard, marginTop: 18, display: showRcaDashboard ? undefined : "none" }}>
                <h3 style={styles.cardTitle}>Latency-chain details for {selectedRcaDomain}</h3>
                <div style={styles.tableWrapTall}>
                  <table style={styles.table}>
                    <thead>
                      <tr>
                        <th style={styles.th}>Stream</th>
                        <th style={styles.thCompact}>DNS ms</th>
                        <th style={styles.thCompact}>Gap ms</th>
                        <th style={styles.thCompact}>RTT ms</th>
                        <th style={styles.thCompact}>First server data</th>
                        <th style={styles.thCompact}>Bottleneck</th>
                        <th style={styles.thCompact}>Severity</th>
                        <th style={styles.th}>Interpretation</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(latencyChainResult.chains || [])
                        .filter((c) => ((c.query_name || "").toLowerCase()).includes((selectedRcaDomain || "").toLowerCase()))
                        .slice(0, 25)
                        .map((c, idx) => (
                          <tr key={`${c.tcp_stream_id}-${idx}`} style={styles.tr}>
                            <td style={styles.tdCompact}>{c.tcp_stream_id || "-"}</td>
                            <td style={styles.tdCompact}>{c.dns_latency_ms ?? "-"}</td>
                            <td style={styles.tdCompact}>{c.dns_to_tcp_gap_ms ?? "-"}</td>
                            <td style={styles.tdCompact}>{c.tcp_rtt_ms ?? "-"}</td>
                            <td style={styles.tdCompact}>{c.first_server_data_ms ?? "-"} ms</td>
                            <td style={styles.tdCompact}>{c.bottleneck || "-"}</td>
                            <td style={styles.tdCompact}>{c.severity || "-"}</td>
                            <td style={styles.tdWide}>{c.interpretation || "-"}</td>
                          </tr>
                        ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </section>
        )}

      {streamsResult.length > 0 && (
          <section id="top-streams-section" style={styles.section}>
            <SectionToolbar
              title="Top streams"
              subtitle="Click a row to inspect packets and stream-specific notes."
              expanded={showStreams}
              onToggle={() => setShowStreams((v) => !v)}
              rightNode={<div style={styles.badgeMuted}>{filteredStreams.length} streams shown</div>}
            />

            {showStreams && (
                <>
                                      {selectedRcaDomain && (
                      <div style={styles.noteCard}>
                        RCA drilldown active for <b>{selectedRcaDomain}</b>: showing {selectedRcaStreamIds.length} correlated stream(s).
                        <button
                          onClick={() => {
                            setSelectedRcaDomain("");
                            setSelectedRcaStreamIds([]);
                            setStreamSearch("");
                          }}
                          style={{ ...styles.secondaryButton, marginLeft: 12 }}
                        >
                          Clear RCA filter
                        </button>
                      </div>
                    )}

<div style={styles.streamFilterBar}>
                    <input
                      type="text"
                      placeholder="Search by IP, port, SNI, app, summary..."
                      value={streamSearch}
                      onChange={(e) => setStreamSearch(e.target.value)}
                      style={styles.streamSearchInput}
                    />

                    <select
                      value={streamSeverityFilter}
                      onChange={(e) => setStreamSeverityFilter(e.target.value)}
                      style={styles.streamFilterSelect}
                    >
                      <option value="all">All severities</option>
                      <option value="high">High</option>
                      <option value="medium">Medium</option>
                      <option value="low">Low</option>
                      <option value="info">Info</option>
                    </select>

                    <select
                      value={streamRowLimit}
                      onChange={(e) => setStreamRowLimit(e.target.value)}
                      style={styles.streamFilterSelect}
                    >
                      <option value="50">50 rows</option>
                      <option value="100">100 rows</option>
                      <option value="200">200 rows</option>
                      <option value="500">500 rows</option>
                      <option value="all">All rows</option>
                    </select>
                  </div>

              <div style={styles.tableWrap}>
                <table style={styles.table}>
                  <thead>
                    <tr>
                      <th style={styles.thCompact}>Protocol</th>
                      <th style={styles.th}>Endpoint A</th>
                      <th style={styles.th}>Endpoint B</th>
                      <th style={styles.th}>SNI</th>
                      <th style={styles.th}>Application</th>
                      <th style={styles.th}>TCP insight</th>
                      <th style={styles.th}>Confidence</th>
                      <th style={styles.thCompact}>Packets</th>
                      <th style={styles.thCompact}>Bytes</th>
                      <th style={styles.thCompact}>Duration</th>
                        <th style={styles.thCompact}>Start UTC</th>
                        <th style={styles.thCompact}>End UTC</th>
                        <th style={styles.thCompact}>Start Offset</th>
                      <th style={styles.thCompact}>A → B</th>
                      <th style={styles.thCompact}>B → A</th>
                      <th style={styles.thCompact}>Flags</th>
                      <th style={styles.thCompact}>Health</th>
                      <th style={styles.thCompact}>Handshake</th>
                      <th style={styles.thCompact}>Retrans</th>
                      <th style={styles.thCompact}>Dup ACK</th>
                      <th style={styles.thCompact}>Zero Win</th>
                      <th style={styles.thCompact}>RTT ms</th>
                      <th style={styles.thCompact}>Throughput bps</th>
                      <th style={styles.thCompact}>Max BIF</th>
                      <th style={styles.thCompact}>Avg BIF</th>
                      <th style={styles.thCompact}>TCP Limiter</th>
                      <th style={styles.th}>Limiter reason</th>
                      <th style={styles.th}>BIF Interpretation</th>
                      <th style={styles.th}>Engineer action</th>
                        <th style={styles.thCompact}>Score</th>
                        <th style={styles.thCompact}>Severity</th>
                        <th style={styles.th}>Why Critical</th>
                        <th style={styles.thCompact}>Directional</th>
                        <th style={styles.th}>Impact Hint</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredStreams.map((stream) => {
                      const isSelected = selectedStream?.stream_id === stream.stream_id;

                      return (
                        <tr
                          key={stream.stream_id}
                          onClick={() => fetchStreamDrilldown(stream)}
                          style={{
                            ...styles.tr,
                            ...(isSelected ? styles.trSelected : {}),
                          }}
                        >
                          <td style={styles.tdCompact}>{stream.protocol}</td>
                          <td style={styles.td}>{stream.endpoint_a_ip}:{stream.endpoint_a_port}</td>
                          <td style={styles.td}>{stream.endpoint_b_ip}:{stream.endpoint_b_port}</td>
                          <td style={styles.tdSni}>{stream.tls_sni || "-"}</td>
                          <td style={styles.td}><ApplicationBadge value={stream.application} /></td>
                          <td style={styles.tdWide}>{stream.stream_summary || "-"}</td>
                          <td style={styles.td}>
                            <ConfidenceBadge value={stream.stream_confidence} />
                          </td>
                          <td style={styles.tdCompact}>{stream.packet_count}</td>
                          <td style={styles.tdCompact}>{stream.byte_count}</td>
                          <td style={styles.tdCompact}>{stream.duration_seconds}</td>
                            <td style={styles.tdCompact}>{__formatUtcStreamTs(stream.start_time)}</td>
                            <td style={styles.tdCompact}>{__formatUtcStreamTs(stream.end_time)}</td>
                            <td style={styles.tdCompact}>{__formatStreamStartOffset(stream.start_time, streamsResult)}</td>
                          <td style={styles.tdCompact}>{stream.packets_a_to_b} / {stream.bytes_a_to_b} B</td>
                          <td style={styles.tdCompact}>{stream.packets_b_to_a} / {stream.bytes_b_to_a} B</td>
                          <td style={styles.tdCompact}>{(stream.tcp_flags_seen || []).join(", ")}</td>
                          <td style={styles.tdCompact}><Pill text={stream.stream_health} /></td>
                          <td style={styles.tdCompact}><Pill text={stream.handshake_status} /></td>
                          <td style={styles.tdCompact}>{stream.retransmission_count}</td>
                          <td style={styles.tdCompact}>{stream.duplicate_ack_count}</td>
                          <td style={styles.tdCompact}>{stream.zero_window_count}</td>
                          <td style={styles.tdCompact}>{stream.handshake_rtt_ms ?? "-"}</td>
                          <td style={styles.tdCompact}>{stream.throughput_bps}</td>
                          <td style={styles.tdCompact}>{stream.max_bytes_in_flight ?? 0}</td>
                          <td style={styles.tdCompact}>{stream.avg_bytes_in_flight ?? 0}</td>
                          <td style={styles.tdCompact}>{stream.tcp_limiter || "-"}</td>
                          <td style={styles.tdWide}>{stream.tcp_limiter_reason || "-"}</td>
                          <td style={styles.tdWide}>{stream.tcp_bif_interpretation || "-"}</td>
                          <td style={styles.tdWide}>{stream.tcp_engineer_action_hint || "-"}</td>
                            <td style={styles.tdCompact}>{stream.criticality_score ?? 0}</td>
                            <td style={styles.tdCompact}>{stream.criticality_severity || "info"}</td>
                            <td style={styles.tdWide}>{stream.criticality_reason || "-"}</td>
                            <td style={styles.tdCompact}>{stream.directional_hint || "-"}</td>
                            <td style={styles.tdWide}>{stream.impact_hint || "-"}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
                </>
            )}
          </section>
        )}


        <section style={styles.section}>
          <SectionToolbar
            title="HTTP panel"
            subtitle="Minimal HTTP request/response records detected from packet payloads."
            expanded={showHttpPanel}
            onToggle={() => setShowHttpPanel((v) => !v)}
          />

          {showHttpPanel && (
            <>
              {httpError && (
                <div style={styles.errorBanner}>{httpError}</div>
              )}

              {!httpError && !httpLoading && httpRecords.length === 0 && (
                <div style={styles.noteCard}>No HTTP records loaded yet. Click "Get HTTP".</div>
              )}

              {httpLoading && (
                <div style={styles.noteCard}>Loading HTTP records...</div>
              )}

              {!httpLoading && httpRecords.length > 0 && (
                <div style={styles.tableWrapTall}>
                  <table style={styles.table}>
                    <thead>
                      <tr>
                        <th style={styles.thCompact}>Frame</th>
                        <th style={styles.thCompact}>Type</th>
                        <th style={styles.thCompact}>Method</th>
                        <th style={styles.th}>Host</th>
                        <th style={styles.th}>Path</th>
                        <th style={styles.thCompact}>Status</th>
                        <th style={styles.th}>First line</th>
                      </tr>
                    </thead>
                    <tbody>
                      {httpRecords.slice(0, 200).map((rec, idx) => (
                        <tr key={`${rec.frame || "f"}-${idx}`} style={styles.tr}>
                          <td style={styles.tdCompact}>{rec.frame ?? "-"}</td>
                          <td style={styles.tdCompact}>{rec.type || "-"}</td>
                          <td style={styles.tdCompact}>{rec.method || "-"}</td>
                          <td style={styles.tdCompact}>{rec.host || "-"}</td>
                          <td style={styles.tdWide}>{rec.path || "-"}</td>
                          <td style={styles.tdCompact}>{rec.status_code ?? "-"}</td>
                          <td style={styles.tdWide}>{rec.first_line || "-"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </>
          )}
        </section>

        {selectedStream && (
          <section style={styles.section}>
            <SectionToolbar
              title="Stream drilldown"
              subtitle="Detailed evidence for the selected stream."
              expanded={showDrilldown}
              onToggle={() => setShowDrilldown((v) => !v)}
              rightNode={
                <div style={styles.badgeMuted}>
                  {selectedStream.protocol} · {selectedStream.endpoint_a_ip}:{selectedStream.endpoint_a_port}
                </div>
              }
            />

            {showDrilldown && (
              <>
                <div style={styles.drilldownGrid}>
                  <InfoCard title="Stream summary">
                    <div style={styles.jobMeta}><span>Stream ID</span><strong>{selectedStream.stream_id}</strong></div>
                    <div style={styles.jobMeta}><span>Label</span><strong>{selectedStream.stream_label}</strong></div>
                    <div style={styles.jobMeta}><span>SNI</span><strong>{selectedStream.tls_sni || "-"}</strong></div>
                    <div style={styles.jobMeta}><span>TCP insight</span><strong>{selectedStream.stream_summary || "-"}</strong></div>
                    <div style={styles.jobMeta}><span>Confidence</span><strong>{selectedStream.stream_confidence}</strong></div>
                    <div style={styles.jobMeta}><span>Health</span><strong>{selectedStream.stream_health}</strong></div>
                    <div style={styles.jobMeta}><span>Handshake</span><strong>{selectedStream.handshake_status}</strong></div>
                    <div style={styles.jobMeta}><span>Retransmissions</span><strong>{selectedStream.retransmission_count}</strong></div>
                    <div style={styles.jobMeta}><span>Duplicate ACKs</span><strong>{selectedStream.duplicate_ack_count}</strong></div>
                    <div style={styles.jobMeta}><span>Zero window</span><strong>{selectedStream.zero_window_count}</strong></div>
                    <div style={styles.jobMeta}><span>RTT ms</span><strong>{selectedStream.handshake_rtt_ms ?? "-"}</strong></div>
                    <div style={styles.jobMeta}><span>Throughput bps</span><strong>{selectedStream.throughput_bps}</strong></div>
                  </InfoCard>

                  <InfoCard title="Notes">
                    {(selectedStream.notes || []).length > 0 ? (
                      <ul style={{ ...(styles.notesList || {}), textAlign: "left" }}>
                        {selectedStream.notes.map((note, idx) => (
                          <li key={idx} style={styles.noteItem}>{note}</li>
                        ))}
                      </ul>
                    ) : (
                      <div style={styles.emptyText}>No notes for this stream.</div>
                    )}
                  </InfoCard>
                </div>

                <div style={styles.packetPanel}>
                  <div style={styles.packetHeader}>
                    <h3 style={styles.subSectionTitle}>Packets in stream</h3>
                    <div style={styles.badgeMuted}>{selectedStreamPackets.length} packets shown</div>
                  </div>

                  {streamDrilldownLoading ? (
                    <div style={styles.emptyText}>Loading stream packets...</div>
                  ) : (
                    <div style={styles.tableWrapTall}>
                      <table style={styles.table}>
                        <thead>
                          <tr>
                            <th style={styles.th}>Frame</th>
                            <th style={styles.th}>Time</th>
                            <th style={styles.th}>Source</th>
                            <th style={styles.th}>Destination</th>
                            <th style={styles.thCompact}>Protocol</th>
                            <th style={styles.th}>Length</th>
                            <th style={styles.th}>Seq</th>
                            <th style={styles.th}>Ack</th>
                            <th style={styles.th}>Window</th>
                            <th style={styles.th}>Info</th>
                            <th style={styles.thCompact}>BIF</th>
                          </tr>
                        </thead>
                        <tbody>
                          {selectedStreamPackets.map((pkt, idx) => (
                            <tr key={`${pkt.frame}-${pkt.time}`} style={styles.tr}>
                              <td style={styles.td}>{pkt.frame}</td>
                              <td style={styles.td}>{pkt.time}</td>
                              <td style={styles.td}>{pkt.src}{pkt.src_port ? `:${pkt.src_port}` : ""}</td>
                              <td style={styles.td}>{pkt.dst}{pkt.dst_port ? `:${pkt.dst_port}` : ""}</td>
                              <td style={styles.td}>{pkt.protocol}</td>
                              <td style={styles.td}>{pkt.length}</td>
                              <td style={styles.td}>{pkt.tcp_seq ?? "-"}</td>
                              <td style={styles.td}>{pkt.tcp_ack ?? "-"}</td>
                              <td style={styles.td}>{pkt.tcp_window ?? "-"}</td>
                              <td style={styles.td}>{pkt.info}</td>
                              <td style={styles.tdCompact}>{selectedStream?.bytes_in_flight_samples?.[idx] ?? selectedStream?.bytes_in_flight_samples?.[selectedStream?.bytes_in_flight_samples?.length - 1] ?? "ACK/control"}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              </>
            )}
          </section>
        )}
      </div>
    </div>
  );
}

function SectionToolbar({ title, subtitle, expanded, onToggle, rightNode }) {
  return (
    <div style={styles.sectionHeader}>
      <div>
        <h2 style={styles.sectionTitle}>{title}</h2>
        <p style={styles.sectionText}>{subtitle}</p>
      </div>
      <div style={styles.toolbarRight}>
        {rightNode}
        <button onClick={onToggle} style={styles.collapseButton}>
          {expanded ? "Collapse" : "Expand"}
        </button>
      </div>
    </div>
  );
}

function MetricCard({ label, value }) {
  return (
    <div style={styles.metricCard}>
      <div style={styles.metricLabel}>{label}</div>
      <div style={styles.metricValue}>{value}</div>
    </div>
  );
}

function InfoCard({ title, children }) {
  return (
    <div style={styles.infoCard}>
      <h3 style={styles.cardTitle}>{title}</h3>
      {children}
    </div>
  );
}

function SimpleList({ data }) {
  if (!data || Object.keys(data).length === 0) {
    return <div style={styles.emptyText}>No data.</div>;
  }

  return (
    <div style={styles.keyValueList}>
      {Object.entries(data).map(([key, value]) => (
        <div key={key} style={styles.keyValueRow}>
          <span style={styles.keyText}>{key}</span>
          <strong style={styles.valueText}>{value}</strong>
        </div>
      ))}
    </div>
  );
}

function CauseCard({ item, onStreamClick }) {
  return (
    <div style={{ ...styles.insightCard, borderLeft: `4px solid ${severityColor[item.severity] || "#64748b"}` }}>
      <div style={styles.insightHeader}>
        <h4 style={styles.insightTitle}>{item.title}</h4>
        <span style={{ ...styles.severityBadge, background: severityColor[item.severity] || "#334155" }}>
          {item.severity}
        </span>
      </div>
      <div style={styles.insightMeta}>Category: {item.category} · Confidence: {item.confidence}</div>
      <p style={styles.insightText}>{item.summary}</p>
      <ul style={{ ...(styles.notesList || {}), textAlign: "left" }}>
        {(item.evidence || []).map((entry, idx) => (
          <li key={idx} style={styles.noteItem}>{entry}</li>
        ))}
      </ul>
      {(item.stream_labels || []).length > 0 && (
        <div style={styles.relatedBlock}>
          <div style={styles.relatedTitle}>Related streams</div>
          <div style={styles.relatedList}>
            {item.stream_labels.map((label, idx) => (
              <button key={idx} style={styles.linkChip} onClick={() => onStreamClick({ label, stream_id: item.stream_ids?.[idx] })}>
                {label}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function FindingCard({ item, onStreamClick }) {
  return (
    <div style={{ ...styles.insightCard, borderLeft: `4px solid ${severityColor[item.severity] || "#64748b"}` }}>
      <div style={styles.insightHeader}>
        <h4 style={styles.insightTitle}>{item.title}</h4>
        <span style={{ ...styles.severityBadge, background: severityColor[item.severity] || "#334155" }}>
          {item.severity}
        </span>
      </div>
      <div style={styles.insightMeta}>Type: {item.type} · Affected streams: {item.affected_streams}</div>
      <p style={styles.insightText}>{item.description}</p>
      {(item.stream_labels || []).length > 0 && (
        <div style={styles.relatedBlock}>
          <div style={styles.relatedTitle}>Related streams</div>
          <div style={styles.relatedList}>
            {item.stream_labels.map((label, idx) => (
              <button key={idx} style={styles.linkChip} onClick={() => onStreamClick({ label, stream_id: item.stream_ids?.[idx] })}>
                {label}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function EmptyCard({ text }) {
  return <div style={styles.infoCard}>{text}</div>;
}

function Pill({ text }) {
  return <span style={styles.pill}>{text}</span>;
}

function ConfidenceBadge({ value }) {
  const pct = Math.round((value || 0) * 100);
  let bg = "#1e293b";
  let color = "#cbd5e1";

  if (pct >= 80) {
    bg = "rgba(239,68,68,0.18)";
    color = "#fecaca";
  } else if (pct >= 60) {
    bg = "rgba(245,158,11,0.18)";
    color = "#fde68a";
  } else {
    bg = "rgba(59,130,246,0.18)";
    color = "#bfdbfe";
  }

  return <span style={{ ...styles.confidenceBadge, background: bg, color }}>{pct}%</span>;
}

function ApplicationBadge({ value }) {
  const label = value || "-";
  return <span style={styles.appBadge}>{label}</span>;
}

const styles = {
  page: {
    minHeight: "100vh",
    background: "#0b1020",
    color: "#e5e7eb",
    padding: "24px 32px 40px 32px",
  },
  shell: {
    maxWidth: "1680px",
    margin: "0 auto",
  },
  header: {
    display: "grid",
    gridTemplateColumns: "1.8fr 1fr",
    gap: "24px",
    alignItems: "stretch",
    marginBottom: "24px",
  },
  eyebrow: {
    fontSize: "12px",
    textTransform: "uppercase",
    letterSpacing: "0.12em",
    color: "#94a3b8",
    marginBottom: "8px",
  },
  title: {
    margin: "0 0 10px 0",
    fontSize: "42px",
    lineHeight: 1.1,
    color: "#f8fafc",
  },
  subtitle: {
    margin: 0,
    color: "#94a3b8",
    fontSize: "16px",
    maxWidth: "760px",
  },
  uploadCard: {
    background: "#111827",
    border: "1px solid #1f2937",
    borderRadius: "16px",
    padding: "18px",
    display: "flex",
    flexDirection: "column",
    justifyContent: "space-between",
    gap: "12px",
    boxShadow: "0 10px 30px rgba(0,0,0,0.22)",
  },
  uploadTitle: {
    fontSize: "14px",
    fontWeight: 700,
    color: "#cbd5e1",
  },
  fileInput: {
    color: "#cbd5e1",
  },
  primaryButton: {
    background: "#2563eb",
    color: "#fff",
    border: 0,
    borderRadius: "10px",
    padding: "12px 16px",
    fontWeight: 700,
    cursor: "pointer",
  },
  secondaryButton: {
    background: "#1f2937",
    color: "#e5e7eb",
    border: "1px solid #374151",
    borderRadius: "10px",
    padding: "10px 14px",
    fontWeight: 600,
    cursor: "pointer",
  },
  collapseButton: {
    background: "#0f172a",
    color: "#cbd5e1",
    border: "1px solid #334155",
    borderRadius: "10px",
    padding: "10px 14px",
    fontWeight: 700,
    cursor: "pointer",
    minWidth: "100px",
  },
  toolbarRight: {
    display: "flex",
    alignItems: "center",
    gap: "10px",
    flexWrap: "wrap",
  },
  errorBanner: {
    background: "rgba(239,68,68,0.12)",
    border: "1px solid rgba(239,68,68,0.35)",
    color: "#fecaca",
    padding: "12px 14px",
    borderRadius: "12px",
    marginBottom: "20px",
  },
  section: {
    background: "#111827",
    border: "1px solid #1f2937",
    borderRadius: "18px",
    padding: "22px",
    marginBottom: "24px",
    boxShadow: "0 10px 30px rgba(0,0,0,0.18)",
  },
  sectionHeader: {
    display: "flex",
    justifyContent: "space-between",
    gap: "16px",
    alignItems: "flex-start",
    marginBottom: "18px",
  },
  sectionTitle: {
    margin: 0,
    fontSize: "22px",
    color: "#f8fafc",
  },
  subSectionTitle: {
    margin: "0 0 14px 0",
    fontSize: "18px",
    color: "#f8fafc",
  },
  sectionText: {
    margin: "6px 0 0 0",
    color: "#94a3b8",
    fontSize: "14px",
  },
  actionRow: {
    display: "flex",
    gap: "10px",
    flexWrap: "wrap",
  },
  badge: {
    background: "#0f172a",
    color: "#cbd5e1",
    border: "1px solid #334155",
    borderRadius: "999px",
    padding: "8px 12px",
    fontSize: "12px",
    fontWeight: 700,
    textTransform: "uppercase",
  },
  badgeMuted: {
    background: "#0f172a",
    color: "#94a3b8",
    border: "1px solid #334155",
    borderRadius: "999px",
    padding: "8px 12px",
    fontSize: "12px",
    fontWeight: 700,
  },
  metricGrid: {
    display: "grid",
    gridTemplateColumns: "repeat(4, minmax(0, 1fr))",
    gap: "16px",
    marginBottom: "18px",
  },
  metricCard: {
    background: "#0f172a",
    border: "1px solid #1e293b",
    borderRadius: "14px",
    padding: "18px",
  },
  metricLabel: {
    color: "#94a3b8",
    fontSize: "13px",
    marginBottom: "10px",
  },
  metricValue: {
    color: "#f8fafc",
    fontWeight: 800,
    fontSize: "28px",
    lineHeight: 1.1,
  },
  twoColGrid: {
    display: "grid",
    gridTemplateColumns: "repeat(2, minmax(0, 1fr))",
    gap: "16px",
  },
  analysisGrid: {
    display: "grid",
    gridTemplateColumns: "1fr 1fr",
    gap: "20px",
  },
  drilldownGrid: {
    display: "grid",
    gridTemplateColumns: "1.2fr 1fr",
    gap: "16px",
    marginBottom: "18px",
  },
  infoCard: {
    background: "#0f172a",
    border: "1px solid #1e293b",
    borderRadius: "14px",
    padding: "16px",
  },
  cardTitle: {
    margin: "0 0 14px 0",
    fontSize: "16px",
    color: "#f8fafc",
  },
  keyValueList: {
    display: "flex",
    flexDirection: "column",
    gap: "10px",
  },
  keyValueRow: {
    display: "flex",
    justifyContent: "space-between",
    gap: "12px",
    paddingBottom: "8px",
    borderBottom: "1px solid #1f2937",
  },
  keyText: {
    color: "#cbd5e1",
    overflowWrap: "anywhere",
  },
  valueText: {
    color: "#f8fafc",
  },
  jobMeta: {
    display: "flex",
    justifyContent: "space-between",
    gap: "16px",
    padding: "8px 0",
    borderBottom: "1px solid #1f2937",
    color: "#cbd5e1",
  },
  jobMetaColumn: {
    display: "flex",
    flexDirection: "column",
    gap: "8px",
    paddingTop: "10px",
    color: "#cbd5e1",
  },
  codeBlock: {
    background: "#020617",
    border: "1px solid #1e293b",
    color: "#cbd5e1",
    padding: "10px",
    borderRadius: "10px",
    whiteSpace: "pre-wrap",
    wordBreak: "break-all",
  },
  insightCard: {
    background: "#0f172a",
    border: "1px solid #1e293b",
    borderRadius: "14px",
    padding: "16px",
    marginBottom: "14px",
  },
  insightHeader: {
    display: "flex",
    justifyContent: "space-between",
    gap: "12px",
    alignItems: "center",
    marginBottom: "8px",
  },
  insightTitle: {
    margin: 0,
    fontSize: "16px",
    color: "#f8fafc",
  },
  severityBadge: {
    color: "#fff",
    borderRadius: "999px",
    padding: "4px 10px",
    fontSize: "12px",
    fontWeight: 700,
    textTransform: "uppercase",
  },
  insightMeta: {
    color: "#94a3b8",
    fontSize: "13px",
    marginBottom: "10px",
  },
  insightText: {
    margin: 0,
    color: "#cbd5e1",
    lineHeight: 1.5,
  },
  relatedBlock: {
    marginTop: "12px",
    paddingTop: "12px",
    borderTop: "1px solid #1f2937",
  },
  relatedTitle: {
    fontSize: "12px",
    textTransform: "uppercase",
    letterSpacing: "0.04em",
    color: "#94a3b8",
    marginBottom: "8px",
  },
  relatedList: {
    display: "flex",
    flexWrap: "wrap",
    gap: "8px",
  },
  linkChip: {
    background: "#111827",
    color: "#bfdbfe",
    border: "1px solid #1d4ed8",
    borderRadius: "999px",
    padding: "6px 10px",
    fontSize: "12px",
    cursor: "pointer",
  },
  streamFilterBar: {
    display: "flex",
    gap: "12px",
    flexWrap: "wrap",
    alignItems: "center",
    marginBottom: "14px",
  },

  streamSearchInput: {
    minWidth: "320px",
    flex: "1 1 360px",
    background: "#0f172a",
    color: "#e2e8f0",
    border: "1px solid rgba(148,163,184,0.25)",
    borderRadius: "10px",
    padding: "10px 12px",
    outline: "none",
  },

  streamFilterSelect: {
    background: "#0f172a",
    color: "#e2e8f0",
    border: "1px solid rgba(148,163,184,0.25)",
    borderRadius: "10px",
    padding: "10px 12px",
    outline: "none",
  },

  tableWrap: {
    overflowX: "auto",
    border: "1px solid #1f2937",
    borderRadius: "14px",
  },
  tableWrapTall: {
    overflow: "auto",
    maxHeight: "460px",
    border: "1px solid #1f2937",
    borderRadius: "14px",
  },
  table: {
    width: "max-content",
    minWidth: "100%",
    borderCollapse: "collapse",
    tableLayout: "auto",
  },
  th: {
    position: "sticky",
    top: 0,
    background: "#0f172a",
    color: "#cbd5e1",
    textAlign: "left",
    padding: "12px",
    borderBottom: "1px solid #1f2937",
    fontSize: "12px",
    textTransform: "uppercase",
    letterSpacing: "0.04em",
    zIndex: 1,
  },
  thCompact: {
    position: "sticky",
    top: 0,
    background: "#0f172a",
    color: "#cbd5e1",
    textAlign: "left",
    padding: "12px",
    borderBottom: "1px solid #1f2937",
    fontSize: "12px",
    textTransform: "uppercase",
    letterSpacing: "0.04em",
    zIndex: 1,
    whiteSpace: "nowrap",
    width: "1%",
  },
  td: {
    padding: "12px",
    borderBottom: "1px solid #1f2937",
    color: "#e5e7eb",
    fontSize: "13px",
    verticalAlign: "top",
    whiteSpace: "normal",
  },
  tdCompact: {
    padding: "12px",
    borderBottom: "1px solid #1f2937",
    color: "#e5e7eb",
    fontSize: "13px",
    verticalAlign: "top",
    whiteSpace: "nowrap",
    width: "1%",
  },
  tdWide: {
    padding: "12px",
    borderBottom: "1px solid #1f2937",
    color: "#cbd5e1",
    fontSize: "13px",
    minWidth: "320px",
    maxWidth: "520px",
    verticalAlign: "top",
    whiteSpace: "normal",
    wordBreak: "break-word",
    lineHeight: 1.5,
  },
  tdSni: {
    padding: "12px",
    borderBottom: "1px solid #1f2937",
    color: "#93c5fd",
    fontSize: "13px",
    minWidth: "180px",
    maxWidth: "280px",
    verticalAlign: "top",
    whiteSpace: "normal",
    wordBreak: "break-word",
  },
  tr: {
    cursor: "pointer",
    background: "#111827",
  },
  trSelected: {
    background: "#172554",
  },
  pill: {
    background: "#1e293b",
    color: "#cbd5e1",
    border: "1px solid #334155",
    borderRadius: "999px",
    padding: "3px 8px",
    fontSize: "12px",
    whiteSpace: "nowrap",
  },
  confidenceBadge: {
    borderRadius: "999px",
    padding: "4px 10px",
    fontSize: "12px",
    fontWeight: 700,
    whiteSpace: "nowrap",
  },
  appBadge: {
    display: "inline-block",
    background: "rgba(37,99,235,0.16)",
    color: "#bfdbfe",
    border: "1px solid rgba(59,130,246,0.35)",
    borderRadius: "999px",
    padding: "4px 10px",
    fontSize: "12px",
    fontWeight: 700,
    whiteSpace: "nowrap",
  },
  notesList: {
    margin: "8px 0 0 18px",
    padding: 0,
    color: "#cbd5e1",
  },
  noteItem: {
    marginBottom: "6px",
    lineHeight: 1.5,
  },
  emptyText: {
    color: "#94a3b8",
    fontSize: "14px",
  },
  packetPanel: {
    marginTop: "12px",
  },
  packetHeader: {
    display: "flex",
    justifyContent: "space-between",
    gap: "12px",
    alignItems: "center",
    marginBottom: "12px",
  },
  gtraceForm: {
    display: "flex",
    gap: "10px",
    flexWrap: "wrap",
    marginTop: "8px",
  },
  gtraceInput: {
    background: "#0f172a",
    color: "#e5e7eb",
    border: "1px solid #334155",
    borderRadius: "10px",
    padding: "10px 12px",
    minWidth: "120px",
  },
  gtraceInputWide: {
    background: "#0f172a",
    color: "#e5e7eb",
    border: "1px solid #334155",
    borderRadius: "10px",
    padding: "10px 12px",
    minWidth: "320px",
    flex: "1 1 320px",
  },
  gtraceInputSmall: {
    background: "#0f172a",
    color: "#e5e7eb",
    border: "1px solid #334155",
    borderRadius: "10px",
    padding: "10px 12px",
    width: "110px",
  },
  gtraceResultCard: {
    background: "#0f172a",
    border: "1px solid #1e293b",
    borderRadius: "14px",
    padding: "16px",
    marginTop: "16px",
  },
  gtraceMetaRow: {
    display: "flex",
    gap: "20px",
    flexWrap: "wrap",
    marginBottom: "10px",
    color: "#cbd5e1",
    fontSize: "14px",
  },
  gtraceInsightCard: {
    background: "#0f172a",
    border: "1px solid #1e293b",
    borderRadius: "14px",
    padding: "16px",
    marginTop: "16px",
    marginBottom: "16px",
  },
  gtraceOutputWrap: {
    marginTop: "12px",
    border: "1px solid #1f2937",
    borderRadius: "12px",
    overflow: "auto",
    background: "#020617",
  },
  gtracePre: {
    margin: 0,
    padding: "14px",
    color: "#d1d5db",
    fontSize: "13px",
    lineHeight: 1.5,
    whiteSpace: "pre-wrap",
    wordBreak: "break-word",
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace",
  },
};

