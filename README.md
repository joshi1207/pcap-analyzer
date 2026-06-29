# PCAP Analyzer

PCAP Analyzer is a web-based network performance and root-cause analysis tool for PCAP and PCAPNG files.

## Capabilities

- Packet and TCP stream analysis
- DNS latency and DNS-to-TCP correlation
- TLS and application-flow analysis
- TCP retransmission and duplicate ACK detection
- Zero-window and receiver-pressure analysis
- Bytes-in-Flight analysis
- TCP limiter classification
- First Server Data and TTFB approximation
- MTU, MSS, and PMTUD analysis
- Latency-chain analysis
- Root Cause Analysis dashboard
- Stream and packet drilldown
- PDF report export
- GTrace comparison support

## Development

Backend:

    cd backend
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

Frontend, in another terminal:

    cd frontend
    npm install
    npm run dev

Frontend URL: http://localhost:5173
Backend URL: http://localhost:8000
API documentation: http://localhost:8000/docs

During development, Vite proxies /api requests to the backend.

## Runtime data

Uploaded captures and generated results are stored below backend/data.
Runtime captures and analysis results are excluded from Git.

## Data privacy

Packet captures may contain internal addresses, hostnames, DNS queries, session metadata, credentials, or unencrypted payloads.
Only process captures in an approved environment.

## Distribution roadmap

- Backend and frontend Docker images
- Docker Compose deployment
- Private GitHub Container Registry distribution
- Windows Docker Desktop with WSL 2 support
- macOS Docker Desktop support
- GitHub Actions CI validation
- Public release after security and licensing review

## Status

Pre-release development. Not yet ready for public deployment.
