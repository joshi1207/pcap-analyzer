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

## Docker deployment

### Prerequisites

Install:

- Docker Engine or Docker Desktop
- Docker Compose v2

Supported deployment platforms:

- Linux with Docker Engine
- Windows with Docker Desktop and WSL 2
- macOS with Docker Desktop, including Apple Silicon

### Start the application

From the project root:

    docker compose up -d --build

Open:

    http://localhost:8080

Check service status:

    docker compose ps

Check the frontend health endpoint:

    curl http://localhost:8080/health

### Configure the host port

The default host port is `8080`.

Copy the environment example:

    cp .env.example .env

Then change:

    PCAP_ANALYZER_PORT=8080

For example, to use port `9080`:

    PCAP_ANALYZER_PORT=9080

Restart the deployment:

    docker compose up -d

The application will then be available at:

    http://localhost:9080

### Logs

View all logs:

    docker compose logs -f

View only backend logs:

    docker compose logs -f backend

View only frontend logs:

    docker compose logs -f frontend

### Stop the application

Stop containers while preserving analysis data:

    docker compose down

Stop containers and delete persistent analysis data:

    docker compose down -v

### Persistent data

Docker Compose stores runtime data in named volumes:

- `pcap-analyzer_uploads`
- `pcap-analyzer_results`
- `pcap-analyzer_gtrace-results`
- `pcap-analyzer_gtrace-cache`

List the volumes:

    docker volume ls --filter name=pcap-analyzer

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

Frontend URL:

    http://localhost:5173

Backend URL:

    http://localhost:8000

API documentation:

    http://localhost:8000/docs

During development, Vite proxies `/api` requests to the backend.

The backend runtime data directory defaults to:

    backend/data

It can be overridden with:

    PCAP_DATA_DIR=/custom/data/path

## Platform notes

### Linux

The backend requires the `NET_RAW` capability for GTrace and ICMP-related functions. This capability is already configured in `compose.yaml`.

### Windows

Use Docker Desktop with the WSL 2 backend enabled. Run Docker Compose from PowerShell, Windows Terminal, or a WSL shell.

### macOS

Docker Desktop is required. The backend Docker image detects `amd64` or `arm64` automatically and installs the matching GTrace binary.

## Data privacy

Packet captures may contain:

- Internal IP addresses
- Hostnames and DNS queries
- Session metadata
- Credentials
- Unencrypted application payloads

Only process captures in an approved environment. Do not upload sensitive customer captures to public services or repositories.

## Current status

The application has been validated with:

- Dockerized FastAPI backend
- Dockerized React frontend with Nginx
- Docker Compose networking
- Persistent named volumes
- PCAP upload through the Nginx reverse proxy
- Full packet-analysis processing
- Summary, findings, and stream API responses

This remains a pre-release project and should undergo security, licensing, and operational review before public distribution.
