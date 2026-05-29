# Developer Guide

## Components

| Service | Purpose | Local endpoint |
| --- | --- | --- |
| `apk-scanner` | APK upload, static extraction, downstream dispatch | `http://localhost:5000/swagger/` |
| `network-inspector` | Network findings | `http://localhost:5001/swagger/` |
| `secret-hunter` | Secret detection | `http://localhost:5002/swagger/` |
| `crypto-check` | Cryptographic checks | `http://localhost:8084/swagger-ui.html` |
| `reportgen` | PDF, JSON and SARIF export | `http://localhost:3005/api/reports` |
| `fixsuggest` | MASVS/LLM remediation suggestions | `http://localhost:8000/docs` |
| `ml-model` | LightGBM training and table output | `http://localhost:8001/docs` |

## Configuration

The Docker Compose deployment provides `MONGODB_URI`, `MONGODB_DATABASE`,
service URLs and Kafka brokers. Relevant optional controls include:

```text
NOTIFICATION_MAX_ATTEMPTS=3
NOTIFICATION_TIMEOUT_SECONDS=10
NOTIFICATION_RETRY_DELAY_SECONDS=1
ML_MIN_LABEL_CONFIDENCE=0.75
OPENROUTER_API_KEY=<set outside version control>
OPENROUTER_MODEL=<configured model>
```

Do not commit real API keys into `docker-compose.yml` or source files; provide
them using `.env` or deployment secrets.

## Add Or Extend A Service

1. Expose a health endpoint and document its request/response contract.
2. Write results using the shared `scan_id`; do not infer cross-service joins
   from filenames.
3. Add service environment variables, volume requirements and health checks to
   `backend/docker-compose.yml`.
4. Update ReportGen normalization or ML extraction only when the new service
   emits reportable/training evidence.
5. Add a benchmark measurement column only when the data can be captured in
   `scripts/run-benchmark-evaluation.js` or imported from a measured CSV.

## Key APIs

```text
POST /api/scan?force=true                      apk-scanner APK upload
POST /api/retry-notifications/{scan_id}        replay unavailable downstream stages
POST /api/reports                              ReportGen format=pdf|json|sarif
GET  /api/v1/paper/tables                      ML evidence tables
GET  /api/v1/train/stream?source=mongodb       ML training stream
```

The reproducible execution commands are in `docs/reproducibility.md`.
