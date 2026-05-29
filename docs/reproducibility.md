# MobileSec Reproducibility Protocol

This protocol generates evidence from executable artifacts. It does not convert
historical scans into accuracy claims unless ground truth is supplied.

## Services

From `backend/`:

```powershell
docker compose up -d --build
docker compose ps
```

Expected service health endpoints:

```powershell
Invoke-RestMethod http://localhost:5000/health
Invoke-RestMethod http://localhost:3005/health
Invoke-RestMethod http://localhost:8001/api/v1/health
```

## Scan One APK

```powershell
$apk = "C:\path\to\sample.apk"
Invoke-RestMethod -Method Post -Form @{ file = Get-Item $apk } "http://localhost:5000/api/scan?force=true"
```

The returned `scan_id` identifies MongoDB records and downstream results. A
result with `status=partial` records unavailable downstream services; it must
not be counted as a complete pipeline run.

## Export One Report

Use a recorded scan result as ReportGen input and select the format under test:

```powershell
$payload = @{
  projectName = "sample"
  scanId = "replace-with-scan-id"
  format = "sarif"
  scanResults = @{ apkScanner = @{} }
} | ConvertTo-Json -Depth 5
Invoke-WebRequest -Method Post -ContentType "application/json" `
  -Body $payload "http://localhost:3005/api/reports" `
  -OutFile "sample.sarif.json"
```

Use `format = "pdf"` with `-OutFile "sample.pdf"` for PDF export or
`format = "json"` for JSON export.

## Benchmark APK Sources

Prepare local folders containing compiled APKs:

```text
evaluation-apks/
  DroidBench/
  Ghera/
```

DroidBench is a micro-benchmark focused mainly on taint/data-flow behavior.
Ghera supplies Android vulnerability pairs and is more suitable for selected
platform misuse cases. Neither dataset substitutes for a manually annotated
set of current real-world applications.

Run MobileSec on both folders and execute each report format:

```powershell
node scripts/run-benchmark-evaluation.js `
  --droidbench "C:\path\to\evaluation-apks\DroidBench" `
  --ghera "C:\path\to\evaluation-apks\Ghera" `
  --api "http://localhost:5000" `
  --reportgen "http://localhost:3005" `
  --concurrency 1
```

For a balanced smoke test that does not overwrite the main experiment tables:

```powershell
node scripts/run-benchmark-evaluation.js `
  --droidbench "C:\path\to\evaluation-apks\DroidBench" `
  --ghera "C:\path\to\evaluation-apks\Ghera" `
  --api "http://localhost:5000" `
  --reportgen "http://localhost:3005" `
  --limit-per-dataset 5 `
  --concurrency 1 `
  --output-dir "backend\ml-model\experiments\smoke_real_10"
```

Run a throughput comparison under the same hardware and container limits:

```powershell
node scripts/run-benchmark-evaluation.js `
  --droidbench "C:\path\to\evaluation-apks\DroidBench" `
  --ghera "C:\path\to\evaluation-apks\Ghera" `
  --api "http://localhost:5000" `
  --reportgen "http://localhost:3005" `
  --concurrency 4
```

Outputs are in `backend/ml-model/experiments/`:

- `benchmark_scan_details.csv`
- `ground_truth.csv`
- `runtime_results.csv`

`runtime_results.csv` records CPU, RAM, requested concurrency, throughput,
generated export bytes, and measured PDF/JSON/SARIF success. Values are
measured by invoking ReportGen; they are not inferred from scanner output.

## Ground Truth And Category Metrics

Before publication, review `ground_truth.csv`. Fill the `category` column with
`secrets`, `crypto`, or `network` for manually verified benchmark findings.
The paper table API then calculates TP, FP, FN, precision, recall, and F1 for
each populated category. Historical MongoDB scan records remain coverage data
only because they have no manual ground truth.

## External Tools

Run external tools on exactly the same APK folder set. Import measured rows:

```powershell
node scripts/automate-paper-evaluation.js `
  --no-scan `
  --external-tool-csv "C:\path\to\external-tool-summary.csv"
```

The supported comparison rows are `MobSF`, `APKDeepLens`, `BeVigil`, and
`Yaazhini/Vooki`. When a tool cannot be run locally under comparable
conditions, leave its metrics empty and give the reason in the manuscript; do
not manufacture a value.

## FixSuggest Review

Create actual expert annotations from the template:

```powershell
Copy-Item backend\ml-model\experiments\fixsuggest_expert_review_template.csv `
  backend\ml-model\experiments\fixsuggest_expert_review.csv
node scripts/evaluate-fixsuggest-review.js
```

The output `fixsuggest_evaluation.json` reports only manually reviewed
acceptability and correctness rates.

## Security Score Validation

Convert each APK Scanner score to risk using `mobile_risk_score = 100 - score`,
then add independent expert and CVSS assessments:

```powershell
Copy-Item backend\ml-model\experiments\security_score_expert_review_template.csv `
  backend\ml-model\experiments\security_score_expert_review.csv
node scripts/evaluate-security-score-review.js
```

The output provides Pearson and Spearman correlations only after at least two
real reviewed rows exist. The template row is illustrative and is not a result.

## Generate Paper Values

```powershell
node scripts/automate-paper-evaluation.js --validate-only
```

In the UI, open the dashboard and use `Generate Values` in the paper
evaluation section. Unmeasured inputs are rendered as `N/A` and warnings.
