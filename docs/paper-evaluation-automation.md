# Paper Evaluation Automation

This workflow generates the CSV files used by the frontend "Paper Evaluation
Tables" page without deleting existing experiment data. Before any generated
CSV is replaced, the automation copies the current files into:

```text
backend/ml-model/experiments/backups/<timestamp>/
```

## Validate Current State

From the repository root:

```powershell
node scripts/automate-paper-evaluation.js --validate-only
```

The script writes:

```text
backend/ml-model/experiments/paper_evaluation_status.json
```

Use this file to see which values are still missing or unsafe for final paper
tables.

## Generate MobileSec Benchmark Values

Run the same APK benchmark folders through MobileSec:

```powershell
node scripts/automate-paper-evaluation.js `
  --droidbench "C:\path\to\DroidBench apks" `
  --ghera "C:\path\to\Ghera apks" `
  --api "http://localhost:5000" `
  --resume
```

For a smoke test:

```powershell
node scripts/automate-paper-evaluation.js `
  --droidbench "C:\path\to\DroidBench apks" `
  --ghera "C:\path\to\Ghera apks" `
  --limit 10 `
  --resume
```

This refreshes:

- `backend/ml-model/experiments/benchmark_scan_details.csv`
- `backend/ml-model/experiments/ground_truth.csv`
- `backend/ml-model/experiments/runtime_results.csv`

The benchmark script derives default binary ground truth as follows:

- DroidBench APKs: expected vulnerable.
- Ghera APK names containing `-malicious`: expected vulnerable.
- Ghera APK names containing `-benign` or `-secure`: expected not vulnerable.

To apply this derivation to an existing `ground_truth.csv` without rerunning
scans:

```powershell
node scripts/automate-paper-evaluation.js --no-scan --derive-ground-truth
```

Report generation is asynchronous. To update `runtime_results.csv` from
MongoDB report records after ReportGen finishes:

```powershell
node scripts/automate-paper-evaluation.js --no-scan --sync-report-success
```

This sets `report_success=true` when a JSON report exists in MongoDB for the
scan ID, and sets `sarif_success=true` only when a SARIF report exists.

## Import External Tool Results

Run MobSF and Yaazhini/Vooki on the same APK set, then create a measured summary
CSV with this schema:

```csv
tool,number_of_apks_analyzed,benchmark_apks,real_world_apks,mean_scan_time_per_apk,detected_vulnerability_categories,hardcoded_secrets_detected,network_issues_detected,cryptographic_issues_detected,pdf_export,json_export,sarif_export,ci_cd_integration,ml_based_prioritization,ai_assisted_remediation,reproducible_docker_deployment
MobSF,283,"DroidBench, Ghera",0,12.40 s,5,120,44,31,Yes,Yes,No,Yes,No,No,Yes
Yaazhini/Vooki,283,"DroidBench, Ghera",0,18.70 s,4,95,30,22,Yes,Yes,No,No,No,No,No
```

Then import it:

```powershell
node scripts/automate-paper-evaluation.js `
  --no-scan `
  --external-tool-csv "C:\path\to\external-tool-summary.csv"
```

The imported file becomes:

```text
backend/ml-model/experiments/external_tool_results.csv
```

## Important Limits

The automation does not fabricate scientific values. It can only fill values
that were actually measured or imported from measured tool outputs.

If `paper_evaluation_status.json` reports these issues, fix the underlying
pipeline before using the table in a journal article:

- `Report-generation success is measured but currently 0%`
- `SARIF export success is measured but currently 0%`
- `external_tool_results.csv` missing MobSF or Yaazhini/Vooki rows
- `ground_truth.csv` rows with no expected label

After the script finishes, open the frontend and click **Generate Values**.
