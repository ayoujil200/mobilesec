# MobSF Static Dataset Automation

This project can build a training-ready `fix_category` dataset from APK/AAB files using MobSF static analysis.

## Prerequisites

- A MobSF instance. By default the wrapper targets `https://mobsf.live`.
- A MobSF REST API key from the MobSF `/api_docs` page.
- Node.js available as `node`.

Optional local MobSF container, if the hosted service blocks automation or you do not want to upload APKs to a public service:

```powershell
docker run -d --name mobsf -p 8005:8000 opensecurity/mobile-security-framework-mobsf:latest
```

Port `8005` is used on the host because this project already maps FixSuggest to `8000`. Run the wrapper with `-MobSFUrl "http://localhost:8005"` when using this local container.

## Build Dataset

From the repository root:

```powershell
$env:MOBSF_API_KEY = "<your-mobsf-api-key>"
.\scripts\run-mobsf-static-dataset.ps1 `
  -ApkDir "backend\ml-model\experiments\controlled_apktool_dataset_v2\apks" `
  -MobSFUrl "https://mobsf.live" `
  -Resume
```

Outputs:

- `backend/ml-model/data/mobsf_static_dataset.csv` - training-ready rows with `fix_category`.
- `backend/ml-model/data/mobsf_reports/*.json` - raw MobSF JSON reports for audit/reprocessing.

## Train Immediately

```powershell
.\scripts\run-mobsf-static-dataset.ps1 `
  -ApkDir "path\to\apks" `
  -ApiKey "<your-mobsf-api-key>" `
  -Train `
  -Resume
```

The `-Train` switch calls the existing LightGBM trainer with the generated CSV and writes model artifacts under `backend/ml-model/models/`.

## Labeling Logic

The script maps MobSF static findings into the existing ML schema:

- Crypto findings: `FIX_WEAK_CIPHER`, `FIX_WEAK_HASH`, `FIX_INSECURE_RANDOM`, `FIX_WEAK_RSA_KEY`, `FIX_CRYPTO_GENERAL`.
- Secret findings: `FIX_EXPOSED_API_KEY`, `FIX_HARDCODED_PASSWORD`, `FIX_EXPOSED_SECRET`.
- Network findings: `FIX_INSECURE_HTTP`, `FIX_CERTIFICATE_ISSUE`.
- Clean apps: `NO_CRITICAL_ISSUES`.

Each row includes `label_source=mobsf_static_rules`, `label_confidence`, `label_review_status`, `label_evidence`, and `candidate_fix_categories` so low-margin labels can be reviewed before model training.

## Useful Options

```powershell
.\scripts\run-mobsf-static-dataset.ps1 -ApkDir "path\to\apks" -Limit 20
.\scripts\run-mobsf-static-dataset.ps1 -ApkDir "path\to\apks" -Force
.\scripts\run-mobsf-static-dataset.ps1 -ApkDir "path\to\apks" -StartMobSF
```

Use `-Resume` for long runs. Existing JSON reports are reused and the CSV is regenerated from saved reports.
