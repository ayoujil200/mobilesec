#!/usr/bin/env python3
"""
Build a MobileSec training dataset from MobSF static analysis reports.

Workflow:
1. Find APK/AAB files in an input directory.
2. Upload each file to MobSF.
3. Trigger static analysis.
4. Download the JSON report.
5. Convert MobSF findings into the existing ML feature schema and fix_category.

The script is intentionally dependency-free so it can run from the repository
root with a stock Python installation.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


ALLOWED_EXTENSIONS = {".apk", ".aab"}

FEATURE_COLUMNS = [
    "crypto_total_vulns",
    "crypto_high",
    "crypto_medium",
    "crypto_low",
    "crypto_info",
    "crypto_weak_cipher",
    "crypto_weak_hash",
    "crypto_insecure_random",
    "crypto_weak_rsa",
    "crypto_unique_cwes",
    "secrets_count",
    "secrets_api_keys",
    "secrets_passwords",
    "secrets_tokens",
    "secrets_aws_keys",
    "secrets_other",
    "secrets_unique_types",
    "network_findings",
    "network_endpoints",
    "network_http_issues",
    "network_cert_issues",
    "network_domain_issues",
    "total_vulnerabilities",
    "severity_score",
]

OUTPUT_COLUMNS = [
    "scan_id",
    *FEATURE_COLUMNS[:10],
    "crypto_cwe_codes",
    *FEATURE_COLUMNS[10:],
    "fix_category",
    "has_fix_suggestion",
    "label_source",
    "label_confidence",
    "label_review_status",
    "label_evidence",
    "candidate_fix_categories",
    "sample_id",
    "project_name",
    "apk_path",
    "mobsf_hash",
    "mobsf_app_name",
    "mobsf_package_name",
    "mobsf_security_score",
    "mobsf_report_path",
]

CATEGORY_PRIORITY = {
    "FIX_HARDCODED_PASSWORD": 100,
    "FIX_EXPOSED_API_KEY": 100,
    "FIX_EXPOSED_SECRET": 95,
    "FIX_CERTIFICATE_ISSUE": 95,
    "FIX_WEAK_CIPHER": 90,
    "FIX_WEAK_HASH": 80,
    "FIX_INSECURE_RANDOM": 75,
    "FIX_WEAK_RSA_KEY": 75,
    "FIX_INSECURE_HTTP": 70,
    "FIX_CRYPTO_MEDIUM": 50,
    "FIX_CRYPTO_GENERAL": 40,
    "NO_CRITICAL_ISSUES": 0,
}
SEVERITY_WEIGHT
 = {
    "critical": 4.0,
    "high": 3.0,
    "warning": 2.0,
    "medium": 2.0,
    "low": 1.0,
    "info": 0.25,
    "secure": 0.0,
    "good": 0.0,
}


@dataclass
class Finding:
    category: str
    source: str
    severity: str
    reason: str
    cwe: Optional[str] = None
    file: Optional[str] = None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run MobSF static scans and build a MobileSec ML dataset CSV."
    )
    parser.add_argument("apk_dir", help="Directory containing APK/AAB files.")
    parser.add_argument(
        "--mobsf-url",
        default=os.getenv("MOBSF_URL", "http://localhost:8005"),
        help="MobSF base URL. Default: MOBSF_URL or http://localhost:8005",
    )
    parser.add_argument(
        "--api-key",
        default=os.getenv("MOBSF_API_KEY", ""),
        help="MobSF REST API key. Default: MOBSF_API_KEY.",
    )
    parser.add_argument(
        "--output",
        default="backend/ml-model/data/mobsf_static_dataset.csv",
        help="Training CSV output path.",
    )
    parser.add_argument(
        "--reports-dir",
        default="backend/ml-model/data/mobsf_reports",
        help="Directory for raw MobSF JSON reports and progress state.",
    )
    parser.add_argument("--limit", type=int, default=None, help="Maximum files to process.")
    parser.add_argument("--resume", action="store_true", help="Reuse existing report JSON files.")
    parser.add_argument("--force", action="store_true", help="Rescan even when a report exists.")
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=900,
        help="Maximum time to wait for each MobSF report.",
    )
    parser.add_argument(
        "--poll-seconds",
        type=int,
        default=10,
        help="Delay between report polling attempts.",
    )
    parser.add_argument(
        "--train",
        action="store_true",
        help="After CSV generation, run python -m src.model.trainer in backend/ml-model.",
    )
    return parser.parse_args()


def find_apps(root: Path) -> List[Path]:
    if not root.exists() or not root.is_dir():
        raise SystemExit(f"APK directory not found: {root}")
    files = [
        path
        for path in root.rglob("*")
        if path.is_file() and path.suffix.lower() in ALLOWED_EXTENSIONS
    ]
    return sorted(files, key=lambda item: str(item).lower())


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class MobSFClient:
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key

    def upload(self, path: Path) -> Dict[str, Any]:
        boundary = f"----MobileSecMobSF{uuid.uuid4().hex}"
        file_bytes = path.read_bytes()
        filename = path.name.replace('"', '\\"')
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            "Content-Type: application/vnd.android.package-archive\r\n\r\n"
        ).encode("utf-8") + file_bytes + f"\r\n--{boundary}--\r\n".encode("utf-8")

        return self._request_json(
            "POST",
            "/api/v1/upload",
            body=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        )

    def scan(self, upload_result: Dict[str, Any]) -> Dict[str, Any]:
        payload = {
            "scan_type": upload_result.get("scan_type") or "apk",
            "file_name": upload_result.get("file_name") or upload_result.get("name"),
            "hash": upload_result.get("hash"),
        }
        return self._request_json("POST", "/api/v1/scan", data=payload)

    def report_json(self, app_hash: str) -> Dict[str, Any]:
        return self._request_json("POST", "/api/v1/report_json", data={"hash": app_hash})

    def _request_json(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict[str, Any]] = None,
        body: Optional[bytes] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        headers = dict(headers or {})
        headers["Authorization"] = self.api_key
        headers.setdefault("Accept", "application/json")

        if data is not None:
            body = urllib.parse.urlencode(data).encode("utf-8")
            headers["Content-Type"] = "application/x-www-form-urlencoded"

        request = urllib.request.Request(
            f"{self.base_url}{endpoint}",
            data=body,
            headers=headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                raw = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"MobSF {endpoint} failed with HTTP {exc.code}: {raw}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Cannot connect to MobSF at {self.base_url}: {exc}") from exc

        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"MobSF {endpoint} returned non-JSON response: {raw[:500]}") from exc


def iter_text_items(value: Any, path: str = "") -> Iterable[Tuple[str, Dict[str, Any]]]:
    if isinstance(value, dict):
        yield path, value
        for key, nested in value.items():
            yield from iter_text_items(nested, f"{path}.{key}" if path else str(key))
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            yield from iter_text_items(nested, f"{path}[{index}]")


def text_blob(item: Dict[str, Any]) -> str:
    parts = []
    for key, value in item.items():
        if isinstance(value, (str, int, float, bool)):
            parts.append(f"{key}: {value}")
    return " ".join(parts).upper()


def severity_of(item: Dict[str, Any]) -> str:
    for key in ("severity", "level", "status", "risk", "cvss"):
        value = item.get(key)
        if value:
            text = str(value).strip().lower()
            if text in SEVERITY_WEIGHT:
                return text
            if "high" in text:
                return "high"
            if "warn" in text or "medium" in text:
                return "warning"
            if "low" in text:
                return "low"
            if "info" in text:
                return "info"
    return "warning"


def cwe_of(item: Dict[str, Any]) -> Optional[str]:
    for key in ("cwe", "cwe_id", "masvs", "owasp"):
        value = item.get(key)
        if value and "CWE" in str(value).upper():
            return str(value)
    return None


def file_of(item: Dict[str, Any]) -> Optional[str]:
    for key in ("file", "file_path", "path", "component", "name"):
        value = item.get(key)
        if value:
            return str(value)
    return None


def categorize_item(path: str, item: Dict[str, Any]) -> Optional[Finding]:
    text = f"{path} {text_blob(item)}"

    category = None
    if any(token in text for token in ("API KEY", "API_KEY", "GOOGLE API", "FIREBASE", "AWS ACCESS", "AKIA")):
        category = "FIX_EXPOSED_API_KEY"
    elif any(token in text for token in ("PASSWORD", "PASSWD", "PWD", "HARDCODED CREDENTIAL")):
        category = "FIX_HARDCODED_PASSWORD"
    elif any(token in text for token in ("SECRET", "TOKEN", "PRIVATE KEY", "BEARER", "CREDENTIAL")):
        category = "FIX_EXPOSED_SECRET"
    elif any(token in text for token in ("SSL", "TLS", "CERTIFICATE", "TRUSTMANAGER", "HOSTNAME VERIFIER")):
        category = "FIX_CERTIFICATE_ISSUE"
    elif any(token in text for token in ("HTTP://", "CLEARTEXT", "INSECURE HTTP", "USES CLEARTEXT")):
        category = "FIX_INSECURE_HTTP"
    elif any(token in text for token in ("AES/ECB", " ECB", " DES ", "DES/", "DES-", "3DES", "DESEDE", "RC4", "BLOWFISH", "WEAK CIPHER")):
        category = "FIX_WEAK_CIPHER"
    elif any(token in text for token in ("MD5", "SHA-1", "SHA1", "WEAK HASH")):
        category = "FIX_WEAK_HASH"
    elif any(token in text for token in ("INSECURE RANDOM", "JAVA.UTIL.RANDOM", "CWE-330", "PSEUDO RANDOM")):
        category = "FIX_INSECURE_RANDOM"
    elif any(token in text for token in ("RSA", "WEAK KEY", "1024")):
        category = "FIX_WEAK_RSA_KEY"
    elif any(token in text for token in ("CRYPTO", "ENCRYPT", "DECRYPT", "CWE-327", "CWE-326")):
        category = "FIX_CRYPTO_GENERAL"

    if not category:
        return None

    return Finding(
        category=category,
        source=path or "mobsf_report",
        severity=severity_of(item),
        reason=str(item.get("title") or item.get("description") or item.get("name") or category),
        cwe=cwe_of(item),
        file=file_of(item),
    )


def extract_findings(report: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []
    for path, item in iter_text_items(report):
        finding = categorize_item(path, item)
        if finding:
            findings.append(finding)
    return findings


def score_label(findings: List[Finding]) -> Dict[str, Any]:
    candidates: Dict[str, Dict[str, float]] = {}
    for finding in findings:
        priority = CATEGORY_PRIORITY.get(finding.category, 0)
        weight = SEVERITY_WEIGHT.get(finding.severity.lower(), 1.0)
        candidates.setdefault(finding.category, {"count": 0, "score": 0.0})
        candidates[finding.category]["count"] += 1
        candidates[finding.category]["score"] += priority * max(weight, 0.25)

    if not candidates:
        return {
            "fix_category": "NO_CRITICAL_ISSUES",
            "confidence": 1.0,
            "review_status": "accepted",
            "candidate_fix_categories": {"NO_CRITICAL_ISSUES": {"count": 1, "score": 0}},
        }

    ranked = sorted(
        candidates.items(),
        key=lambda item: (item[1]["score"], CATEGORY_PRIORITY.get(item[0], 0), item[1]["count"]),
        reverse=True,
    )
    top_category, top = ranked[0]
    second_score = ranked[1][1]["score"] if len(ranked) > 1 else 0
    margin = top["score"] - second_score

    if len(ranked) == 1:
        confidence = 0.95
        review_status = "accepted"
    elif margin >= 50:
        confidence = 0.90
        review_status = "accepted"
    elif margin >= 20:
        confidence = 0.80
        review_status = "accepted"
    else:
        confidence = 0.60
        review_status = "needs_review"

    return {
        "fix_category": top_category,
        "confidence": confidence,
        "review_status": review_status,
        "candidate_fix_categories": {name: data for name, data in ranked},
    }


def build_row(app_path: Path, report_path: Path, report: Dict[str, Any], sample_index: int) -> Dict[str, Any]:
    findings = extract_findings(report)
    label = score_label(findings)
    categories = [finding.category for finding in findings]
    severities = [finding.severity.lower() for finding in findings]
    cwes = sorted({finding.cwe for finding in findings if finding.cwe})

    crypto_categories = {
        "FIX_WEAK_CIPHER",
        "FIX_WEAK_HASH",
        "FIX_INSECURE_RANDOM",
        "FIX_WEAK_RSA_KEY",
        "FIX_CRYPTO_GENERAL",
        "FIX_CRYPTO_MEDIUM",
    }
    secret_categories = {"FIX_EXPOSED_API_KEY", "FIX_HARDCODED_PASSWORD", "FIX_EXPOSED_SECRET"}
    network_categories = {"FIX_INSECURE_HTTP", "FIX_CERTIFICATE_ISSUE"}

    crypto_findings = [finding for finding in findings if finding.category in crypto_categories]
    secret_findings = [finding for finding in findings if finding.category in secret_categories]
    network_findings = [finding for finding in findings if finding.category in network_categories]

    high = sum(1 for severity in severities if severity in {"critical", "high"})
    medium = sum(1 for severity in severities if severity in {"warning", "medium"})
    low = sum(1 for severity in severities if severity == "low")
    info = sum(1 for severity in severities if severity == "info")
    severity_score = sum(SEVERITY_WEIGHT.get(severity, 1.0) for severity in severities)

    package_name = report.get("package_name") or report.get("appsec", {}).get("package_name") or ""
    app_name = report.get("app_name") or report.get("file_name") or app_path.stem
    mobsf_hash = report.get("md5") or report.get("hash") or report.get("app_hash") or sha256_file(app_path)
    selected_evidence = [
        {
            "source": finding.source,
            "reason": finding.reason,
            "severity": finding.severity,
            "file": finding.file,
            "cwe": finding.cwe,
        }
        for finding in findings
        if finding.category == label["fix_category"]
    ][:5]

    row = {
        "scan_id": f"mobsf-{mobsf_hash}",
        "crypto_total_vulns": len(crypto_findings),
        "crypto_high": sum(1 for finding in crypto_findings if finding.severity.lower() in {"critical", "high"}),
        "crypto_medium": sum(1 for finding in crypto_findings if finding.severity.lower() in {"warning", "medium"}),
        "crypto_low": sum(1 for finding in crypto_findings if finding.severity.lower() == "low"),
        "crypto_info": sum(1 for finding in crypto_findings if finding.severity.lower() == "info"),
        "crypto_weak_cipher": categories.count("FIX_WEAK_CIPHER"),
        "crypto_weak_hash": categories.count("FIX_WEAK_HASH"),
        "crypto_insecure_random": categories.count("FIX_INSECURE_RANDOM"),
        "crypto_weak_rsa": categories.count("FIX_WEAK_RSA_KEY"),
        "crypto_cwe_codes": ",".join(cwes),
        "crypto_unique_cwes": len(cwes),
        "secrets_count": len(secret_findings),
        "secrets_api_keys": categories.count("FIX_EXPOSED_API_KEY"),
        "secrets_passwords": categories.count("FIX_HARDCODED_PASSWORD"),
        "secrets_tokens": sum(1 for finding in secret_findings if "TOKEN" in finding.reason.upper()),
        "secrets_aws_keys": sum(1 for finding in secret_findings if "AWS" in finding.reason.upper()),
        "secrets_other": max(len(secret_findings) - categories.count("FIX_EXPOSED_API_KEY") - categories.count("FIX_HARDCODED_PASSWORD"), 0),
        "secrets_unique_types": len(set(finding.category for finding in secret_findings)),
        "network_findings": len(network_findings),
        "network_endpoints": count_network_endpoints(report),
        "network_http_issues": categories.count("FIX_INSECURE_HTTP"),
        "network_cert_issues": categories.count("FIX_CERTIFICATE_ISSUE"),
        "network_domain_issues": count_domain_findings(report),
        "total_vulnerabilities": len(findings),
        "severity_score": round(severity_score + high * 2 + medium + low * 0.5 + info * 0.1, 3),
        "fix_category": label["fix_category"],
        "has_fix_suggestion": False,
        "label_source": "mobsf_static_rules",
        "label_confidence": label["confidence"],
        "label_review_status": label["review_status"],
        "label_evidence": json.dumps(selected_evidence, ensure_ascii=True),
        "candidate_fix_categories": json.dumps(label["candidate_fix_categories"], ensure_ascii=True),
        "sample_id": f"mobsf-{sample_index:05d}",
        "project_name": app_path.stem,
        "apk_path": str(app_path),
        "mobsf_hash": mobsf_hash,
        "mobsf_app_name": app_name,
        "mobsf_package_name": package_name,
        "mobsf_security_score": report.get("security_score") or report.get("appsec", {}).get("security_score") or "",
        "mobsf_report_path": str(report_path),
    }
    return row


def count_network_endpoints(report: Dict[str, Any]) -> int:
    count = 0
    for key in ("urls", "domains", "emails"):
        value = report.get(key)
        if isinstance(value, list):
            count += len(value)
        elif isinstance(value, dict):
            count += len(value)
    return count


def count_domain_findings(report: Dict[str, Any]) -> int:
    count = 0
    for _, item in iter_text_items(report):
        text = text_blob(item)
        if any(token in text for token in ("DOMAIN", "URL", "IP ADDRESS", "ENDPOINT")):
            count += 1
    return count


def write_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=OUTPUT_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def wait_for_report(client: MobSFClient, app_hash: str, timeout_seconds: int, poll_seconds: int) -> Dict[str, Any]:
    deadline = time.time() + timeout_seconds
    last_error = None
    while time.time() < deadline:
        try:
            report = client.report_json(app_hash)
            if isinstance(report, dict) and len(report) > 2 and not report.get("error"):
                return report
            last_error = report
        except RuntimeError as exc:
            last_error = str(exc)
        time.sleep(poll_seconds)
    raise RuntimeError(f"Timed out waiting for MobSF report for {app_hash}. Last response: {last_error}")


def run_training(csv_path: Path) -> int:
    ml_dir = Path("backend/ml-model").resolve()
    resolved_csv = csv_path.resolve()
    original_cwd = Path.cwd()
    sys.path.insert(0, str(ml_dir))

    try:
        os.chdir(ml_dir)
        from src.model.trainer import train_model

        print(f"Training model from {resolved_csv}")
        train_model(str(resolved_csv))
        return 0
    finally:
        os.chdir(original_cwd)


def main() -> int:
    args = parse_args()
    if not args.api_key:
        print("MOBSF_API_KEY is required. Pass --api-key or set MOBSF_API_KEY.", file=sys.stderr)
        return 2

    apps = find_apps(Path(args.apk_dir).resolve())
    if args.limit:
        apps = apps[: args.limit]
    if not apps:
        print(f"No APK/AAB files found in {args.apk_dir}")
        return 0

    reports_dir = Path(args.reports_dir)
    reports_dir.mkdir(parents=True, exist_ok=True)
    client = MobSFClient(args.mobsf_url, args.api_key)
    rows: List[Dict[str, Any]] = []

    print(f"Found {len(apps)} APK/AAB file(s). MobSF: {args.mobsf_url}")
    for index, app_path in enumerate(apps, start=1):
        app_sha = sha256_file(app_path)
        report_path = reports_dir / f"{app_sha}.json"
        print(f"[{index}/{len(apps)}] {app_path.name}")

        if report_path.exists() and args.resume and not args.force:
            report = json.loads(report_path.read_text(encoding="utf-8"))
            print(f"  reused report {report_path}")
        else:
            upload_result = client.upload(app_path)
            app_hash = upload_result.get("hash")
            if not app_hash:
                raise RuntimeError(f"MobSF upload did not return hash for {app_path}: {upload_result}")
            print(f"  uploaded hash={app_hash}")
            client.scan(upload_result)
            print("  static scan started; waiting for JSON report")
            report = wait_for_report(client, app_hash, args.timeout_seconds, args.poll_seconds)
            report_path.write_text(json.dumps(report, indent=2, ensure_ascii=True), encoding="utf-8")

        row = build_row(app_path, report_path, report, index)
        rows.append(row)
        print(
            f"  fix_category={row['fix_category']} confidence={row['label_confidence']} "
            f"findings={row['total_vulnerabilities']}"
        )

        write_csv(Path(args.output), rows)

    output_path = Path(args.output)
    write_csv(output_path, rows)
    print(f"Wrote {len(rows)} row(s) to {output_path}")

    if args.train:
        return run_training(output_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
