"""
Create a balanced development dataset for the LightGBM fix-category model.

This is useful when MongoDB has too few scans to train a classifier. It creates
synthetic, rule-shaped examples for every supported fix category. Replace this
with real extracted scan data once you have enough completed scans.
"""

import argparse
import os
from pathlib import Path
from typing import Dict, List

import numpy as np
import pandas as pd

from src.model.model_config import FEATURE_COLUMNS, TARGET_COLUMN


FIX_CATEGORIES = [
    "FIX_WEAK_CIPHER",
    "FIX_WEAK_HASH",
    "FIX_INSECURE_RANDOM",
    "FIX_WEAK_RSA_KEY",
    "FIX_EXPOSED_API_KEY",
    "FIX_HARDCODED_PASSWORD",
    "FIX_EXPOSED_SECRET",
    "FIX_INSECURE_HTTP",
    "FIX_CERTIFICATE_ISSUE",
    "FIX_CRYPTO_MEDIUM",
    "FIX_CRYPTO_GENERAL",
    "NO_CRITICAL_ISSUES",
    "NO_SUGGESTION",
]


def _empty_row() -> Dict[str, float]:
    return {feature: 0 for feature in FEATURE_COLUMNS}


def _apply_profile(row: Dict[str, float], category: str, rng: np.random.Generator) -> None:
    if category == "FIX_WEAK_CIPHER":
        row.update(crypto_total_vulns=rng.integers(2, 8), crypto_high=rng.integers(1, 4), crypto_weak_cipher=rng.integers(1, 4), crypto_unique_cwes=rng.integers(1, 3))
    elif category == "FIX_WEAK_HASH":
        row.update(crypto_total_vulns=rng.integers(2, 7), crypto_high=rng.integers(1, 3), crypto_weak_hash=rng.integers(1, 4), crypto_unique_cwes=rng.integers(1, 3))
    elif category == "FIX_INSECURE_RANDOM":
        row.update(crypto_total_vulns=rng.integers(1, 5), crypto_high=rng.integers(1, 3), crypto_insecure_random=rng.integers(1, 3), crypto_unique_cwes=1)
    elif category == "FIX_WEAK_RSA_KEY":
        row.update(crypto_total_vulns=rng.integers(1, 5), crypto_high=rng.integers(1, 3), crypto_weak_rsa=rng.integers(1, 3), crypto_unique_cwes=1)
    elif category == "FIX_EXPOSED_API_KEY":
        row.update(secrets_count=rng.integers(1, 6), secrets_api_keys=rng.integers(1, 5), secrets_unique_types=rng.integers(1, 3))
    elif category == "FIX_HARDCODED_PASSWORD":
        row.update(secrets_count=rng.integers(1, 5), secrets_passwords=rng.integers(1, 4), secrets_unique_types=rng.integers(1, 3))
    elif category == "FIX_EXPOSED_SECRET":
        row.update(secrets_count=rng.integers(1, 7), secrets_tokens=rng.integers(0, 3), secrets_aws_keys=rng.integers(0, 2), secrets_other=rng.integers(1, 4), secrets_unique_types=rng.integers(1, 4))
    elif category == "FIX_INSECURE_HTTP":
        row.update(network_findings=rng.integers(1, 7), network_endpoints=rng.integers(2, 12), network_http_issues=rng.integers(1, 5))
    elif category == "FIX_CERTIFICATE_ISSUE":
        row.update(network_findings=rng.integers(1, 6), network_endpoints=rng.integers(1, 8), network_cert_issues=rng.integers(1, 4))
    elif category == "FIX_CRYPTO_MEDIUM":
        row.update(crypto_total_vulns=rng.integers(1, 6), crypto_medium=rng.integers(1, 5), crypto_low=rng.integers(0, 3), crypto_unique_cwes=rng.integers(1, 4))
    elif category == "FIX_CRYPTO_GENERAL":
        row.update(crypto_total_vulns=rng.integers(1, 8), crypto_low=rng.integers(1, 4), crypto_info=rng.integers(0, 3), crypto_unique_cwes=rng.integers(1, 5))
    elif category == "NO_SUGGESTION":
        row.update(crypto_info=rng.integers(0, 3), network_endpoints=rng.integers(0, 5))


def _finalize_row(row: Dict[str, float]) -> None:
    row["total_vulnerabilities"] = (
        row["crypto_total_vulns"] + row["secrets_count"] + row["network_findings"]
    )
    row["severity_score"] = (
        row["crypto_high"] * 3
        + row["crypto_medium"] * 2
        + row["crypto_low"]
        + row["secrets_count"] * 2.5
        + row["network_findings"] * 1.5
    )


def build_dataset(samples_per_class: int, seed: int) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    rows: List[Dict[str, float]] = []

    for category in FIX_CATEGORIES:
        for _ in range(samples_per_class):
            row = _empty_row()
            _apply_profile(row, category, rng)
            _finalize_row(row)
            row[TARGET_COLUMN] = category
            rows.append(row)

    df = pd.DataFrame(rows)
    return df.sample(frac=1, random_state=seed).reset_index(drop=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default="data/security_scan_dataset.csv")
    parser.add_argument("--samples-per-class", type=int, default=30)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    if args.samples_per_class < 3:
        raise ValueError("--samples-per-class must be at least 3")

    df = build_dataset(args.samples_per_class, args.seed)
    output = Path(args.output)
    os.makedirs(output.parent, exist_ok=True)
    df.to_csv(output, index=False)

    print(f"Wrote {len(df)} rows to {output}")
    print(df[TARGET_COLUMN].value_counts().sort_index().to_string())


if __name__ == "__main__":
    main()
