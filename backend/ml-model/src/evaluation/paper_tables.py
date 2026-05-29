"""
Generate paper-ready evaluation tables from MobileSec runtime artifacts.

The report intentionally avoids fabricating metrics. Values that require
external tools or manually curated ground truth are returned as null with a
clear note.
"""

import json
import math
from pathlib import Path
from statistics import mean
from typing import Any, Dict, List, Optional

import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score, top_k_accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

from src.model.model_config import FEATURE_COLUMNS, LIGHTGBM_PARAMS, METRICS_PATH, TARGET_COLUMN, TRAINING_CONFIG
from src.utils.mongodb_client import mongodb_client


DATASET_PATH = Path("data/security_scan_dataset.csv")
EXTERNAL_TOOL_RESULTS_PATH = Path("experiments/external_tool_results.csv")
GROUND_TRUTH_PATH = Path("experiments/ground_truth.csv")
RUNTIME_RESULTS_PATH = Path("experiments/runtime_results.csv")
BENCHMARK_SCAN_DETAILS_PATH = Path("experiments/benchmark_scan_details.csv")
CHECKLIST_STATUS_PATH = Path("experiments/checklist_review_status.json")

HISTORICAL_DATASET = "Historical MobileSec records (no ground truth)"
DATASETS = ["DroidBench", "Ghera", HISTORICAL_DATASET]
COMPARISON_TOOLS = ["MobileSec", "MobSF", "APKDeepLens", "BeVigil", "Yaazhini/Vooki"]

CATEGORY_PRIORITY = {
    "NO_CRITICAL_ISSUES": 0,
    "NO_SUGGESTION": 1,
    "GENERAL": 1,
    "FIX_CRYPTO_MEDIUM": 2,
    "FIX_INSECURE_RANDOM": 2,
    "FIX_CRYPTO_GENERAL": 2,
    "FIX_WEAK_CIPHER": 3,
    "FIX_WEAK_HASH": 3,
    "FIX_WEAK_RSA_KEY": 3,
    "FIX_INSECURE_HTTP": 3,
    "FIX_CERTIFICATE_ISSUE": 3,
    "FIX_EXPOSED_SECRET": 3,
    "FIX_EXPOSED_API_KEY": 4,
    "FIX_HARDCODED_PASSWORD": 4,
}


def _fmt(value: Any, precision: int = 4) -> str:
    if value is None:
        return "N/A"
    if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
        return "N/A"
    if isinstance(value, float):
        return f"{value:.{precision}f}"
    return str(value)


def _fmt_percent(value: Any, precision: int = 1) -> str:
    if value is None:
        return "N/A"
    if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
        return "N/A"
    return f"{float(value) * 100:.{precision}f}\\%"


def _safe_ratio(numerator: Optional[float], denominator: Optional[float]) -> Optional[float]:
    if numerator is None or denominator in (None, 0):
        return None
    return numerator / denominator


def _first_present(row: Dict, names: List[str]) -> Any:
    for name in names:
        if name in row and pd.notnull(row[name]):
            return row[name]
    return None


def _latex_cell(value: Any) -> str:
    text = _fmt(value)
    replacements = {
        "\\": r"\textbackslash{}",
        "&": r"\&",
        "%": r"\%",
        "$": r"\$",
        "#": r"\#",
        "_": r"\_",
        "{": r"\{",
        "}": r"\}",
        "~": r"\textasciitilde{}",
        "^": r"\textasciicircum{}",
    }
    return "".join(replacements.get(char, char) for char in text)


def _count_crypto(doc: Optional[Dict]) -> int:
    if not doc:
        return 0
    if isinstance(doc.get("total_vulnerabilities"), int):
        return doc["total_vulnerabilities"]
    return len(doc.get("vulnerabilities", []) or [])


def _count_secrets(doc: Optional[Dict]) -> int:
    if not doc:
        return 0
    if isinstance(doc.get("secrets_count"), int):
        return doc["secrets_count"]
    return len(doc.get("secrets", []) or [])


def _count_network(doc: Optional[Dict]) -> int:
    if not doc:
        return 0
    if isinstance(doc.get("findings_count"), int):
        return doc["findings_count"]
    analysis = doc.get("analysis", {}) or {}
    return len(analysis.get("security_issues", []) or [])


def _count_suggestions(doc: Optional[Dict]) -> int:
    if not doc:
        return 0
    if isinstance(doc.get("suggestions_count"), int):
        return doc["suggestions_count"]
    return len(doc.get("suggestions", []) or [])


def _load_metrics() -> Dict:
    if not Path(METRICS_PATH).exists():
        return {}
    with open(METRICS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def _checklist_review_table(warnings: List[str]) -> List[Dict]:
    if not CHECKLIST_STATUS_PATH.exists():
        warnings.append("Checklist review status file is not available.")
        return []

    try:
        with CHECKLIST_STATUS_PATH.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        rows = payload.get("rows", []) if isinstance(payload, dict) else payload
        if not isinstance(rows, list):
            warnings.append("Checklist review status has an invalid rows payload.")
            return []
        return rows
    except (OSError, ValueError) as exc:
        warnings.append(f"Unable to load checklist review status: {exc}")
        return []


def _training_dataset_path(metrics: Dict) -> Path:
    data_path = metrics.get("dataset_info", {}).get("data_path") if metrics else None
    return Path(data_path) if data_path else DATASET_PATH


def _load_training_df(warnings: List[str], metrics: Dict) -> Optional[pd.DataFrame]:
    dataset_path = _training_dataset_path(metrics)
    if not dataset_path.exists():
        warnings.append(f"Training CSV not found at {dataset_path}.")
        return None

    df = pd.read_csv(dataset_path)
    missing = set(FEATURE_COLUMNS + [TARGET_COLUMN]) - set(df.columns)
    if missing:
        warnings.append(f"Training CSV is missing required columns: {sorted(missing)}")
        return None

    counts = df[TARGET_COLUMN].value_counts()
    if len(counts) < 2 or len(df) < 20 or counts.min() < 3:
        warnings.append(
            f"Training CSV is too small for full automated evaluation. rows={len(df)}, "
            f"class_counts={counts.to_dict()}"
        )
        return None

    if "label_confidence" in df.columns:
        confidence = pd.to_numeric(df["label_confidence"], errors="coerce").fillna(0.0)
        accepted_status = (
            df["label_review_status"].astype(str).str.lower().isin(["accepted", "approved", "human_approved"])
            if "label_review_status" in df.columns
            else pd.Series(True, index=df.index)
        )
        quality_mask = (confidence >= 0.75) & accepted_status
        filtered = df[quality_mask].copy()
        if len(filtered) >= 20 and filtered[TARGET_COLUMN].nunique() >= 2:
            df = filtered

    return df


def _rule_based_label(row: pd.Series) -> str:
    if row["crypto_high"] > 0:
        if row["crypto_weak_cipher"] > 0:
            return "FIX_WEAK_CIPHER"
        if row["crypto_weak_hash"] > 0:
            return "FIX_WEAK_HASH"
        if row["crypto_insecure_random"] > 0:
            return "FIX_INSECURE_RANDOM"
        if row["crypto_weak_rsa"] > 0:
            return "FIX_WEAK_RSA_KEY"
        return "FIX_CRYPTO_GENERAL"

    if row["secrets_count"] > 0:
        if row["secrets_api_keys"] > 0:
            return "FIX_EXPOSED_API_KEY"
        if row["secrets_passwords"] > 0:
            return "FIX_HARDCODED_PASSWORD"
        return "FIX_EXPOSED_SECRET"

    if row["network_http_issues"] > 0:
        return "FIX_INSECURE_HTTP"

    if row["network_cert_issues"] > 0:
        return "FIX_CERTIFICATE_ISSUE"

    if row["crypto_medium"] > 0:
        return "FIX_CRYPTO_MEDIUM"

    if row["total_vulnerabilities"] == 0:
        return "NO_CRITICAL_ISSUES"

    return "NO_SUGGESTION"


def _classification_row(model: str, y_true: np.ndarray, y_pred: np.ndarray,
                        y_proba: Optional[np.ndarray], classes: np.ndarray) -> Dict:
    top3 = None
    if y_proba is not None and len(classes) >= 3:
        labels = np.arange(len(classes))
        top3 = top_k_accuracy_score(y_true, y_proba, k=3, labels=labels)

    auc = None
    if y_proba is not None:
        try:
            auc = (
                roc_auc_score(y_true, y_proba, average="macro", multi_class="ovr")
                if len(classes) > 2
                else roc_auc_score(y_true, y_proba[:, 1])
            )
        except ValueError:
            pass

    return {
        "model": model,
        "accuracy": accuracy_score(y_true, y_pred),
        "macro_precision": precision_score(y_true, y_pred, average="macro", zero_division=0),
        "macro_recall": recall_score(y_true, y_pred, average="macro", zero_division=0),
        "macro_f1": f1_score(y_true, y_pred, average="macro", zero_division=0),
        "weighted_f1": f1_score(y_true, y_pred, average="weighted", zero_division=0),
        "top_3_accuracy": top3,
        "auc": auc,
        "classes": len(classes),
    }


def _confusion_matrix_payload(model: str, y_true: np.ndarray, y_pred: np.ndarray,
                              classes: np.ndarray) -> Dict:
    labels = np.arange(len(classes))
    matrix = confusion_matrix(y_true, y_pred, labels=labels)
    return {
        "model": model,
        "labels": [str(label) for label in classes.tolist()],
        "matrix": matrix.astype(int).tolist(),
    }


def _evaluate_models_from_csv(df: pd.DataFrame, warnings: List[str]) -> List[Dict]:
    evaluation = _evaluate_model_artifacts_from_csv(df, warnings)
    return evaluation["rows"]


def _evaluate_confusion_matrices_from_csv(df: pd.DataFrame, warnings: List[str]) -> List[Dict]:
    evaluation = _evaluate_model_artifacts_from_csv(df, warnings)
    return evaluation["confusion_matrices"]


def _evaluate_model_artifacts_from_csv(df: pd.DataFrame, warnings: List[str]) -> Dict:
    X = df[FEATURE_COLUMNS].astype(float).values
    labels = df[TARGET_COLUMN].astype(str).values

    encoder = LabelEncoder()
    y = encoder.fit_transform(labels)

    X_train, X_test, y_train, y_test, idx_train, idx_test = train_test_split(
        X,
        y,
        np.arange(len(df)),
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    rows: List[Dict] = []
    matrices: List[Dict] = []

    rule_predictions = [_rule_based_label(df.iloc[idx]) for idx in idx_test]
    known_classes = set(encoder.classes_)
    rule_predictions = [pred if pred in known_classes else encoder.classes_[0] for pred in rule_predictions]
    rule_y_pred = encoder.transform(rule_predictions)
    rows.append(_classification_row("Rule-based baseline", y_test, rule_y_pred, None, encoder.classes_))
    matrices.append(_confusion_matrix_payload("Rule-based baseline", y_test, rule_y_pred, encoder.classes_))

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    logistic = LogisticRegression(max_iter=2000, class_weight="balanced", random_state=42)
    logistic.fit(X_train_scaled, y_train)
    logistic_pred = logistic.predict(X_test_scaled)
    rows.append(_classification_row(
        "Logistic Regression",
        y_test,
        logistic_pred,
        logistic.predict_proba(X_test_scaled),
        encoder.classes_,
    ))
    matrices.append(_confusion_matrix_payload("Logistic Regression", y_test, logistic_pred, encoder.classes_))

    forest = RandomForestClassifier(n_estimators=200, random_state=42, class_weight="balanced")
    forest.fit(X_train, y_train)
    forest_pred = forest.predict(X_test)
    rows.append(_classification_row(
        "Random Forest",
        y_test,
        forest_pred,
        forest.predict_proba(X_test),
        encoder.classes_,
    ))
    matrices.append(_confusion_matrix_payload("Random Forest", y_test, forest_pred, encoder.classes_))

    params = LIGHTGBM_PARAMS.copy()
    params["num_class"] = len(encoder.classes_)
    params["num_threads"] = 1
    train_data = lgb.Dataset(X_train_scaled, label=y_train)
    model = lgb.train(params, train_data, num_boost_round=200)
    lightgbm_proba = model.predict(X_test_scaled)
    lightgbm_pred = np.argmax(lightgbm_proba, axis=1)
    rows.append(_classification_row(
        "LightGBM",
        y_test,
        lightgbm_pred,
        lightgbm_proba,
        encoder.classes_,
    ))
    matrices.append(_confusion_matrix_payload("LightGBM", y_test, lightgbm_pred, encoder.classes_))

    if len(df) < 100:
        warnings.append("ML comparison is based on fewer than 100 rows; report it as preliminary.")

    return {
        "rows": rows,
        "confusion_matrices": matrices,
    }


def _rank(values: np.ndarray) -> np.ndarray:
    order = np.argsort(-values)
    ranks = np.empty_like(order)
    ranks[order] = np.arange(len(values))
    return ranks


def _kendall_tau(rank_a: np.ndarray, rank_b: np.ndarray) -> Optional[float]:
    n = len(rank_a)
    if n < 2:
        return None

    concordant = 0
    discordant = 0
    for i in range(n - 1):
        for j in range(i + 1, n):
            sign_a = np.sign(rank_a[i] - rank_a[j])
            sign_b = np.sign(rank_b[i] - rank_b[j])
            product = sign_a * sign_b
            if product > 0:
                concordant += 1
            elif product < 0:
                discordant += 1

    denom = n * (n - 1) / 2
    return (concordant - discordant) / denom if denom else None


def _score_with_scheme(df: pd.DataFrame, scheme: str) -> np.ndarray:
    if scheme == "Expert-defined weights":
        return (
            3.0 * df["crypto_high"]
            + 2.0 * df["crypto_medium"]
            + 1.0 * df["crypto_low"]
            + 2.5 * df["secrets_count"]
            + 1.5 * df["network_findings"]
        ).values
    if scheme == "Equal weights":
        return (
            df["crypto_high"]
            + df["crypto_medium"]
            + df["crypto_low"]
            + df["secrets_count"]
            + df["network_findings"]
        ).values
    if scheme == "CVSS-inspired weights":
        return (
            3.0 * df["crypto_high"]
            + 2.0 * df["crypto_medium"]
            + 1.0 * df["crypto_low"]
            + 3.0 * df["secrets_count"]
            + 2.0 * df["network_findings"]
        ).values
    if scheme == "Secrets-heavy weights":
        return (
            2.0 * df["crypto_high"]
            + 1.0 * df["crypto_medium"]
            + 0.5 * df["crypto_low"]
            + 4.0 * df["secrets_count"]
            + 1.0 * df["network_findings"]
        ).values
    raise ValueError(f"Unknown scheme: {scheme}")


def _weight_sensitivity(df: Optional[pd.DataFrame]) -> List[Dict]:
    if df is None:
        return []

    schemes = [
        "Expert-defined weights",
        "Equal weights",
        "CVSS-inspired weights",
        "Secrets-heavy weights",
    ]

    expert_score = _score_with_scheme(df, "Expert-defined weights")
    expert_rank = _rank(expert_score)
    expert_top = set(np.argsort(-expert_score)[: min(10, len(df))].tolist())

    rows = []
    for scheme in schemes:
        score = _score_with_scheme(df, scheme)
        rank = _rank(score)
        top = set(np.argsort(-score)[: min(10, len(df))].tolist())
        overlap_denominator = max(1, len(expert_top))
        rows.append({
            "weighting_scheme": scheme,
            "top_10_overlap": len(expert_top.intersection(top)) / overlap_denominator,
            "kendall_tau": _kendall_tau(expert_rank, rank),
            "macro_f1": None,
        })
    return rows


def _dataset_report(warnings: List[str], metrics: Dict) -> Dict:
    dataset_path = _training_dataset_path(metrics)
    report = {
        "path": str(dataset_path),
        "exists": dataset_path.exists(),
        "rows": 0,
        "classes": 0,
        "class_distribution": {},
        "feature_count": len(FEATURE_COLUMNS),
        "feature_names": FEATURE_COLUMNS,
        "base_hyperparameters": LIGHTGBM_PARAMS,
        "training_configuration": TRAINING_CONFIG,
        "selected_hyperparameters": metrics.get("train_metrics", {}).get("selected_params", {}) if metrics else {},
        "appears_bootstrap": False,
        "training_rows": metrics.get("dataset_info", {}).get("training_rows") if metrics else None,
        "training_classes": None,
        "training_class_distribution": {},
        "feature_collision_summary": metrics.get("dataset_info", {}).get("feature_collision_summary") if metrics else None,
    }

    if not dataset_path.exists():
        warnings.append(f"Training CSV not found at {dataset_path}.")
        return report

    df = pd.read_csv(dataset_path)
    report["rows"] = int(len(df))
    if TARGET_COLUMN in df.columns:
        counts = df[TARGET_COLUMN].value_counts().sort_index()
        report["class_distribution"] = {str(k): int(v) for k, v in counts.items()}
        report["classes"] = int(len(counts))
        report["appears_bootstrap"] = bool(len(counts) >= 2 and counts.nunique() == 1)
        if report["appears_bootstrap"]:
            warnings.append(
                "The current training CSV appears balanced/synthetic. Use it for pipeline validation, not final paper claims."
            )
        training_distribution = metrics.get("dataset_info", {}).get("training_class_distribution") if metrics else None
        if training_distribution:
            report["training_class_distribution"] = training_distribution
            report["training_classes"] = len(training_distribution)
    else:
        warnings.append("Training CSV is missing the fix_category target column.")

    return report


def _mongodb_report(warnings: List[str]) -> Dict:
    if not mongodb_client.is_connected() and not mongodb_client.connect():
        warnings.append("MongoDB is not reachable; scan-result tables are incomplete.")
        return {
            "total_scans": 0,
            "coverage": {},
            "scan_rows": [],
            "finding_totals": {},
        }

    scan_ids = mongodb_client.get_all_scan_ids()
    scan_rows = []

    for scan_id in scan_ids:
        combined = mongodb_client.get_combined_scan_data(scan_id) or {}
        crypto = combined.get("crypto")
        secrets = combined.get("secrets")
        network = combined.get("network")
        fixes = combined.get("fix_suggestions")

        crypto_count = _count_crypto(crypto)
        secret_count = _count_secrets(secrets)
        network_count = _count_network(network)

        scan_rows.append({
            "scan_id": scan_id,
            "has_crypto": crypto is not None,
            "has_secrets": secrets is not None,
            "has_network": network is not None,
            "has_fix_suggestions": fixes is not None,
            "crypto_findings": crypto_count,
            "secret_findings": secret_count,
            "network_findings": network_count,
            "fix_suggestions": _count_suggestions(fixes),
            "total_findings": crypto_count + secret_count + network_count,
        })

    total_scans = len(scan_rows)
    coverage = {
        "crypto_results": sum(1 for row in scan_rows if row["has_crypto"]),
        "secret_results": sum(1 for row in scan_rows if row["has_secrets"]),
        "network_results": sum(1 for row in scan_rows if row["has_network"]),
        "fix_suggestions": sum(1 for row in scan_rows if row["has_fix_suggestions"]),
    }

    if total_scans == 0:
        warnings.append("No scan IDs found in MongoDB. Run APK scans before generating final evaluation tables.")

    finding_totals = {
        "crypto_findings": sum(row["crypto_findings"] for row in scan_rows),
        "secret_findings": sum(row["secret_findings"] for row in scan_rows),
        "network_findings": sum(row["network_findings"] for row in scan_rows),
        "total_findings": sum(row["total_findings"] for row in scan_rows),
        "avg_findings_per_apk": mean([row["total_findings"] for row in scan_rows]) if scan_rows else None,
    }

    return {
        "total_scans": total_scans,
        "coverage": coverage,
        "scan_rows": scan_rows,
        "finding_totals": finding_totals,
    }


def _ml_results(df: Optional[pd.DataFrame], metrics: Dict, warnings: List[str],
                evaluation: Optional[Dict] = None) -> List[Dict]:
    if evaluation is not None:
        return evaluation["rows"]

    if df is not None:
        try:
            return _evaluate_models_from_csv(df, warnings)
        except Exception as exc:
            warnings.append(f"Automated baseline evaluation failed: {exc}")

    if not metrics:
        warnings.append("ML metrics file not found. Train the model before generating ML result tables.")
        return []

    test_metrics = metrics.get("test_metrics", {})
    train_metrics = metrics.get("train_metrics", {})
    report = test_metrics.get("classification_report", {})
    macro = report.get("macro avg", {})
    weighted = report.get("weighted avg", {})

    return [{
        "model": "LightGBM",
        "accuracy": test_metrics.get("test_accuracy"),
        "macro_f1": macro.get("f1-score"),
        "weighted_f1": weighted.get("f1-score"),
        "top_3_accuracy": None,
        "auc": test_metrics.get("auc") or test_metrics.get("test_metrics", {}).get("auc"),
        "classes": train_metrics.get("num_classes"),
    }]


def _confusion_matrices(df: Optional[pd.DataFrame], metrics: Dict, warnings: List[str],
                        evaluation: Optional[Dict] = None) -> List[Dict]:
    if evaluation is not None:
        return evaluation["confusion_matrices"]

    if df is not None:
        try:
            return _evaluate_confusion_matrices_from_csv(df, warnings)
        except Exception as exc:
            warnings.append(f"Automated confusion matrix generation failed: {exc}")

    test_metrics = metrics.get("test_metrics", {}) if metrics else {}
    matrix = test_metrics.get("confusion_matrix")
    labels = test_metrics.get("confusion_matrix_labels")
    if matrix and labels:
        return [{
            "model": "LightGBM",
            "labels": labels,
            "matrix": matrix,
        }]

    return []


def _feature_importance(metrics: Dict) -> List[Dict]:
    rows = metrics.get("feature_importance", []) if metrics else []
    return [
        {
            "feature": row.get("feature"),
            "importance": row.get("importance"),
        }
        for row in rows[:10]
    ]


def _model_configuration(dataset_report: Dict) -> List[Dict]:
    """Expose the exact inputs and selected training settings used in tables."""
    selected = dataset_report.get("selected_hyperparameters") or dataset_report.get("base_hyperparameters") or {}
    rows = [{"parameter": "features", "value": ", ".join(dataset_report.get("feature_names", []))}]
    rows.extend({"parameter": str(key), "value": value} for key, value in selected.items())
    rows.extend(
        {"parameter": f"training.{key}", "value": value}
        for key, value in (dataset_report.get("training_configuration") or {}).items()
    )
    return rows


def _label_provenance(df: Optional[pd.DataFrame]) -> List[Dict]:
    """Summarize weak-supervision provenance and review filtering."""
    if df is None or "label_source" not in df.columns:
        return []

    rows = []
    groups = df.groupby(["label_source", "label_review_status"], dropna=False)
    for (source, review_status), group in groups:
        confidence = pd.to_numeric(group["label_confidence"], errors="coerce") if "label_confidence" in group else None
        rows.append({
            "label_source": source,
            "review_status": review_status,
            "rows": int(len(group)),
            "mean_confidence": float(confidence.mean()) if confidence is not None and confidence.notna().any() else None,
        })
    return rows


def _misclassification_examples(metrics: Dict) -> List[Dict]:
    """Return concrete test-set classification errors persisted during training."""
    predictions = metrics.get("test_metrics", {}).get("test_predictions", []) if metrics else []
    errors = [row for row in predictions if row.get("true_label") != row.get("predicted_label")]
    return [{
        "test_index": row.get("index"),
        "expected_category": row.get("true_label"),
        "predicted_category": row.get("predicted_label"),
        "expected_priority": row.get("true_priority"),
        "predicted_priority": row.get("predicted_priority"),
        "priority_delta": (row.get("predicted_priority") or 0) - (row.get("true_priority") or 0),
    } for row in errors[:3]]


def _failure_analysis(mongo_report: Dict) -> List[Dict]:
    total = mongo_report.get("total_scans", 0)
    rows = mongo_report.get("scan_rows", [])

    def rate(count: int) -> Optional[float]:
        return (count / total) if total else None

    failure_rows = [
        {
            "failure_type": "Missing CryptoCheck result",
            "count": sum(1 for row in rows if not row["has_crypto"]),
            "rate": None,
            "mitigation": "Inspect crypto-check logs; use timeout and partial-report fallback.",
        },
        {
            "failure_type": "Missing SecretHunter result",
            "count": sum(1 for row in rows if not row["has_secrets"]),
            "rate": None,
            "mitigation": "Inspect secret-hunter logs; keep scan result with unavailable-service marker.",
        },
        {
            "failure_type": "Missing NetworkInspector result",
            "count": sum(1 for row in rows if not row["has_network"]),
            "rate": None,
            "mitigation": "Inspect network-inspector logs; continue with static-only findings.",
        },
        {
            "failure_type": "Missing FixSuggest output",
            "count": sum(1 for row in rows if not row["has_fix_suggestions"]),
            "rate": None,
            "mitigation": "Use MASVS rule fallback or regenerate suggestions.",
        },
    ]

    for row in failure_rows:
        row["rate"] = rate(row["count"])
    return failure_rows


def _quantitative_comparison(mongo_report: Dict, warnings: List[str]) -> List[Dict]:
    totals = mongo_report.get("finding_totals", {})
    total_scans = mongo_report.get("total_scans", 0)
    avg_runtime = None

    if RUNTIME_RESULTS_PATH.exists():
        runtime_df = pd.read_csv(RUNTIME_RESULTS_PATH)
        if "runtime_seconds" in runtime_df.columns:
            mobile_rows = runtime_df[runtime_df.get("tool", "MobileSec") == "MobileSec"] if "tool" in runtime_df.columns else runtime_df
            if len(mobile_rows) > 0:
                avg_runtime = float(mobile_rows["runtime_seconds"].mean())
    else:
        warnings.append(
            "Runtime CSV not found at experiments/runtime_results.csv. Average runtime remains N/A."
        )

    rows = [{
        "tool": "MobileSec",
        "apks": total_scans,
        "avg_runtime": avg_runtime,
        "findings_per_apk": totals.get("avg_findings_per_apk"),
        "precision": None,
        "recall": None,
        "f1": None,
        "note": "Precision/recall require benchmark ground truth.",
    }]

    if EXTERNAL_TOOL_RESULTS_PATH.exists():
        df = pd.read_csv(EXTERNAL_TOOL_RESULTS_PATH)
        rows.extend(df.where(pd.notnull(df), None).to_dict("records"))
    else:
        warnings.append(
            "External tool comparison CSV not found at experiments/external_tool_results.csv. "
            "MobSF/BeVigil/Yaazhini rows cannot be computed automatically."
        )

    if not GROUND_TRUTH_PATH.exists():
        warnings.append(
            "Ground truth CSV not found at experiments/ground_truth.csv. Precision, recall, and F1 remain N/A."
        )

    return rows


def _runtime_rows(warnings: List[str]) -> List[Dict]:
    if not RUNTIME_RESULTS_PATH.exists():
        return []

    try:
        df = pd.read_csv(RUNTIME_RESULTS_PATH)
        return df.where(pd.notnull(df), None).to_dict("records")
    except Exception as exc:
        warnings.append(f"Could not read runtime CSV at experiments/runtime_results.csv: {exc}")
        return []


def _benchmark_detail_rows(warnings: List[str]) -> List[Dict]:
    if not BENCHMARK_SCAN_DETAILS_PATH.exists():
        return []

    try:
        df = pd.read_csv(BENCHMARK_SCAN_DETAILS_PATH)
        return df.where(pd.notnull(df), None).to_dict("records")
    except Exception as exc:
        warnings.append(f"Could not read benchmark scan CSV at experiments/benchmark_scan_details.csv: {exc}")
        return []


def _runtime_summary(rows: List[Dict], dataset: str, tool: str = "MobileSec") -> Dict:
    matched = []
    for row in rows:
        row_tool = str(_first_present(row, ["tool", "scanner"]) or tool)
        row_dataset = str(_first_present(row, ["dataset", "benchmark", "apk_set"]) or dataset)
        if row_tool.lower() == tool.lower() and row_dataset.lower() == dataset.lower():
            matched.append(row)

    def numeric_values(columns: List[str]) -> List[float]:
        values = []
        for row in matched:
            value = _first_present(row, columns)
            if value is not None:
                try:
                    values.append(float(value))
                except (TypeError, ValueError):
                    pass
        return values

    def success_rate(columns: List[str]) -> Optional[float]:
        values = []
        for row in matched:
            value = _first_present(row, columns)
            if value is None:
                continue
            if isinstance(value, str):
                values.append(value.strip().lower() in {"1", "true", "yes", "success", "completed"})
            else:
                values.append(bool(value))
        return sum(values) / len(values) if values else None

    runtime = numeric_values(["runtime_seconds", "scan_time_seconds", "scan_time", "duration_seconds"])
    cpu = numeric_values(["cpu_percent", "cpu_usage", "mean_cpu_usage"])
    ram = numeric_values(["ram_mb", "memory_mb", "mean_ram_mb", "mean_ram_usage"])
    throughput = numeric_values(["throughput_apks_per_minute"])
    concurrency = numeric_values(["concurrency"])
    export_bytes = numeric_values(["export_bytes_total"])
    export_time = numeric_values(["export_time_seconds"])

    return {
        "scan_time": mean(runtime) if runtime else None,
        "cpu_usage": mean(cpu) if cpu else None,
        "ram_usage": mean(ram) if ram else None,
        "report_success": success_rate(["report_success", "pdf_success", "report_generation_success"]),
        "json_success": success_rate(["json_success", "json_export_success"]),
        "sarif_success": success_rate(["sarif_success", "sarif_export_success"]),
        "throughput_apks_per_minute": mean(throughput) if throughput else None,
        "concurrency": max(concurrency) if concurrency else None,
        "export_bytes_total": mean(export_bytes) if export_bytes else None,
        "export_time_seconds": mean(export_time) if export_time else None,
    }


def _all_runtime_summary(rows: List[Dict], tool: str = "MobileSec") -> Dict:
    matched = [
        row for row in rows
        if str(_first_present(row, ["tool", "scanner"]) or tool).lower() == tool.lower()
    ]

    def numeric_values(columns: List[str]) -> List[float]:
        values = []
        for row in matched:
            value = _first_present(row, columns)
            if value is not None:
                try:
                    values.append(float(value))
                except (TypeError, ValueError):
                    pass
        return values

    def success_count(columns: List[str]) -> Dict:
        values = []
        for row in matched:
            value = _first_present(row, columns)
            if value is None:
                continue
            if isinstance(value, str):
                values.append(value.strip().lower() in {"1", "true", "yes", "success", "completed"})
            else:
                values.append(bool(value))
        return {
            "success": sum(values),
            "total": len(values),
            "rate": (sum(values) / len(values)) if values else None,
        }

    runtime = numeric_values(["runtime_seconds", "scan_time_seconds", "scan_time", "duration_seconds"])
    return {
        "scan_time": mean(runtime) if runtime else None,
        "report_success": success_count(["report_success", "pdf_success", "report_generation_success"]),
        "json_success": success_count(["json_success", "json_export_success"]),
        "sarif_success": success_count(["sarif_success", "sarif_export_success"]),
    }


def _ground_truth_rows(warnings: List[str]) -> List[Dict]:
    if not GROUND_TRUTH_PATH.exists():
        return []

    try:
        df = pd.read_csv(GROUND_TRUTH_PATH)
        return df.where(pd.notnull(df), None).to_dict("records")
    except Exception as exc:
        warnings.append(f"Could not read ground-truth CSV at experiments/ground_truth.csv: {exc}")
        return []


def _benchmark_counts(rows: List[Dict], dataset: str) -> Dict:
    matched = [
        row for row in rows
        if str(_first_present(row, ["dataset", "benchmark", "apk_set"]) or "").lower() == dataset.lower()
    ]

    apk_ids = {
        str(_first_present(row, ["apk", "apk_id", "apk_name", "scan_id"]) or idx)
        for idx, row in enumerate(matched)
    }

    detected_findings = 0
    for row in matched:
        value = _first_present(row, ["detected_findings", "findings", "finding_count", "total_findings"])
        if value is None:
            detected_value = _first_present(row, ["detected", "mobilesec_detected", "prediction", "found"])
            detected_findings += int(str(detected_value).strip().lower() in {"1", "true", "yes", "detected", "found", "vulnerable"})
            continue
        try:
            detected_findings += int(float(value))
        except (TypeError, ValueError):
            pass

    tp = fp = fn = expected = labeled = 0
    for row in matched:
        expected_value = _first_present(row, ["expected", "is_vulnerable", "ground_truth", "truth"])
        detected_value = _first_present(row, ["detected", "mobilesec_detected", "prediction", "found"])

        if expected_value is None or str(expected_value).strip() == "":
            continue

        labeled += 1
        expected_bool = str(expected_value).strip().lower() in {"1", "true", "yes", "vulnerable"}
        detected_bool = None if detected_value is None else str(detected_value).strip().lower() in {"1", "true", "yes", "detected", "found", "vulnerable"}

        if expected_bool:
            expected += 1
        if expected_bool is True and detected_bool is True:
            tp += 1
        elif expected_bool is False and detected_bool is True:
            fp += 1
        elif expected_bool is True and detected_bool is False:
            fn += 1

    precision = _safe_ratio(tp, tp + fp)
    recall = _safe_ratio(tp, tp + fn)
    f1 = _safe_ratio(2 * precision * recall, precision + recall) if precision is not None and recall is not None else None

    return {
        "apks": len(matched) if matched else None,
        "detected_findings": detected_findings if matched else None,
        "true_positives": tp if labeled else None,
        "false_positives": fp if labeled else None,
        "false_negatives": fn if labeled else None,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "expected_findings": expected if labeled else None,
    }


def _category_detection_table(warnings: List[str]) -> List[Dict]:
    """Compute detection values per manually annotated finding category."""
    rows = _ground_truth_rows(warnings)
    categorized = [row for row in rows if _first_present(row, ["category", "finding_category"])]
    if not categorized:
        warnings.append(
            "Per-category benchmark metrics require a category column in experiments/ground_truth.csv; "
            "annotate secrets, crypto, and network findings before publication."
        )
        return []

    output = []
    for category in ["secrets", "crypto", "network"]:
        selected = [
            row for row in categorized
            if str(_first_present(row, ["category", "finding_category"]) or "").strip().lower() == category
        ]
        counts = _benchmark_counts([{**row, "dataset": category} for row in selected], category) if selected else {}
        output.append({
            "category": category,
            "labeled_rows": len(selected),
            "true_positives": counts.get("true_positives"),
            "false_positives": counts.get("false_positives"),
            "false_negatives": counts.get("false_negatives"),
            "precision": counts.get("precision"),
            "recall": counts.get("recall"),
            "f1_score": counts.get("f1_score"),
        })
    return output


def _mobilesec_benchmark_summary(mongo_report: Dict, warnings: List[str]) -> Dict:
    detail_rows = [
        row for row in _benchmark_detail_rows(warnings)
        if str(_first_present(row, ["status"]) or "").lower() in {"completed", "success", ""}
    ]
    runtime = _all_runtime_summary(_runtime_rows(warnings))
    scan_ids = {
        str(_first_present(row, ["scan_id"]) or "")
        for row in detail_rows
        if _first_present(row, ["scan_id"])
    }
    mongo_rows = [
        row for row in (mongo_report.get("scan_rows") or [])
        if str(row.get("scan_id") or "") in scan_ids
    ]

    crypto_findings = sum(int(row.get("crypto_findings") or 0) for row in mongo_rows)
    secret_findings = sum(int(row.get("secret_findings") or 0) for row in mongo_rows)
    network_findings = sum(int(row.get("network_findings") or 0) for row in mongo_rows)

    detected_findings = 0
    for row in detail_rows:
        value = _first_present(row, ["detected_findings", "findings", "finding_count", "total_findings"])
        try:
            detected_findings += int(float(value or 0))
        except (TypeError, ValueError):
            pass

    categories = sum(1 for value in [crypto_findings, secret_findings, network_findings] if value > 0) or None
    if detail_rows and scan_ids and not mongo_rows:
        warnings.append(
            "MobileSec benchmark scan IDs are not present in MongoDB; Table 5 uses benchmark APK/runtime counts but category totals may be incomplete."
        )

    return {
        "apks": len(detail_rows) if detail_rows else None,
        "benchmark_apks": "DroidBench, Ghera" if detail_rows else "N/A",
        "real_world_apks": 0 if detail_rows else None,
        "scan_time": runtime.get("scan_time"),
        "json_export": runtime.get("json_success"),
        "report_success": runtime.get("report_success"),
        "sarif_success": runtime.get("sarif_success"),
        "detected_vulnerability_categories": categories,
        "hardcoded_secrets_detected": secret_findings if mongo_rows else None,
        "network_issues_detected": network_findings if mongo_rows else None,
        "cryptographic_issues_detected": crypto_findings if mongo_rows else None,
        "detected_findings": detected_findings if detail_rows else None,
    }


def _scan_evaluation_table(mongo_report: Dict, warnings: List[str]) -> List[Dict]:
    gt_rows = _ground_truth_rows(warnings)
    runtime_rows = _runtime_rows(warnings)
    columns = {}

    for dataset in DATASETS:
        if dataset == HISTORICAL_DATASET:
            totals = mongo_report.get("finding_totals", {}) or {}
            columns[dataset] = {
                "apks": mongo_report.get("total_scans") or None,
                "detected_findings": totals.get("total_findings"),
                "true_positives": None,
                "false_positives": None,
                "false_negatives": None,
                "precision": None,
                "recall": None,
                "f1_score": None,
            }
        else:
            columns[dataset] = _benchmark_counts(gt_rows, dataset)

        columns[dataset].update(_runtime_summary(runtime_rows, dataset))

    if not gt_rows:
        warnings.append(
            "Benchmark ground-truth rows are missing. Add experiments/ground_truth.csv to compute DroidBench/Ghera TP, FP, FN, precision, recall, and F1."
        )
    if not runtime_rows:
        warnings.append(
            "Runtime-resource rows are missing. Add experiments/runtime_results.csv to compute scan time, CPU, RAM, report success, and SARIF success."
        )

    metric_rows = [
        ("Number of APKs", "apks", None),
        ("Detected findings", "detected_findings", None),
        ("True positives", "true_positives", None),
        ("False positives", "false_positives", None),
        ("False negatives", "false_negatives", None),
        ("Precision", "precision", None),
        ("Recall", "recall", None),
        ("F1-score", "f1_score", None),
        ("Mean scan time", "scan_time", " s"),
        ("Mean CPU usage", "cpu_usage", "%"),
        ("Mean RAM usage", "ram_usage", " MB"),
        ("Throughput", "throughput_apks_per_minute", " apk/min"),
        ("Concurrent APK scans", "concurrency", None),
        ("Mean generated export bytes", "export_bytes_total", " bytes"),
        ("Mean report export time", "export_time_seconds", " s"),
        ("Report-generation success rate", "report_success", "%"),
        ("SARIF export success rate", "sarif_success", "%"),
    ]

    rows = []
    for label, key, suffix in metric_rows:
        row = {"metric": label}
        for dataset in DATASETS:
            value = columns[dataset].get(key)
            if suffix == " s" and value is not None:
                row[dataset] = f"{float(value):.2f} s"
            elif suffix == " MB" and value is not None:
                row[dataset] = f"{float(value):.1f} MB"
            elif suffix == " apk/min" and value is not None:
                row[dataset] = f"{float(value):.2f} apk/min"
            elif suffix == " bytes" and value is not None:
                row[dataset] = f"{float(value):.0f} bytes"
            elif key == "cpu_usage" and value is not None:
                row[dataset] = f"{float(value):.1f}%"
            elif suffix == "%" and value is not None:
                row[dataset] = f"{float(value) * 100:.1f}%"
            elif key in {"precision", "recall", "f1_score"} and value is not None:
                row[dataset] = f"{float(value):.4f}"
            else:
                row[dataset] = _fmt(value, 0)
        rows.append(row)

    return rows


def _external_tool_rows(warnings: List[str]) -> List[Dict]:
    if not EXTERNAL_TOOL_RESULTS_PATH.exists():
        return []

    try:
        df = pd.read_csv(EXTERNAL_TOOL_RESULTS_PATH)
        return df.where(pd.notnull(df), None).to_dict("records")
    except Exception as exc:
        warnings.append(f"Could not read external-tool CSV at experiments/external_tool_results.csv: {exc}")
        return []


def _tool_value(rows: List[Dict], tool: str, keys: List[str]) -> Any:
    for row in rows:
        row_tool = str(_first_present(row, ["tool", "scanner"]) or "")
        if row_tool.lower() == tool.lower():
            return _first_present(row, keys)
    return None


def _tool_comparison_table(mongo_report: Dict, warnings: List[str]) -> List[Dict]:
    external_rows = _external_tool_rows(warnings)
    benchmark = _mobilesec_benchmark_summary(mongo_report, warnings)

    def measured_export(value: Any) -> str:
        if not value or not isinstance(value, dict):
            return "N/A"
        success = value.get("success")
        total = value.get("total")
        if total in (None, 0):
            return "N/A"
        return f"{success}/{total}"

    mobilesec = {
        "Number of APKs analyzed": benchmark.get("apks"),
        "Benchmark APKs": benchmark.get("benchmark_apks"),
        "Real-world APKs": benchmark.get("real_world_apks"),
        "Mean scan time per APK": f"{benchmark['scan_time']:.2f} s" if benchmark.get("scan_time") is not None else "N/A",
        "Detected vulnerability categories": benchmark.get("detected_vulnerability_categories"),
        "Hardcoded secrets detected": benchmark.get("hardcoded_secrets_detected"),
        "Network issues detected": benchmark.get("network_issues_detected"),
        "Cryptographic issues detected": benchmark.get("cryptographic_issues_detected"),
        "PDF export": measured_export(benchmark.get("report_success")),
        "JSON export": measured_export(benchmark.get("json_export")),
        "SARIF export": measured_export(benchmark.get("sarif_success")),
        "CI/CD integration": "Yes",
        "ML-based prioritization": "Yes",
        "AI-assisted remediation": "Yes",
        "Reproducible Docker deployment": "Yes",
    }
    for metric in ["True positives", "False positives", "False negatives", "Precision", "Recall", "F1 score"]:
        mobilesec[metric] = "See Table 6"

    rows = []
    for criterion, mobile_value in mobilesec.items():
        row = {"criterion": criterion, "MobileSec": _fmt(mobile_value, 0)}
        for tool in COMPARISON_TOOLS[1:]:
            csv_value = _tool_value(external_rows, tool, [
                criterion,
                criterion.lower().replace(" ", "_").replace("/", "_").replace("-", "_"),
            ])
            row[tool] = _fmt(csv_value, 0)
        rows.append(row)

    if not external_rows:
        warnings.append(
            "External-tool comparison rows are missing. Add experiments/external_tool_results.csv for MobSF, APKDeepLens, BeVigil, and Yaazhini/Vooki values measured on the same APK set."
        )

    return rows


def _priority_from_category(category: Any) -> Optional[int]:
    if category is None:
        return None
    return CATEGORY_PRIORITY.get(str(category))


def _lightgbm_prioritization_table(df: Optional[pd.DataFrame], metrics: Dict, warnings: List[str]) -> List[Dict]:
    values = {
        "Accuracy": None,
        "Macro-precision": None,
        "Macro-recall": None,
        "Macro-F1": None,
        "AUC": None,
        "False prioritization rate": None,
        "Under-prioritization rate": None,
        "Over-prioritization rate": None,
    }

    test_metrics = metrics.get("test_metrics", {}) if metrics else {}
    report = test_metrics.get("classification_report", {}) if test_metrics else {}
    macro = report.get("macro avg", {}) if report else {}
    if test_metrics:
        values["Accuracy"] = test_metrics.get("test_accuracy")
        values["Macro-precision"] = macro.get("precision")
        values["Macro-recall"] = macro.get("recall")
        values["Macro-F1"] = macro.get("f1-score")
        values["AUC"] = test_metrics.get("auc") or test_metrics.get("test_metrics", {}).get("auc")
        prioritization_metrics = test_metrics.get("prioritization_metrics", {})
        values["Under-prioritization rate"] = prioritization_metrics.get("under_prioritization_rate")
        values["Over-prioritization rate"] = prioritization_metrics.get("over_prioritization_rate")
        if values["Accuracy"] is not None:
            values["False prioritization rate"] = 1 - values["Accuracy"]
        missing_saved = [
            name
            for name in ["AUC", "Under-prioritization rate", "Over-prioritization rate"]
            if values[name] is None
        ]
        if missing_saved:
            warnings.append(
                "Table 3 uses saved hold-out test metrics from the last trained model. "
                f"Missing saved metrics: {', '.join(missing_saved)}. Retrain the model to persist them."
            )

    if values["Accuracy"] is None and df is not None:
        try:
            X = df[FEATURE_COLUMNS].astype(float).values
            labels = df[TARGET_COLUMN].astype(str).values
            encoder = LabelEncoder()
            y = encoder.fit_transform(labels)
            X_train, X_test, y_train, y_test = train_test_split(
                X,
                y,
                test_size=0.2,
                random_state=42,
                stratify=y,
            )

            scaler = StandardScaler()
            X_train_scaled = scaler.fit_transform(X_train)
            X_test_scaled = scaler.transform(X_test)

            params = LIGHTGBM_PARAMS.copy()
            params["num_class"] = len(encoder.classes_)
            params["num_threads"] = 1
            model = lgb.train(params, lgb.Dataset(X_train_scaled, label=y_train), num_boost_round=200)
            proba = model.predict(X_test_scaled)
            pred = np.argmax(proba, axis=1)

            values["Accuracy"] = accuracy_score(y_test, pred)
            values["Macro-precision"] = precision_score(y_test, pred, average="macro", zero_division=0)
            values["Macro-recall"] = recall_score(y_test, pred, average="macro", zero_division=0)
            values["Macro-F1"] = f1_score(y_test, pred, average="macro", zero_division=0)
            values["False prioritization rate"] = 1 - values["Accuracy"]

            if len(encoder.classes_) > 2:
                values["AUC"] = roc_auc_score(y_test, proba, average="macro", multi_class="ovr")
            elif len(encoder.classes_) == 2:
                values["AUC"] = roc_auc_score(y_test, proba[:, 1])

            true_priorities = [_priority_from_category(encoder.classes_[idx]) for idx in y_test]
            pred_priorities = [_priority_from_category(encoder.classes_[idx]) for idx in pred]
            priority_pairs = [
                (true_priority, pred_priority)
                for true_priority, pred_priority in zip(true_priorities, pred_priorities)
                if true_priority is not None and pred_priority is not None
            ]
            if priority_pairs:
                under = sum(1 for true_priority, pred_priority in priority_pairs if pred_priority < true_priority)
                over = sum(1 for true_priority, pred_priority in priority_pairs if pred_priority > true_priority)
                values["Under-prioritization rate"] = under / len(priority_pairs)
                values["Over-prioritization rate"] = over / len(priority_pairs)
        except Exception as exc:
            warnings.append(f"LightGBM prioritization table could not be recomputed from CSV: {exc}")

    if values["Accuracy"] is None:
        warnings.append(
            "LightGBM prioritization metrics are unavailable. Train the model on a non-trivial dataset before using Table 3 in the paper."
        )

    return [{"metric": metric, "value": _fmt(value)} for metric, value in values.items()]


def _dataset_table(dataset_report: Dict, mongo_report: Dict) -> List[Dict]:
    training_rows = dataset_report.get("training_rows") or dataset_report.get("rows", 0)
    training_classes = dataset_report.get("training_classes") or dataset_report.get("classes", 0)
    return [
        {
            "dataset": "MongoDB scan results",
            "apks": mongo_report.get("total_scans", 0),
            "ground_truth": "No / manual",
            "purpose": "Real platform scan results used for extraction and training",
        },
        {
            "dataset": "Training CSV",
            "apks": training_rows,
            "ground_truth": "Derived labels",
            "purpose": f"{training_classes} fix_category classes, {dataset_report.get('feature_count', 0)} features",
        },
    ]


def _latex_dataset(rows: List[Dict]) -> str:
    body = "\n".join(
        f"{row['dataset']} & {row['apks']} & {row['ground_truth']} & {row['purpose']} \\\\"
        for row in rows
    )
    return f"""\\begin{{table}}[h]
\\centering
\\caption{{Datasets available for MobileSec evaluation.}}
\\label{{tab:evaluation-datasets-generated}}
\\begin{{tabular}}{{lclp{{0.35\\linewidth}}}}
\\hline
\\textbf{{Dataset}} & \\textbf{{APKs/Rows}} & \\textbf{{Ground truth}} & \\textbf{{Purpose}} \\\\
\\hline
{body}
\\hline
\\end{{tabular}}
\\end{{table}}"""


def _latex_ml(rows: List[Dict]) -> str:
    body = "\n".join(
        f"{row['model']} & {_fmt(row.get('accuracy'))} & {_fmt(row.get('macro_f1'))} & "
        f"{_fmt(row.get('weighted_f1'))} & {_fmt(row.get('top_3_accuracy'))} & {_fmt(row.get('classes'), 0)} \\\\"
        for row in rows
    ) or "LightGBM & N/A & N/A & N/A & N/A & N/A \\\\"
    return f"""\\begin{{table}}[h]
\\centering
\\caption{{Performance of the vulnerability remediation classifier.}}
\\label{{tab:ml-results-generated}}
\\begin{{tabular}}{{lccccc}}
\\hline
\\textbf{{Model}} & \\textbf{{Accuracy}} & \\textbf{{Macro-F1}} & \\textbf{{Weighted-F1}} & \\textbf{{Top-3 Acc.}} & \\textbf{{Classes}} \\\\
\\hline
{body}
\\hline
\\end{{tabular}}
\\end{{table}}"""


def _latex_feature_importance(rows: List[Dict]) -> str:
    body = "\n".join(
        f"\\texttt{{{row['feature']}}} & {_fmt(row.get('importance'), 2)} \\\\"
        for row in rows
    ) or "N/A & N/A \\\\"
    return f"""\\begin{{table}}[h]
\\centering
\\caption{{Top LightGBM feature importances.}}
\\label{{tab:feature-importance-generated}}
\\begin{{tabular}}{{lc}}
\\hline
\\textbf{{Feature}} & \\textbf{{Importance}} \\\\
\\hline
{body}
\\hline
\\end{{tabular}}
\\end{{table}}"""


def _latex_failures(rows: List[Dict]) -> str:
    body = "\n".join(
        f"{row['failure_type']} & {row['count']} & {_fmt(row.get('rate'))} & {row['mitigation']} \\\\"
        for row in rows
    )
    return f"""\\begin{{table}}[h]
\\centering
\\caption{{Observed incomplete outputs in the MobileSec pipeline.}}
\\label{{tab:failure-analysis-generated}}
\\begin{{tabular}}{{lccp{{0.35\\linewidth}}}}
\\hline
\\textbf{{Failure type}} & \\textbf{{Count}} & \\textbf{{Rate}} & \\textbf{{Mitigation}} \\\\
\\hline
{body}
\\hline
\\end{{tabular}}
\\end{{table}}"""


def _latex_comparison(rows: List[Dict]) -> str:
    body = "\n".join(
        f"{row.get('tool')} & {_fmt(row.get('apks'), 0)} & {_fmt(row.get('avg_runtime'))} & "
        f"{_fmt(row.get('findings_per_apk'))} & {_fmt(row.get('precision'))} & "
        f"{_fmt(row.get('recall'))} & {_fmt(row.get('f1'))} \\\\"
        for row in rows
    )
    return f"""\\begin{{table}}[h]
\\centering
\\caption{{Quantitative comparison values available from configured experiments.}}
\\label{{tab:quantitative-comparison-generated}}
\\begin{{tabular}}{{lcccccc}}
\\hline
\\textbf{{Tool}} & \\textbf{{APKs}} & \\textbf{{Avg. runtime}} & \\textbf{{Findings/APK}} & \\textbf{{Precision}} & \\textbf{{Recall}} & \\textbf{{F1}} \\\\
\\hline
{body}
\\hline
\\end{{tabular}}
\\end{{table}}"""


def _latex_weight_sensitivity(rows: List[Dict]) -> str:
    body = "\n".join(
        f"{row.get('weighting_scheme')} & {_fmt(row.get('top_10_overlap'))} & "
        f"{_fmt(row.get('kendall_tau'))} & {_fmt(row.get('macro_f1'))} \\\\"
        for row in rows
    ) or "N/A & N/A & N/A & N/A \\\\"
    return f"""\\begin{{table}}[h]
\\centering
\\caption{{Sensitivity analysis of severity-score weighting schemes.}}
\\label{{tab:weight-sensitivity-generated}}
\\begin{{tabular}}{{lccc}}
\\hline
\\textbf{{Weighting scheme}} & \\textbf{{Top-10 overlap}} & \\textbf{{Kendall's $\\tau$}} & \\textbf{{Macro-F1}} \\\\
\\hline
{body}
\\hline
\\end{{tabular}}
\\end{{table}}"""


def _latex_screenshot_table_3(rows: List[Dict]) -> str:
    body = "\n".join(
        f"{_latex_cell(row['metric'])} & {_latex_cell(row['value'])} \\\\"
        for row in rows
    )
    return f"""\\begin{{table}}[h]
\\centering
\\caption{{Performance of the LightGBM prioritization model.}}
\\label{{tab:lightgbm-prioritization-generated}}
\\begin{{tabular}}{{lc}}
\\hline
\\textbf{{Metric}} & \\textbf{{Value}} \\\\
\\hline
{body}
\\hline
\\end{{tabular}}
\\end{{table}}"""


def _latex_screenshot_table_5(rows: List[Dict]) -> str:
    external_tools = COMPARISON_TOOLS[1:]
    column_spec = "l" + ("c" * len(COMPARISON_TOOLS))
    header_cells = " & ".join(f"\\textbf{{{_latex_cell(tool)}}}" for tool in COMPARISON_TOOLS)
    body = "\n".join(
        f"{_latex_cell(row['criterion'])} & {_latex_cell(row['MobileSec'])} & "
        f"{' & '.join(_latex_cell(row.get(tool)) for tool in external_tools)} \\\\"
        for row in rows
    )
    return f"""\\begin{{table*}}[t]
\\centering
\\caption{{Quantitative comparison of MobileSec with representative Android security analysis tools on the same APK set.}}
\\label{{tab:tool-comparison-generated}}
\\begin{{tabular}}{{{column_spec}}}
\\hline
\\textbf{{Criterion}} & {header_cells} \\\\
\\hline
{body}
\\hline
\\end{{tabular}}
\\end{{table*}}"""


def _latex_screenshot_table_6(rows: List[Dict]) -> str:
    body = "\n".join(
        f"{_latex_cell(row['metric'])} & {_latex_cell(row['DroidBench'])} & {_latex_cell(row['Ghera'])} & {_latex_cell(row[HISTORICAL_DATASET])} \\\\"
        for row in rows
    )
    return f"""\\begin{{table*}}[t]
\\centering
\\caption{{Evaluation of MobileSec on benchmark and real-world APKs.}}
\\label{{tab:mobilesec-benchmark-realworld-generated}}
\\begin{{tabular}}{{lccc}}
\\hline
\\textbf{{Metric}} & \\textbf{{DroidBench}} & \\textbf{{Ghera}} & \\textbf{{Historical records (no ground truth)}} \\\\
\\hline
{body}
\\hline
\\end{{tabular}}
\\end{{table*}}"""


def generate_paper_tables() -> Dict:
    warnings: List[str] = []
    metrics = _load_metrics()
    training_df = _load_training_df(warnings, metrics)
    dataset = _dataset_report(warnings, metrics)
    mongo = _mongodb_report(warnings)

    dataset_table = _dataset_table(dataset, mongo)
    model_evaluation = None
    if training_df is not None:
        try:
            model_evaluation = _evaluate_model_artifacts_from_csv(training_df, warnings)
        except Exception as exc:
            warnings.append(f"Automated baseline evaluation failed: {exc}")
            model_evaluation = {"rows": [], "confusion_matrices": []}
    ml_results = _ml_results(training_df, metrics, warnings, model_evaluation)
    confusion_matrices = _confusion_matrices(training_df, metrics, warnings, model_evaluation)
    feature_importance = _feature_importance(metrics)
    model_configuration = _model_configuration(dataset)
    label_provenance = _label_provenance(training_df)
    misclassification_examples = _misclassification_examples(metrics)
    failure_analysis = _failure_analysis(mongo)
    quantitative_comparison = _quantitative_comparison(mongo, warnings)
    weight_sensitivity = _weight_sensitivity(training_df)
    lightgbm_prioritization = _lightgbm_prioritization_table(training_df, metrics, warnings)
    tool_comparison = _tool_comparison_table(mongo, warnings)
    benchmark_realworld = _scan_evaluation_table(mongo, warnings)
    category_detection = _category_detection_table(warnings)
    checklist_review = _checklist_review_table(warnings)

    return {
        "warnings": warnings,
        "dataset": dataset,
        "mongodb": {
            "total_scans": mongo.get("total_scans"),
            "coverage": mongo.get("coverage"),
            "finding_totals": mongo.get("finding_totals"),
        },
        "tables": {
            "evaluation_datasets": dataset_table,
            "ml_results": ml_results,
            "confusion_matrices": confusion_matrices,
            "feature_importance": feature_importance,
            "model_configuration": model_configuration,
            "label_provenance": label_provenance,
            "misclassification_examples": misclassification_examples,
            "failure_analysis": failure_analysis,
            "quantitative_comparison": quantitative_comparison,
            "weight_sensitivity": weight_sensitivity,
            "lightgbm_prioritization": lightgbm_prioritization,
            "tool_comparison": tool_comparison,
            "benchmark_realworld": benchmark_realworld,
            "category_detection": category_detection,
            "checklist_review": checklist_review,
        },
        "latex": {
            "table_3_lightgbm_prioritization": _latex_screenshot_table_3(lightgbm_prioritization),
            "table_5_tool_comparison": _latex_screenshot_table_5(tool_comparison),
            "table_6_benchmark_realworld": _latex_screenshot_table_6(benchmark_realworld),
            "evaluation_datasets": _latex_dataset(dataset_table),
            "ml_results": _latex_ml(ml_results),
            "feature_importance": _latex_feature_importance(feature_importance),
            "failure_analysis": _latex_failures(failure_analysis),
            "quantitative_comparison": _latex_comparison(quantitative_comparison),
            "weight_sensitivity": _latex_weight_sensitivity(weight_sensitivity),
        },
    }
