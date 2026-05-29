"""
Model Trainer for Security Fix Suggestion
Uses LightGBM for multi-class classification
"""

import os
import json
import logging
import argparse
import joblib
import numpy as np
import pandas as pd
import lightgbm as lgb
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    top_k_accuracy_score,
)
from sklearn.utils.class_weight import compute_sample_weight
from typing import Dict, List, Tuple

from .model_config import (
    LIGHTGBM_PARAMS, TRAINING_CONFIG, FEATURE_COLUMNS, TARGET_COLUMN,
    MODEL_PATH, LABEL_ENCODER_PATH, FEATURE_SCALER_PATH, METRICS_PATH
)

logger = logging.getLogger(__name__)


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


class ModelTrainer:
    """Train LightGBM model for security fix suggestions"""
    
    def __init__(self):
        self.model = None
        self.label_encoder = LabelEncoder()
        self.feature_scaler = StandardScaler()
        self.feature_columns = FEATURE_COLUMNS
        self.target_column = TARGET_COLUMN
        self.dataset_info = {}

    def _feature_collision_summary(self, df: pd.DataFrame) -> Dict:
        """Estimate the label ceiling caused by identical features with different labels."""
        grouped = df.groupby(self.feature_columns, dropna=False)[self.target_column]
        class_counts = grouped.nunique()
        majority_correct = grouped.value_counts().groupby(
            level=list(range(len(self.feature_columns)))
        ).max().sum()

        return {
            'unique_feature_vectors': int(len(class_counts)),
            'ambiguous_feature_vectors': int((class_counts > 1).sum()),
            'rows_in_ambiguous_feature_vectors': int(
                df.set_index(self.feature_columns).index.isin(class_counts[class_counts > 1].index).sum()
            ),
            'majority_label_accuracy_upper_bound': float(majority_correct / len(df)) if len(df) else None,
        }
        
    def prepare_data(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
        """
        Prepare data for training
        
        Returns: X_train, X_val, y_train, y_val
        """
        logger.info("Preparing data for training...")
        
        # Check for required columns
        missing_features = set(self.feature_columns) - set(df.columns)
        if missing_features:
            raise ValueError(f"Missing features in dataset: {missing_features}")
        
        if self.target_column not in df.columns:
            raise ValueError(f"Target column '{self.target_column}' not found in dataset")

        label_quality_info = {}
        if 'label_confidence' in df.columns:
            min_confidence = float(os.getenv('ML_MIN_LABEL_CONFIDENCE', '0.75'))
            original_rows = len(df)
            confidence = pd.to_numeric(df['label_confidence'], errors='coerce').fillna(0.0)
            accepted_status = (
                df['label_review_status'].astype(str).str.lower().isin(['accepted', 'approved', 'human_approved'])
                if 'label_review_status' in df.columns
                else pd.Series(True, index=df.index)
            )
            keep_mask = (confidence >= min_confidence) & accepted_status
            filtered_df = df[keep_mask].copy()

            label_quality_info = {
                'min_label_confidence': min_confidence,
                'rows_before_label_quality_filter': int(original_rows),
                'rows_after_label_quality_filter': int(len(filtered_df)),
                'excluded_low_confidence_or_unreviewed': int(original_rows - len(filtered_df)),
            }

            if len(filtered_df) > 0:
                df = filtered_df
                logger.info(
                    "Using %s/%s high-confidence accepted labels for training (threshold=%.2f)",
                    len(df),
                    original_rows,
                    min_confidence,
                )
            else:
                logger.warning(
                    "Label quality filter removed every row; using all rows to avoid an empty dataset. "
                    "Review labels or lower ML_MIN_LABEL_CONFIDENCE."
                )

        raw_class_counts = df[self.target_column].astype(str).value_counts()
        class_counts = raw_class_counts.copy()
        rare_classes = class_counts[class_counts < 3]
        if not rare_classes.empty:
            logger.warning(
                "Excluding classes with fewer than 3 real samples from training: %s",
                rare_classes.to_dict()
            )
            df = df[df[self.target_column].astype(str).isin(class_counts[class_counts >= 3].index)].copy()
            if len(df) == 0:
                raise ValueError(
                    "No classes have enough real samples for training. Need at least 3 samples "
                    "per class for the current train/validation/test split."
                )
            class_counts = df[self.target_column].astype(str).value_counts()
        
        # Extract features and target
        X = df[self.feature_columns].values
        y_raw = df[self.target_column].values
        
        # Encode labels
        y = self.label_encoder.fit_transform(y_raw)
        logger.info(f"Encoded {len(self.label_encoder.classes_)} unique classes: {self.label_encoder.classes_}")

        class_counts = pd.Series(y_raw).value_counts()
        self.dataset_info = {
            'raw_rows': int(raw_class_counts.sum()),
            'training_rows': int(len(df)),
            'raw_class_distribution': {str(k): int(v) for k, v in raw_class_counts.items()},
            'training_class_distribution': {str(k): int(v) for k, v in class_counts.items()},
            'excluded_rare_classes': {str(k): int(v) for k, v in rare_classes.items()},
            'label_quality_filter': label_quality_info,
            'feature_collision_summary': self._feature_collision_summary(df),
        }

        if len(self.label_encoder.classes_) < 2:
            raise ValueError(
                "Training needs at least 2 different fix_category values, but the dataset "
                f"has only {len(self.label_encoder.classes_)}: {self.label_encoder.classes_.tolist()}. "
                "Run more scans that produce different vulnerability types, or create a development "
                "bootstrap dataset with: python -m src.data.bootstrap_dataset"
            )

        if len(df) < 20 or class_counts.min() < 3:
            raise ValueError(
                "Training dataset is too small for the stratified train/validation/test split. "
                f"Rows={len(df)}, class_counts={class_counts.to_dict()}. "
                "Use more MongoDB scan results, or create a development bootstrap dataset with: "
                "python -m src.data.bootstrap_dataset"
            )
        
        # Split data
        test_size = TRAINING_CONFIG['test_size']
        val_size = TRAINING_CONFIG['validation_size']
        random_state = TRAINING_CONFIG['random_state']
        
        # First split: train+val vs test
        X_temp, X_test, y_temp, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state, stratify=y
        )
        
        # Second split: train vs val
        val_ratio = val_size / (1 - test_size)
        X_train, X_val, y_train, y_val = train_test_split(
            X_temp, y_temp, test_size=val_ratio, random_state=random_state, stratify=y_temp
        )
        
        # Scale features
        X_train = self.feature_scaler.fit_transform(X_train)
        X_val = self.feature_scaler.transform(X_val)
        X_test = self.feature_scaler.transform(X_test)
        
        logger.info(f"Data split: Train={len(X_train)}, Val={len(X_val)}, Test={len(X_test)}")
        
        # Store test set for final evaluation
        self.X_test = X_test
        self.y_test = y_test
        
        self.X_train = X_train
        self.y_train = y_train
        self.X_val = X_val
        self.y_val = y_val

        return X_train, X_val, y_train, y_val

    def _metric_summary(self, y_true: np.ndarray, y_pred: np.ndarray,
                        y_proba: np.ndarray = None) -> Dict:
        """Compute metrics that are robust for imbalanced multiclass data."""
        metrics = {
            'accuracy': accuracy_score(y_true, y_pred),
            'balanced_accuracy': balanced_accuracy_score(y_true, y_pred),
            'macro_precision': precision_score(y_true, y_pred, average='macro', zero_division=0),
            'macro_recall': recall_score(y_true, y_pred, average='macro', zero_division=0),
            'macro_f1': f1_score(y_true, y_pred, average='macro', zero_division=0),
            'weighted_f1': f1_score(y_true, y_pred, average='weighted', zero_division=0),
        }

        if y_proba is not None and len(self.label_encoder.classes_) >= 3:
            labels = np.arange(len(self.label_encoder.classes_))
            metrics['top_3_accuracy'] = top_k_accuracy_score(
                y_true,
                y_proba,
                k=min(3, len(self.label_encoder.classes_)),
                labels=labels,
            )
        else:
            metrics['top_3_accuracy'] = None

        return metrics

    def _auc_score(self, y_true: np.ndarray, y_proba: np.ndarray) -> float:
        """Compute binary or multiclass AUC when probability outputs are available."""
        if y_proba is None:
            return None

        class_count = len(self.label_encoder.classes_)
        try:
            if class_count > 2:
                return float(roc_auc_score(
                    y_true,
                    y_proba,
                    average='macro',
                    multi_class='ovr',
                    labels=np.arange(class_count),
                ))
            if class_count == 2:
                return float(roc_auc_score(y_true, y_proba[:, 1]))
        except ValueError as exc:
            logger.warning("AUC could not be computed: %s", exc)

        return None

    def _priority_metrics(self, y_true: np.ndarray, y_pred: np.ndarray) -> Dict:
        """Measure whether predicted fix categories under/over-prioritize severity."""
        class_names = self.label_encoder.classes_
        pairs = []
        for true_idx, pred_idx in zip(y_true, y_pred):
            true_label = str(class_names[int(true_idx)])
            pred_label = str(class_names[int(pred_idx)])
            true_priority = CATEGORY_PRIORITY.get(true_label)
            pred_priority = CATEGORY_PRIORITY.get(pred_label)
            if true_priority is None or pred_priority is None:
                continue
            pairs.append((true_label, pred_label, true_priority, pred_priority))

        total = len(pairs)
        under = sum(1 for _, _, true_priority, pred_priority in pairs if pred_priority < true_priority)
        over = sum(1 for _, _, true_priority, pred_priority in pairs if pred_priority > true_priority)
        exact = sum(1 for _, _, true_priority, pred_priority in pairs if pred_priority == true_priority)

        return {
            'priority_pair_count': total,
            'under_prioritization_count': under,
            'over_prioritization_count': over,
            'priority_match_count': exact,
            'under_prioritization_rate': under / total if total else None,
            'over_prioritization_rate': over / total if total else None,
            'priority_match_rate': exact / total if total else None,
        }

    def _candidate_params(self, X_train: np.ndarray) -> List[Dict]:
        """Return conservative candidate configs tuned for small imbalanced datasets."""
        num_classes = len(self.label_encoder.classes_)
        adaptive_min_child = max(2, min(20, len(X_train) // max(num_classes * 6, 1)))
        base = LIGHTGBM_PARAMS.copy()
        base['num_class'] = num_classes
        base['metric'] = 'multi_logloss'
        base['verbosity'] = -1

        candidates = []
        for name, updates in [
            ('balanced_regularized', {
                'learning_rate': 0.03,
                'num_leaves': 15,
                'min_child_samples': adaptive_min_child,
                'feature_fraction': 0.85,
                'bagging_fraction': 0.85,
                'reg_alpha': 0.2,
                'reg_lambda': 0.4,
            }),
            ('minority_sensitive', {
                'learning_rate': 0.05,
                'num_leaves': 31,
                'min_child_samples': max(2, adaptive_min_child // 2),
                'feature_fraction': 0.9,
                'bagging_fraction': 0.9,
                'reg_alpha': 0.1,
                'reg_lambda': 0.2,
            }),
            ('simple_low_variance', {
                'learning_rate': 0.08,
                'num_leaves': 7,
                'min_child_samples': adaptive_min_child,
                'feature_fraction': 1.0,
                'bagging_fraction': 0.8,
                'reg_alpha': 0.3,
                'reg_lambda': 0.6,
            }),
            ('slow_deep_regularized', {
                'learning_rate': 0.015,
                'num_leaves': 31,
                'min_child_samples': adaptive_min_child,
                'feature_fraction': 0.9,
                'bagging_fraction': 0.9,
                'reg_alpha': 0.15,
                'reg_lambda': 0.5,
            }),
        ]:
            params = base.copy()
            params.update(updates)
            candidates.append({'name': name, 'params': params})

        return candidates
    
    def train(self, X_train: np.ndarray, X_val: np.ndarray, 
              y_train: np.ndarray, y_val: np.ndarray) -> Dict:
        """
        Train LightGBM model
        
        Returns: Training metrics
        """
        logger.info("Starting model training...")
        
        train_weights = compute_sample_weight(class_weight='balanced', y=y_train)
        val_weights = compute_sample_weight(class_weight='balanced', y=y_val)
        candidate_results = []

        for candidate in self._candidate_params(X_train):
            logger.info("Training candidate: %s", candidate['name'])
            train_data = lgb.Dataset(X_train, label=y_train, weight=train_weights)
            val_data = lgb.Dataset(X_val, label=y_val, weight=val_weights, reference=train_data)

            callbacks = [
                lgb.log_evaluation(period=TRAINING_CONFIG['verbose_eval']),
                lgb.early_stopping(stopping_rounds=TRAINING_CONFIG['early_stopping_rounds'])
            ]

            model = lgb.train(
                candidate['params'],
                train_data,
                num_boost_round=TRAINING_CONFIG['num_boost_round'],
                valid_sets=[train_data, val_data],
                valid_names=['train', 'val'],
                callbacks=callbacks
            )

            y_val_proba = model.predict(X_val, num_iteration=model.best_iteration)
            y_val_pred = np.argmax(y_val_proba, axis=1)
            summary = self._metric_summary(y_val, y_val_pred, y_val_proba)
            candidate_results.append({
                'name': candidate['name'],
                'model': model,
                'params': candidate['params'],
                'best_iteration': int(model.best_iteration or TRAINING_CONFIG['num_boost_round']),
                'validation_metrics': summary,
            })
            logger.info(
                "Candidate %s validation macro-F1=%.4f balanced-accuracy=%.4f accuracy=%.4f",
                candidate['name'],
                summary['macro_f1'],
                summary['balanced_accuracy'],
                summary['accuracy'],
            )

        best = max(
            candidate_results,
            key=lambda item: (
                item['validation_metrics']['macro_f1'],
                item['validation_metrics']['balanced_accuracy'],
                item['validation_metrics']['accuracy'],
            )
        )
        self.model = best['model']
        self.selected_params = best['params']
        self.selected_candidate = best['name']

        logger.info(
            "Selected candidate %s. Best iteration: %s",
            self.selected_candidate,
            self.model.best_iteration,
        )
        
        # Generate classification report
        class_names = self.label_encoder.classes_
        all_labels = np.arange(len(class_names))
        y_val_proba = self.model.predict(X_val, num_iteration=self.model.best_iteration)
        y_val_pred_class = np.argmax(y_val_proba, axis=1)
        report = classification_report(
            y_val, y_val_pred_class,
            labels=all_labels,
            target_names=class_names,
            output_dict=True,
            zero_division=0
        )
        
        metrics = {
            'validation_accuracy': best['validation_metrics']['accuracy'],
            'validation_metrics': best['validation_metrics'],
            'best_iteration': self.model.best_iteration,
            'num_classes': len(class_names),
            'class_names': class_names.tolist(),
            'classification_report': report,
            'selected_candidate': self.selected_candidate,
            'selected_params': self.selected_params,
            'candidate_results': [
                {
                    'name': item['name'],
                    'best_iteration': item['best_iteration'],
                    'validation_metrics': item['validation_metrics'],
                }
                for item in candidate_results
            ],
            'dataset_info': self.dataset_info,
        }
        
        return metrics
    
    def evaluate(self) -> Dict:
        """Evaluate model on test set"""
        if self.model is None:
            raise ValueError("Model not trained yet")
        
        logger.info("Evaluating model on test set...")
        
        y_test_proba = self.model.predict(self.X_test, num_iteration=self.model.best_iteration)
        y_test_pred_class = np.argmax(y_test_proba, axis=1)
        
        test_accuracy = accuracy_score(self.y_test, y_test_pred_class)
        logger.info(f"Test accuracy: {test_accuracy:.4f}")
        
        # Classification report
        class_names = self.label_encoder.classes_
        all_labels = np.arange(len(class_names))
        report = classification_report(
            self.y_test, y_test_pred_class,
            labels=all_labels,
            target_names=class_names,
            output_dict=True,
            zero_division=0
        )
        
        # Confusion matrix
        conf_matrix = confusion_matrix(self.y_test, y_test_pred_class, labels=all_labels)
        test_metric_summary = self._metric_summary(self.y_test, y_test_pred_class, y_test_proba)
        test_metric_summary['auc'] = self._auc_score(self.y_test, y_test_proba)
        priority_metrics = self._priority_metrics(self.y_test, y_test_pred_class)
        test_labels = class_names[self.y_test].tolist()
        predicted_labels = class_names[y_test_pred_class].tolist()
        
        return {
            'test_accuracy': test_accuracy,
            'test_metrics': test_metric_summary,
            'classification_report': report,
            'confusion_matrix': conf_matrix.tolist(),
            'confusion_matrix_labels': class_names.tolist(),
            'auc': test_metric_summary['auc'],
            'prioritization_metrics': priority_metrics,
            'test_predictions': [
                {
                    'index': int(index),
                    'true_label': str(true_label),
                    'predicted_label': str(predicted_label),
                    'true_priority': CATEGORY_PRIORITY.get(str(true_label)),
                    'predicted_priority': CATEGORY_PRIORITY.get(str(predicted_label)),
                    'probabilities': {
                        str(label): float(probability)
                        for label, probability in zip(class_names, y_test_proba[index])
                    },
                }
                for index, (true_label, predicted_label) in enumerate(zip(test_labels, predicted_labels))
            ],
        }
    
    def get_feature_importance(self) -> pd.DataFrame:
        """Get feature importance from trained model"""
        if self.model is None:
            raise ValueError("Model not trained yet")
        
        importance = self.model.feature_importance(importance_type='gain')
        feature_importance_df = pd.DataFrame({
            'feature': self.feature_columns,
            'importance': importance
        }).sort_values('importance', ascending=False)
        
        return feature_importance_df
    
    def save(self):
        """Save model and preprocessors"""
        os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
        
        # Save LightGBM model
        self.model.save_model(MODEL_PATH)
        logger.info(f"Model saved to {MODEL_PATH}")
        
        # Save label encoder
        joblib.dump(self.label_encoder, LABEL_ENCODER_PATH)
        logger.info(f"Label encoder saved to {LABEL_ENCODER_PATH}")
        
        # Save feature scaler
        joblib.dump(self.feature_scaler, FEATURE_SCALER_PATH)
        logger.info(f"Feature scaler saved to {FEATURE_SCALER_PATH}")
    
    def save_metrics(self, train_metrics: Dict, test_metrics: Dict):
        """Save training metrics to JSON"""
        metrics = {
            'train_metrics': train_metrics,
            'test_metrics': test_metrics,
            'dataset_info': self.dataset_info,
            'feature_importance': self.get_feature_importance().to_dict('records')
        }
        
        with open(METRICS_PATH, 'w') as f:
            json.dump(metrics, f, indent=2)
        logger.info(f"Metrics saved to {METRICS_PATH}")


def train_model(data_path: str) -> ModelTrainer:
    """
    Main training function
    
    Args:
        data_path: Path to CSV file with extracted features
        
    Returns:
        Trained ModelTrainer instance
    """
    logger.info(f"Loading data from {data_path}")
    df = pd.read_csv(data_path)
    logger.info(f"Loaded {len(df)} samples")
    
    # Initialize trainer
    trainer = ModelTrainer()
    
    # Prepare data
    X_train, X_val, y_train, y_val = trainer.prepare_data(df)
    trainer.dataset_info['data_path'] = data_path
    
    # Train model
    train_metrics = trainer.train(X_train, X_val, y_train, y_val)
    
    # Evaluate on test set
    test_metrics = trainer.evaluate()
    
    # Print results
    print("\n" + "="*60)
    print("TRAINING RESULTS")
    print("="*60)
    print(f"Validation Accuracy: {train_metrics['validation_accuracy']:.4f}")
    print(f"Test Accuracy: {test_metrics['test_accuracy']:.4f}")
    print(f"Validation Macro-F1: {train_metrics['validation_metrics']['macro_f1']:.4f}")
    print(f"Test Macro-F1: {test_metrics['test_metrics']['macro_f1']:.4f}")
    print(f"Selected Candidate: {train_metrics['selected_candidate']}")
    print(f"Best Iteration: {train_metrics['best_iteration']}")
    print("\nTop 10 Important Features:")
    feature_importance = trainer.get_feature_importance()
    print(feature_importance.head(10).to_string(index=False))
    print("="*60 + "\n")
    
    # Save model and metrics
    trainer.save()
    trainer.save_metrics(train_metrics, test_metrics)
    
    logger.info("Training complete!")
    return trainer


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    parser = argparse.ArgumentParser(description="Train the LightGBM fix suggestion model")
    parser.add_argument(
        "data_path",
        nargs="?",
        default=os.getenv("ML_TRAINING_DATA_PATH", "data/security_scan_dataset.csv"),
        help="CSV dataset path to train from",
    )
    args = parser.parse_args()

    # Train model
    data_path = args.data_path
    if os.path.exists(data_path):
        trainer = train_model(data_path)
    else:
        logger.error(f"Data file not found: {data_path}")
        logger.info("Run data extraction first or specify correct path")
