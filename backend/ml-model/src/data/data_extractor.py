"""
Data Extractor for ML Model
Extracts security vulnerability data from MongoDB collections
"""

import argparse
import json
import logging
import pandas as pd
from typing import List, Dict, Optional
from ..utils.mongodb_client import mongodb_client

logger = logging.getLogger(__name__)


class DataExtractor:
    """Extract and prepare security scan data for ML training"""

    CATEGORY_PRIORITY = {
        'FIX_HARDCODED_PASSWORD': 100,
        'FIX_EXPOSED_API_KEY': 100,
        'FIX_EXPOSED_SECRET': 95,
        'FIX_CERTIFICATE_ISSUE': 95,
        'FIX_WEAK_CIPHER': 90,
        'FIX_WEAK_HASH': 80,
        'FIX_INSECURE_RANDOM': 75,
        'FIX_WEAK_RSA_KEY': 75,
        'FIX_INSECURE_HTTP': 70,
        'FIX_CRYPTO_MEDIUM': 50,
        'FIX_CRYPTO_GENERAL': 40,
        'NO_CRITICAL_ISSUES': 0,
        'NO_SUGGESTION': 0,
    }
    
    def __init__(self):
        self.client = mongodb_client
        
    def connect(self) -> bool:
        """Connect to MongoDB"""
        return self.client.connect()
    
    def disconnect(self):
        """Disconnect from MongoDB"""
        self.client.disconnect()
    
    def extract_all_data(self, limit: Optional[int] = None) -> pd.DataFrame:
        """
        Extract all security scan data and combine into a single DataFrame
        
        Args:
            limit: Optional limit on number of scans to extract
            
        Returns:
            DataFrame with combined features from all services
        """
        logger.info("Starting data extraction...")
        
        if not self.client.is_connected():
            logger.info("Connecting to MongoDB...")
            if not self.connect():
                raise ConnectionError("Failed to connect to MongoDB")
        
        # Get all scan IDs
        scan_ids = self.client.get_all_scan_ids()
        if limit:
            scan_ids = scan_ids[:limit]
        
        logger.info(f"Extracting data for {len(scan_ids)} scans...")
        
        # Extract data for each scan
        records = []
        for i, scan_id in enumerate(scan_ids):
            if (i + 1) % 10 == 0:
                logger.info(f"Processing scan {i+1}/{len(scan_ids)}")
            
            record = self._extract_scan_features(scan_id)
            if record:
                records.append(record)
        
        logger.info(f"Successfully extracted {len(records)} scan records")
        
        # Convert to DataFrame
        df = pd.DataFrame(records)
        return df
    
    def _extract_scan_features(self, scan_id: str) -> Optional[Dict]:
        """
        Extract features from a single scan
        
        Returns a dictionary with all features for ML training
        """
        try:
            # Get data from all collections
            combined_data = self.client.get_combined_scan_data(scan_id)
            if not combined_data:
                logger.warning(f"No data found for scan_id: {scan_id}")
                return None
            
            features = {'scan_id': scan_id}
            
            # ============ CRYPTO FEATURES ============
            crypto = combined_data.get('crypto')
            if crypto:
                features['crypto_total_vulns'] = crypto.get('total_vulnerabilities', 0)
                summary = crypto.get('summary', {})
                features['crypto_high'] = summary.get('high', 0)
                features['crypto_medium'] = summary.get('medium', 0)
                features['crypto_low'] = summary.get('low', 0)
                features['crypto_info'] = summary.get('info', 0)
                
                # CWE codes (most common ones)
                vulnerabilities = crypto.get('vulnerabilities', [])
                crypto_type_counts = self._count_crypto_categories(vulnerabilities, summary.get('by_type', {}))
                features['crypto_weak_cipher'] = crypto_type_counts.get('FIX_WEAK_CIPHER', 0)
                features['crypto_weak_hash'] = crypto_type_counts.get('FIX_WEAK_HASH', 0)
                features['crypto_insecure_random'] = crypto_type_counts.get('FIX_INSECURE_RANDOM', 0)
                features['crypto_weak_rsa'] = crypto_type_counts.get('FIX_WEAK_RSA_KEY', 0)

                cwe_counts = {}
                for vuln in vulnerabilities:
                    cwe = vuln.get('cwe', 'UNKNOWN')
                    cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1
                features['crypto_cwe_codes'] = ','.join(sorted(cwe_counts.keys()))
                features['crypto_unique_cwes'] = len(cwe_counts)
                
            else:
                # Default values if no crypto data
                features.update({
                    'crypto_total_vulns': 0, 'crypto_high': 0, 'crypto_medium': 0,
                    'crypto_low': 0, 'crypto_info': 0, 'crypto_weak_cipher': 0,
                    'crypto_weak_hash': 0, 'crypto_insecure_random': 0,
                    'crypto_weak_rsa': 0, 'crypto_cwe_codes': '', 'crypto_unique_cwes': 0
                })
            
            # ============ SECRET FEATURES ============
            secrets = combined_data.get('secrets')
            if secrets:
                features['secrets_count'] = secrets.get('secrets_count', 0)
                
                secret_items = secrets.get('secrets', [])
                secret_types = {}
                normalized_secret_categories = {}
                for secret in secret_items:
                    stype = secret.get('type', 'UNKNOWN')
                    secret_types[stype] = secret_types.get(stype, 0) + 1
                    category = self._secret_category_for_finding(secret)
                    if category:
                        normalized_secret_categories[category] = normalized_secret_categories.get(category, 0) + 1
                
                features['secrets_api_keys'] = normalized_secret_categories.get('FIX_EXPOSED_API_KEY', 0)
                features['secrets_passwords'] = normalized_secret_categories.get('FIX_HARDCODED_PASSWORD', 0)
                features['secrets_tokens'] = normalized_secret_categories.get('SECRET_TOKEN', 0)
                features['secrets_aws_keys'] = normalized_secret_categories.get('AWS_KEY', 0)
                known_secret_count = (
                    features['secrets_api_keys'] +
                    features['secrets_passwords'] +
                    features['secrets_tokens'] +
                    features['secrets_aws_keys']
                )
                features['secrets_other'] = max(features['secrets_count'] - known_secret_count, 0)
                features['secrets_unique_types'] = len(normalized_secret_categories) or len(secret_types)
                
            else:
                features.update({
                    'secrets_count': 0, 'secrets_api_keys': 0, 'secrets_passwords': 0,
                    'secrets_tokens': 0, 'secrets_aws_keys': 0, 'secrets_other': 0,
                    'secrets_unique_types': 0
                })
            
            # ============ NETWORK FEATURES ============
            network = combined_data.get('network')
            if network:
                features['network_findings'] = network.get('findings_count', 0)
                features['network_endpoints'] = network.get('endpoints_count', 0)
                
                analysis = network.get('analysis', {})
                security_issues = analysis.get('security_issues', [])
                
                # Count issue types from normalized network issue categories.
                http_count = sum(1 for issue in security_issues if self._network_category_for_issue(issue) == 'FIX_INSECURE_HTTP')
                cert_count = sum(1 for issue in security_issues if self._network_category_for_issue(issue) == 'FIX_CERTIFICATE_ISSUE')
                domain_count = sum(1 for issue in security_issues if 'DOMAIN' in issue.get('type', '').upper() or issue.get('type', '').upper() == 'INTERNAL_IP')
                
                features['network_http_issues'] = http_count
                features['network_cert_issues'] = cert_count
                features['network_domain_issues'] = domain_count
                
            else:
                features.update({
                    'network_findings': 0, 'network_endpoints': 0,
                    'network_http_issues': 0, 'network_cert_issues': 0,
                    'network_domain_issues': 0
                })
            
            # ============ AGGREGATED FEATURES ============
            features['total_vulnerabilities'] = (
                features['crypto_total_vulns'] + 
                features['secrets_count'] + 
                features['network_findings']
            )
            
            # Severity score (weighted sum)
            features['severity_score'] = (
                features['crypto_high'] * 3 +
                features['crypto_medium'] * 2 +
                features['crypto_low'] * 1 +
                features['secrets_count'] * 2.5 +  # Secrets are critical
                features['network_findings'] * 1.5
            )
            
            # ============ TRAINING LABEL ============
            # The model target is generated from raw scanner evidence first, then
            # falls back to legacy FixSuggest/rule labels only when evidence is absent.
            label = self._choose_training_label(features, combined_data)
            features.update(label)
            
            return features
            
        except Exception as e:
            logger.error(f"Error extracting features for scan {scan_id}: {e}")
            return None

    def _infer_label_from_suggestion(self, suggestion: Dict) -> Optional[str]:
        """Infer a training label from legacy FixSuggest documents."""
        text = ' '.join(
            str(suggestion.get(field, ''))
            for field in ['vulnerability_id', 'vulnerability_title', 'tool', 'titre_simple', 'explication', 'solution']
        ).upper()

        if 'WEAK_CIPHER' in text or 'DES' in text or 'RC4' in text:
            return 'FIX_WEAK_CIPHER'
        if 'WEAK_HASH' in text or 'MD5' in text or 'SHA-1' in text or 'SHA1' in text:
            return 'FIX_WEAK_HASH'
        if 'INSECURE_RANDOM' in text or 'RANDOM' in text:
            return 'FIX_INSECURE_RANDOM'
        if 'WEAK_RSA' in text or 'RSA' in text:
            return 'FIX_WEAK_RSA_KEY'
        if 'CERTIFICATE' in text or 'TLS' in text or 'SSL' in text:
            return 'FIX_CERTIFICATE_ISSUE'
        if 'INSECURE_HTTP' in text or 'HTTP' in text or 'HTTPS' in text or 'NETWORK' in text:
            return 'FIX_INSECURE_HTTP'
        if 'API_KEY' in text or 'API KEY' in text:
            return 'FIX_EXPOSED_API_KEY'
        if 'PASSWORD' in text or 'MOT DE PASSE' in text:
            return 'FIX_HARDCODED_PASSWORD'
        if 'SECRET' in text or 'TOKEN' in text or 'YARA' in text:
            return 'FIX_EXPOSED_SECRET'
        if 'CRYPTO' in text or 'CRYPTOGRAPH' in text:
            return 'FIX_CRYPTO_GENERAL'

        return None

    def _count_crypto_categories(self, vulnerabilities: List[Dict], by_type: Dict) -> Dict[str, int]:
        """Normalize CryptoCheck descriptions into ML feature categories."""
        counts = {}

        for vuln in vulnerabilities or []:
            category = self._crypto_category_for_vulnerability(vuln)
            if category:
                counts[category] = counts.get(category, 0) + 1

        # Backward compatibility with already-normalized historical documents.
        legacy_type_map = {
            'WEAK_CIPHER': 'FIX_WEAK_CIPHER',
            'WEAK_HASH': 'FIX_WEAK_HASH',
            'INSECURE_RANDOM': 'FIX_INSECURE_RANDOM',
            'WEAK_RSA_KEY': 'FIX_WEAK_RSA_KEY',
        }
        for key, value in (by_type or {}).items():
            category = legacy_type_map.get(str(key).upper())
            if category and counts.get(category, 0) == 0:
                counts[category] = int(value or 0)

        return counts

    def _crypto_category_for_vulnerability(self, vuln: Dict) -> Optional[str]:
        text = ' '.join(
            str(vuln.get(field, ''))
            for field in ['vulnerability', 'cwe', 'recommendation', 'codeSnippet']
        ).upper()

        if any(token in text for token in ['AES/ECB', ' ECB', 'DES ', 'DES/', 'RC4', 'WEAK CIPHER']):
            return 'FIX_WEAK_CIPHER'
        if any(token in text for token in ['MD5', 'SHA-1', 'SHA1', 'WEAK HASH']):
            return 'FIX_WEAK_HASH'
        if any(token in text for token in ['RANDOM INSTEAD OF SECURERANDOM', 'WEAK RANDOM', 'CWE-330', 'JAVA.UTIL.RANDOM']):
            return 'FIX_INSECURE_RANDOM'
        if any(token in text for token in ['WEAK RSA', 'RSA KEY', '1024-BIT RSA']):
            return 'FIX_WEAK_RSA_KEY'
        if 'CWE-327' in text or 'CWE-321' in text:
            return 'FIX_CRYPTO_GENERAL'
        return None

    def _secret_category_for_finding(self, secret: Dict) -> Optional[str]:
        text = ' '.join(
            str(secret.get(field, ''))
            for field in ['type', 'rule_name', 'description', 'match', 'line_content']
        ).upper()

        if any(token in text for token in ['AWS ACCESS KEY', 'AWS SECRET', 'AWS_KEY', 'AKIA']):
            return 'AWS_KEY'
        if any(token in text for token in ['PASSWORD', 'PASSWD', 'PWD']):
            return 'FIX_HARDCODED_PASSWORD'
        if any(token in text for token in ['API KEY', 'API_KEY', 'GOOGLE API', 'FIREBASE', 'STRIPE', 'SENDGRID', 'TWILIO']):
            return 'FIX_EXPOSED_API_KEY'
        if any(token in text for token in ['TOKEN', 'JWT', 'OAUTH', 'GITHUB', 'SLACK', 'BEARER']):
            return 'SECRET_TOKEN'
        if any(token in text for token in ['PRIVATE KEY', 'SECRET', 'CREDENTIAL', 'CONNECTION STRING']):
            return 'FIX_EXPOSED_SECRET'
        return None

    def _network_category_for_issue(self, issue: Dict) -> Optional[str]:
        text = ' '.join(
            str(issue.get(field, ''))
            for field in ['type', 'description', 'detail', 'recommendation']
        ).upper()

        if any(token in text for token in ['SSL_BYPASS', 'CERTIFICATE', 'TRUSTALL', 'TRUST MANAGER', 'TLS', 'HOSTNAME VERIFICATION']):
            return 'FIX_CERTIFICATE_ISSUE'
        if any(token in text for token in ['INSECURE_HTTP', 'CLEARTEXT', 'HTTP://', 'HTTP URL']):
            return 'FIX_INSECURE_HTTP'
        return None

    def _choose_training_label(self, features: Dict, combined_data: Dict) -> Dict:
        """Choose an auditable weak-supervision label for model training."""
        candidates = {}
        evidence = []

        def add_candidate(category: str, tool: str, reason: str, finding: Optional[Dict] = None):
            if not category:
                return
            priority = self.CATEGORY_PRIORITY.get(category, 0)
            candidates.setdefault(category, {'count': 0, 'score': 0})
            candidates[category]['count'] += 1
            candidates[category]['score'] += priority

            finding = finding or {}
            evidence.append({
                'category': category,
                'tool': tool,
                'reason': reason,
                'file': finding.get('file') or finding.get('file_path'),
                'line': finding.get('line') or finding.get('line_number'),
                'cwe': finding.get('cwe'),
                'severity': finding.get('severity'),
                'rule_name': finding.get('rule_name'),
            })

        crypto = combined_data.get('crypto') or {}
        for vuln in crypto.get('vulnerabilities', []) or []:
            category = self._crypto_category_for_vulnerability(vuln)
            add_candidate(category, 'CryptoCheck', vuln.get('vulnerability', 'crypto finding'), vuln)

        secrets = combined_data.get('secrets') or {}
        for secret in secrets.get('secrets', []) or []:
            category = self._secret_category_for_finding(secret)
            if category == 'AWS_KEY':
                category = 'FIX_EXPOSED_API_KEY'
            elif category == 'SECRET_TOKEN':
                category = 'FIX_EXPOSED_SECRET'
            add_candidate(category, 'SecretHunter', secret.get('rule_name') or secret.get('description', 'secret finding'), secret)

        network = combined_data.get('network') or {}
        analysis = network.get('analysis', {}) or {}
        for issue in analysis.get('security_issues', []) or []:
            category = self._network_category_for_issue(issue)
            add_candidate(category, 'NetworkInspector', issue.get('description') or issue.get('type', 'network finding'), issue)

        if candidates:
            ranked = sorted(
                candidates.items(),
                key=lambda item: (
                    item[1]['score'],
                    self.CATEGORY_PRIORITY.get(item[0], 0),
                    item[1]['count'],
                ),
                reverse=True,
            )
            fix_category, top = ranked[0]
            second_score = ranked[1][1]['score'] if len(ranked) > 1 else 0
            margin = top['score'] - second_score

            if len(ranked) == 1:
                confidence = 0.98
                review_status = 'accepted'
            elif margin >= 30:
                confidence = 0.90
                review_status = 'accepted'
            elif margin >= 15:
                confidence = 0.80
                review_status = 'accepted'
            else:
                confidence = 0.60
                review_status = 'needs_review'

            selected_evidence = [item for item in evidence if item['category'] == fix_category]
            return {
                'fix_category': fix_category,
                'has_fix_suggestion': bool(combined_data.get('fix_suggestions')),
                'label_source': 'raw_scanner_rules',
                'label_confidence': confidence,
                'label_review_status': review_status,
                'label_evidence': json.dumps(selected_evidence[:5], ensure_ascii=True),
                'candidate_fix_categories': json.dumps(
                    {category: {'count': data['count'], 'score': data['score']} for category, data in ranked},
                    ensure_ascii=True,
                ),
            }

        legacy_label = self._legacy_fixsuggest_label(combined_data)
        if legacy_label:
            return {
                'fix_category': legacy_label,
                'has_fix_suggestion': True,
                'label_source': 'legacy_fixsuggest',
                'label_confidence': 0.70,
                'label_review_status': 'needs_review',
                'label_evidence': json.dumps([{'tool': 'FixSuggest', 'reason': 'legacy suggestion text'}], ensure_ascii=True),
                'candidate_fix_categories': json.dumps({legacy_label: {'count': 1, 'score': self.CATEGORY_PRIORITY.get(legacy_label, 0)}}, ensure_ascii=True),
            }

        fallback = self._rule_based_label(features)
        confidence = 1.0 if fallback == 'NO_CRITICAL_ISSUES' and features.get('total_vulnerabilities', 0) == 0 else 0.55
        return {
            'fix_category': fallback,
            'has_fix_suggestion': False,
            'label_source': 'aggregate_feature_fallback',
            'label_confidence': confidence,
            'label_review_status': 'accepted' if confidence >= 0.75 else 'needs_review',
            'label_evidence': json.dumps([], ensure_ascii=True),
            'candidate_fix_categories': json.dumps({fallback: {'count': 1, 'score': self.CATEGORY_PRIORITY.get(fallback, 0)}}, ensure_ascii=True),
        }

    def _legacy_fixsuggest_label(self, combined_data: Dict) -> Optional[str]:
        fix_suggestions = combined_data.get('fix_suggestions')
        if not fix_suggestions:
            return None

        suggestions = fix_suggestions.get('suggestions', [])
        if not suggestions:
            return None

        primary = suggestions[0]
        return primary.get('category') or self._infer_label_from_suggestion(primary)
    
    def _rule_based_label(self, features: Dict) -> str:
        """
        Create a label based on vulnerability patterns when no AI suggestion exists
        
        Returns a fix category string
        """
        # Priority-based labeling
        if features['crypto_high'] > 0:
            if features['crypto_weak_cipher'] > 0:
                return 'FIX_WEAK_CIPHER'
            elif features['crypto_weak_hash'] > 0:
                return 'FIX_WEAK_HASH'
            elif features['crypto_insecure_random'] > 0:
                return 'FIX_INSECURE_RANDOM'
            else:
                return 'FIX_CRYPTO_GENERAL'
        
        if features['secrets_count'] > 0:
            if features['secrets_api_keys'] > 0:
                return 'FIX_EXPOSED_API_KEY'
            elif features['secrets_passwords'] > 0:
                return 'FIX_HARDCODED_PASSWORD'
            else:
                return 'FIX_EXPOSED_SECRET'
        
        if features['network_http_issues'] > 0:
            return 'FIX_INSECURE_HTTP'
        
        if features['network_cert_issues'] > 0:
            return 'FIX_CERTIFICATE_ISSUE'
        
        if features['crypto_medium'] > 0:
            return 'FIX_CRYPTO_MEDIUM'
        
        return 'NO_CRITICAL_ISSUES'
    
    def get_statistics(self) -> Dict:
        """Get data statistics"""
        return self.client.get_statistics()


# Example usage
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract MobileSec scan features from MongoDB.")
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Optional maximum number of scan IDs to extract. Defaults to all scans.",
    )
    parser.add_argument(
        "--output",
        default="data/extracted_data.csv",
        help="CSV output path.",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    
    extractor = DataExtractor()
    
    try:
        # Get statistics
        stats = extractor.get_statistics()
        print(f"Database statistics: {stats}")
        
        # Extract data
        df = extractor.extract_all_data(limit=args.limit)
        print(f"\nExtracted DataFrame shape: {df.shape}")
        print(f"\nColumns: {df.columns.tolist()}")
        print(f"\nFirst few rows:\n{df.head()}")
        
        # Save to CSV
        output_path = args.output
        df.to_csv(output_path, index=False)
        print(f"\nData saved to {output_path}")
        
    finally:
        extractor.disconnect()
