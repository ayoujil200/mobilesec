"""
Model Configuration for LightGBM Classifier
"""

import os


def _env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


# LightGBM Model Parameters
LIGHTGBM_PARAMS = {
    'objective': 'multiclass',
    'metric': 'multi_logloss',
    'boosting_type': 'gbdt',
    'num_leaves': 31,
    'learning_rate': 0.05,
    'feature_fraction': 0.9,
    'bagging_fraction': 0.8,
    'bagging_freq': 5,
    'verbose': -1,
    'min_child_samples': 20,
    'max_depth': -1,
    'reg_alpha': 0.1,
    'reg_lambda': 0.1,
}

# Training Parameters
TRAINING_CONFIG = {
    'num_boost_round': _env_int('LIGHTGBM_NUM_BOOST_ROUND', 3000),
    'early_stopping_rounds': _env_int('LIGHTGBM_EARLY_STOPPING_ROUNDS', 150),
    'test_size': 0.15,
    'validation_size': 0.15,
    'random_state': 42,
    'verbose_eval': _env_int('LIGHTGBM_VERBOSE_EVAL', 100),
}

# Feature Engineering
FEATURE_COLUMNS = [
    # Crypto features
    'crypto_total_vulns', 'crypto_high', 'crypto_medium', 'crypto_low', 'crypto_info',
    'crypto_weak_cipher', 'crypto_weak_hash', 'crypto_insecure_random', 'crypto_weak_rsa',
    'crypto_unique_cwes',
    
    # Secret features
    'secrets_count', 'secrets_api_keys', 'secrets_passwords', 'secrets_tokens',
    'secrets_aws_keys', 'secrets_other', 'secrets_unique_types',
    
    # Network features
    'network_findings', 'network_endpoints', 'network_http_issues',
    'network_cert_issues', 'network_domain_issues',
    
    # Aggregated features
    'total_vulnerabilities', 'severity_score',
]

TARGET_COLUMN = 'fix_category'

# Model Output
MODEL_PATH = 'models/lightgbm_model.txt'
LABEL_ENCODER_PATH = 'models/label_encoder.pkl'
FEATURE_SCALER_PATH = 'models/feature_scaler.pkl'
METRICS_PATH = 'models/training_metrics.json'

# Optuna Hyperparameter Tuning
OPTUNA_CONFIG = {
    'n_trials': 50,
    'timeout': 3600,  # 1 hour
    'study_name': 'lightgbm_optimization',
}

# Fix Suggestion Mapping
FIX_SUGGESTION_TEMPLATES = {
    'FIX_WEAK_CIPHER': {
        'title': 'Upgrade to Strong Encryption Algorithms',
        'description': 'Replace weak ciphers (DES, RC4) with AES-256 or ChaCha20.',
        'priority': 'HIGH',
        'code_example': '''// Replace DES with AES
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
cipher.init(Cipher.ENCRYPT_MODE, keySpec);'''
    },
    'FIX_WEAK_HASH': {
        'title': 'Use Strong Hashing Algorithms',
        'description': 'Replace MD5/SHA-1 with SHA-256 or SHA-3.',
        'priority': 'HIGH',
        'code_example': '''// Replace MD5 with SHA-256
MessageDigest digest = MessageDigest.getInstance("SHA-256");
byte[] hash = digest.digest(input.getBytes());'''
    },
    'FIX_INSECURE_RANDOM': {
        'title': 'Use Cryptographically Secure Random Generator',
        'description': 'Replace java.util.Random with SecureRandom.',
        'priority': 'MEDIUM',
        'code_example': '''// Use SecureRandom
SecureRandom secureRandom = new SecureRandom();
byte[] randomBytes = new byte[16];
secureRandom.nextBytes(randomBytes);'''
    },
    'FIX_WEAK_RSA_KEY': {
        'title': 'Increase RSA Key Size',
        'description': 'Use at least 2048-bit RSA keys (4096-bit recommended).',
        'priority': 'HIGH',
        'code_example': '''// Generate strong RSA keys
KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
keyGen.initialize(4096);
KeyPair keyPair = keyGen.generateKeyPair();'''
    },
    'FIX_EXPOSED_API_KEY': {
        'title': 'Remove Hardcoded API Keys',
        'description': 'Store API keys in environment variables or secure vaults.',
        'priority': 'CRITICAL',
        'code_example': '''// Use environment variables
String apiKey = System.getenv("API_KEY");
// Or use Android Keystore for mobile apps'''
    },
    'FIX_HARDCODED_PASSWORD': {
        'title': 'Remove Hardcoded Passwords',
        'description': 'Never hardcode passwords. Use secure credential management.',
        'priority': 'CRITICAL',
        'code_example': '''// Store credentials securely
// Use Android Keystore, AWS Secrets Manager, or similar'''
    },
    'FIX_EXPOSED_SECRET': {
        'title': 'Secure Sensitive Data',
        'description': 'Remove hardcoded secrets and use secure storage mechanisms.',
        'priority': 'HIGH',
        'code_example': '''// Encrypt sensitive data before storage
// Use platform-specific secure storage (Keystore, Keychain, etc.)'''
    },
    'FIX_INSECURE_HTTP': {
        'title': 'Enforce HTTPS',
        'description': 'Always use HTTPS instead of HTTP for network communication.',
        'priority': 'HIGH',
        'code_example': '''// Enforce HTTPS URLs
String secureUrl = "https://api.example.com/data";
// Configure Network Security Config for Android'''
    },
    'FIX_CERTIFICATE_ISSUE': {
        'title': 'Fix SSL/TLS Certificate Validation',
        'description': 'Properly validate SSL certificates and avoid trust-all approaches.',
        'priority': 'HIGH',
        'code_example': '''// Enable proper certificate validation
// Remove custom TrustManagers that bypass validation'''
    },
    'FIX_CRYPTO_MEDIUM': {
        'title': 'Address Medium Severity Crypto Issues',
        'description': 'Review and fix medium severity cryptographic vulnerabilities.',
        'priority': 'MEDIUM',
        'code_example': '// Refer to specific vulnerability details for targeted fixes'
    },
    'FIX_CRYPTO_GENERAL': {
        'title': 'Improve Cryptographic Implementation',
        'description': 'Review and strengthen overall cryptographic practices.',
        'priority': 'MEDIUM',
        'code_example': '// Follow OWASP cryptographic guidelines'
    },
    'NO_CRITICAL_ISSUES': {
        'title': 'No Critical Issues Found',
        'description': 'No critical security issues detected. Continue monitoring.',
        'priority': 'INFO',
        'code_example': ''
    },
    'NO_SUGGESTION': {
        'title': 'Manual Review Required',
        'description': 'Unable to generate automatic suggestion. Manual security review recommended.',
        'priority': 'LOW',
        'code_example': ''
    },
    'GENERAL': {
        'title': 'General Security Improvements',
        'description': 'Review and apply security best practices.',
        'priority': 'MEDIUM',
        'code_example': '// Follow OWASP Mobile Security guidelines'
    },
}
