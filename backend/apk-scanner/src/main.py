"""
APKScanner - Microservice Flask pour l'analyse de sécurité des APK Android

Ce service permet de :
- Désassembler un fichier APK
- Analyser le manifest, les permissions, les composants exportés
- Extraire les endpoints réseau
- Détecter les configurations non sécurisées
- Stocker les résultats dans MongoDB
- Notifier les autres microservices (SecretHunter, CryptoCheck, NetworkInspector)
- Produire un rapport JSON détaillé

API Documentation: /swagger/
"""
import os
import os
import sys
import uuid
import logging
import hashlib
import requests
import threading
import json
try:
    from confluent_kafka import Consumer, Producer
except ImportError:
    Consumer = None
    Producer = None

# Global Producer instance
producer_instance = None

def get_kafka_producer():
    global producer_instance
    if producer_instance is None:
        if Producer is None:
            return None
        conf = {'bootstrap.servers': os.getenv('KAFKA_BROKERS', 'kafka:9092')}
        producer_instance = Producer(conf)
    return producer_instance

def produce_scan_event(scan_id, apk_path):
    p = get_kafka_producer()
    if not p:
        logger.warning("Kafka Producer not available, skipping event production")
        return
    
    topic = 'scan-requests'
    # Use relative path for network-inspector to resolve via shared volume
    # apk-scanner stores in /app/uploads/filename.apk
    # network-inspector mounts it at /app/shared_uploads/filename.apk
    filename = os.path.basename(apk_path)
    
    message = {
        'id': scan_id,
        'apk_path': filename, # Send filename only, let consumer resolve path
        'timestamp': datetime.utcnow().isoformat()
    }
    
    try:
        print(f"Producing message to {topic}...", flush=True)
        p.produce(topic, json.dumps(message).encode('utf-8'))
        p.flush()
        print(f"Message produced to {topic}!", flush=True)
        logger.info(f"✅ Produced Kafka event to {topic}: {message}")
    except Exception as e:
        print(f"Failed to produce message: {e}", flush=True)
        logger.error(f"❌ Failed to produce Kafka event: {e}")

# ...existing code...

from datetime import datetime

# --- Kafka consumer for orchestration ---
def kafka_consumer_thread():
    if Consumer is None:
        print("confluent_kafka n'est pas installé. Kafka consumer désactivé.")
        return
    conf = {
        'bootstrap.servers': os.getenv('KAFKA_BROKERS', 'kafka:9092'),
        'group.id': 'apk-scanner-group',
        'auto.offset.reset': 'earliest'
    }
    consumer = Consumer(conf)
    consumer.subscribe(['scan-requests'])
    while True:
        msg = consumer.poll(1.0)
        if msg is None:
            continue
        if msg.error():
            print(f"Kafka error: {msg.error()}")
            continue
        data = json.loads(msg.value().decode('utf-8'))
        scan_id = data.get('id')
        if scan_id:
            print(f"[Kafka] Received scan request for scan_id: {scan_id}")
            # TODO: Appeler ici perform_complete_scan(scan_id, apk_path) ou logique adaptée

# Démarre le consommateur dans un thread séparé
threading.Thread(target=kafka_consumer_thread, daemon=True).start()
from pathlib import Path
from flask import Flask, request, jsonify
from flask_cors import CORS
from flasgger import Swagger, swag_from
from werkzeug.utils import secure_filename

# Ajouter le répertoire parent au PYTHONPATH
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.manifest_parser import ManifestParser
from utils.permissions_analyzer import PermissionsAnalyzer
from utils.androguard_wrapper import AndroguardWrapper
from database.mongodb_client import mongodb_client

# Configuration
UPLOAD_FOLDER = 'uploads'
OUTPUT_FOLDER = 'output'
DECOMPILED_FOLDER = os.getenv('DECOMPILED_FOLDER', '/app/decompiled')
ALLOWED_EXTENSIONS = {'apk', 'aab'}
MAX_FILE_SIZE = 500 * 1024 * 1024  # 500 MB

# Créer les dossiers nécessaires
Path(UPLOAD_FOLDER).mkdir(exist_ok=True)
Path(OUTPUT_FOLDER).mkdir(exist_ok=True)
Path(DECOMPILED_FOLDER).mkdir(exist_ok=True)
Path('logs').mkdir(exist_ok=True)

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/apk_scanner.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Initialisation Flask
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE
CORS(app)

@app.before_request
def log_request_info():
    if request.path == '/api/scan' and request.method == 'POST':
        cl = request.content_length
        logger.info(f"Incoming POST /api/scan. Content-Length: {cl}")
        logger.info(f"App Config MAX_CONTENT_LENGTH: {app.config['MAX_CONTENT_LENGTH']}")


# Configuration Swagger
swagger_config = {
    "headers": [],
    "specs": [
        {
            "endpoint": 'apispec',
            "route": '/apispec.json',
            "rule_filter": lambda rule: True,
            "model_filter": lambda tag: True,
        }
    ],
    "static_url_path": "/flasgger_static",
    "swagger_ui": True,
    "specs_route": "/swagger/"
}

swagger_template = {
    "info": {
        "title": "APK-Scanner API",
        "description": "API pour l'analyse de sécurité des fichiers APK Android. Stocke les résultats dans MongoDB et notifie SecretHunter, CryptoCheck et NetworkInspector.",
        "version": "2.0.0",
        "contact": {"name": "Security Platform Team"}
    },
    "basePath": "/",
    "schemes": ["http", "https"],
    "tags": [
        {"name": "Health", "description": "Endpoints de santé"},
        {"name": "Scan", "description": "Endpoints de scan APK"},
        {"name": "Results", "description": "Endpoints de résultats"},
        {"name": "Statistics", "description": "Endpoints de statistiques"}
    ]
}

swagger = Swagger(app, config=swagger_config, template=swagger_template)


def allowed_file(filename):
    """Vérifie si l'extension du fichier est autorisée"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def calculate_file_hash(filepath):
    """Calcule le hash SHA256 d'un fichier"""
    hash_sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()


def generate_scan_id():
    """Génère un ID de scan unique"""
    return str(uuid.uuid4())


def notify_microservices(scan_id: str):
    """
    Notifie les autres microservices qu'un APK a été analysé.
    Ils peuvent maintenant lire les résultats depuis MongoDB.
    """
    services = [
        (os.getenv('SECRET_HUNTER_URL', 'http://secret-hunter:5002'), '/api/analyze'),
        (os.getenv('CRYPTO_CHECK_URL', 'http://crypto-check:8080'), '/api/analyze'),
        (os.getenv('NETWORK_INSPECTOR_URL', 'http://network-inspector:5001'), '/api/analyze')
    ]
    
    results = {}
    for base_url, endpoint in services:
        service_name = base_url.split('//')[1].split(':')[0]
        try:
            response = requests.post(
                f"{base_url}{endpoint}",
                json={"scan_id": scan_id},
                timeout=10
            )
            results[service_name] = {
                "status": "notified" if response.status_code in [200, 202] else "failed",
                "http_code": response.status_code
            }
            logger.info(f"✅ Notified {service_name}: {response.status_code}")
        except Exception as e:
            results[service_name] = {"status": "failed", "error": str(e)}
            logger.warning(f"⚠️ Failed to notify {service_name}: {e}")
    
    return results


def perform_complete_scan(scan_id: str, apk_path: str):
    """
    Effectue un scan complet d'un APK et stocke les résultats dans MongoDB.
    Notifie ensuite SecretHunter, CryptoCheck et NetworkInspector.
    
    Args:
        scan_id (str): ID unique du scan
        apk_path (str): Chemin vers le fichier APK
        
    Returns:
        dict: Résultats complets du scan
    """
    logger.info(f"Starting complete scan for: {apk_path} (scan_id: {scan_id})")
    
    # Mettre à jour le statut dans MongoDB
    mongodb_client.update_scan_status(scan_id, 'apk_scanner', 'in_progress')
    
    results = {
        'scan_id': scan_id,
        'scan_timestamp': datetime.utcnow().isoformat(),
        'apk_path': apk_path,
        'apk_name': os.path.basename(apk_path),
        'file_hash': calculate_file_hash(apk_path),
        'file_size': os.path.getsize(apk_path) if os.path.exists(apk_path) else 0,
        'status': 'in_progress'
    }
    
    try:
        # 1. Analyse avec Androguard
        logger.info("Step 1: Analyzing with Androguard...")
        androguard = AndroguardWrapper(apk_path)
        androguard.load_apk()
        
        basic_info = androguard.get_basic_info()
        results.update({
            'package_name': basic_info['package_name'],
            'app_name': basic_info['app_name'],
            'version_code': basic_info['version_code'],
            'version_name': basic_info['version_name'],
            'min_sdk': basic_info['min_sdk'],
            'target_sdk': basic_info['target_sdk'],
            'main_activity': basic_info['main_activity'],
            'is_signed': basic_info['is_signed'],
            'file_count': basic_info['file_count']
        })
        
        # 2. Parser le manifest avec apktool et sauvegarder le code décompilé
        logger.info("Step 2: Parsing manifest and decompiling...")
        manifest_parser = ManifestParser(apk_path)
        
        # Créer un dossier unique pour ce scan (partagé avec les autres services)
        decompiled_path = os.path.join(DECOMPILED_FOLDER, scan_id)
        Path(decompiled_path).mkdir(exist_ok=True)
        
        try:
            manifest_parser.decompile_apk(decompiled_path)
            manifest_data = manifest_parser.parse_manifest()
            
            results.update({
                'decompiled_path': decompiled_path,
                'debuggable': manifest_data.get('debuggable', False),
                'cleartext_allowed': manifest_data.get('cleartext_allowed', False),
                'network_security_config': manifest_data.get('network_security_config')
            })
            
            # Composants exportés
            results['exported_components'] = manifest_data.get('exported_components', [])
            
            # Problèmes de sécurité du manifest
            security_issues = manifest_parser.get_security_issues(manifest_data)
            results['manifest_issues'] = security_issues
            
        except Exception as e:
            logger.warning(f"Manifest parsing failed: {e}")
            results['decompiled_path'] = None
            results['manifest_issues'] = []
            results['exported_components'] = []
        
        # 3. Analyser les permissions
        logger.info("Step 3: Analyzing permissions...")
        permissions_analyzer = PermissionsAnalyzer()
        permissions_list = basic_info.get('permissions', [])
        
        permissions_analysis = permissions_analyzer.analyze_permissions(permissions_list)
        results['permissions'] = [
            permissions_analyzer.get_permission_info(perm) 
            for perm in permissions_list
        ]
        results['permissions_analysis'] = {
            'total': permissions_analysis['total'],
            'dangerous_count': permissions_analysis['summary']['dangerous_count'],
            'normal_count': permissions_analysis['summary']['normal_count'],
            'critical_count': permissions_analysis['summary']['critical_count'],
            'risk_score': permissions_analysis['risk_score'],
            'risk_level': permissions_analysis['summary']['risk_level']
        }
        
        # Recommandations de sécurité
        recommendations = permissions_analyzer.get_security_recommendations(permissions_analysis)
        results['security_recommendations'] = recommendations
        
        # 4. Extraire les endpoints réseau
        logger.info("Step 4: Extracting network endpoints...")
        endpoints = androguard.extract_network_endpoints()
        results['endpoints'] = endpoints
        results['insecure_endpoints'] = androguard.detect_insecure_endpoints()
        
        # 5. Rechercher les secrets codés en dur
        logger.info("Step 5: Searching for hardcoded secrets...")
        api_keys = androguard.get_api_keys()
        results['potential_secrets'] = api_keys
        
        # 6. Informations sur le certificat
        logger.info("Step 6: Analyzing certificate...")
        cert_info = androguard.get_certificate_info()
        results['certificate'] = cert_info
        
        # 7. Analyse DEX
        logger.info("Step 7: Analyzing DEX files...")
        dex_stats = androguard.analyze_dex()
        results['dex_stats'] = dex_stats
        
        # 8. Calculer le score de sécurité global
        security_score = calculate_security_score(results)
        results['security_score'] = security_score
        
        # Finaliser
        results['status'] = 'completed'
        
        # 9. Sauvegarder dans MongoDB
        logger.info("Step 9: Saving results to MongoDB...")
        mongodb_client.save_apk_results(scan_id, results)
        mongodb_client.update_scan_status(scan_id, 'apk_scanner', 'completed')
        
        logger.info(f"✅ Complete scan finished for {results['package_name']}")
        
        # 10. Notifier les autres microservices (SecretHunter, CryptoCheck, NetworkInspector)
        logger.info("Step 10: Notifying other microservices...")
        notification_results = notify_microservices(scan_id)
        results['notifications'] = notification_results
        
        # 11. Kafka Event Production
        produce_scan_event(scan_id, apk_path)
        
        # NOTE: Ne PAS nettoyer les fichiers décompilés!
        # Les autres microservices (SecretHunter, CryptoCheck,        # Nettoyer le fichier uploadé
        try:
             print(f"Removing file {filepath}...", flush=True)
             os.remove(filepath)
        except Exception as e:
             print(f"Error removing file: {e}", flush=True)
             pass
        
        return results
        
    except Exception as e:
        logger.error(f"Scan failed: {e}", exc_info=True)
        print(f"CRITICAL SCAN FAILURE: {e}", flush=True) # Explicit stdout print
        results = {
            'status': 'failed',
            'error': str(e)
        }
        # Attempt to save failure status
        try:
             mongodb_client.update_scan_status(scan_id, 'apk_scanner', 'failed')
             mongodb_client.save_apk_results(scan_id, results)
        except:
             pass
        return results


def calculate_security_score(results):
    """
    Calcule un score de sécurité global (0-100)
    
    Args:
        results (dict): Résultats du scan
        
    Returns:
        dict: Score et détails
    """
    score = 100
    issues = []

    # 1) Problèmes de configuration manifeste
    if results.get('debuggable'):
        penalty = 20
        score -= penalty
        issues.append('Application is debuggable in manifest (-20)')

    if results.get('cleartext_allowed'):
        penalty = 20
        score -= penalty
        issues.append('Cleartext traffic allowed in manifest (-20)')

    # 2) Permissions (score et criticité)
    perm_analysis = results.get('permissions_analysis', {})
    perm_risk = perm_analysis.get('risk_score', 0) or 0
    perm_level = perm_analysis.get('risk_level', 'MINIMAL') or 'MINIMAL'
    critical_perms = perm_analysis.get('critical_count', 0) or 0

    perm_penalty = 0
    if perm_risk > 0:
        if perm_risk >= 80:
            perm_penalty += 25
        elif perm_risk >= 50:
            perm_penalty += 18
        elif perm_risk >= 20:
            perm_penalty += 10
        else:
            perm_penalty += 5

    if critical_perms > 0:
        perm_penalty += min(critical_perms * 2, 10)

    perm_penalty = min(perm_penalty, 35)
    if perm_penalty > 0:
        score -= perm_penalty
        issues.append(
            f"Permissions risk score: {perm_risk} (level {perm_level}, {critical_perms} critical) (-{perm_penalty})"
        )

    # 3) Endpoints réseau non sécurisés (HTTP)
    insecure_count = len(results.get('insecure_endpoints', []))
    if insecure_count > 0:
        penalty = min(5 + insecure_count * 2, 25)
        score -= penalty
        issues.append(f'{insecure_count} insecure endpoints detected (-{penalty})')

    # 4) Secrets codés en dur
    secrets_count = len(results.get('potential_secrets', []))
    if secrets_count > 0:
        penalty = min(secrets_count * 7, 35)
        score -= penalty
        issues.append(f'{secrets_count} potential hardcoded secrets (-{penalty})')

    # 5) Composants exportés
    exported_count = len(results.get('exported_components', []))
    if exported_count > 0:
        penalty = min(5 + exported_count, 30)
        score -= penalty
        issues.append(f'{exported_count} exported components in manifest (-{penalty})')

    score = max(0, min(100, score))

    # Déterminer la note (alignée avec NetworkInspector)
    if score >= 90:
        grade = 'A'
        level = 'EXCELLENT'
    elif score >= 75:
        grade = 'B'
        level = 'GOOD'
    elif score >= 60:
        grade = 'C'
        level = 'FAIR'
    elif score >= 40:
        grade = 'D'
        level = 'POOR'
    else:
        grade = 'F'
        level = 'CRITICAL'
    
    return {
        'score': score,
        'grade': grade,
        'level': level,
        'deductions': issues
    }


# ============= ROUTES API =============

@app.route('/', methods=['GET'])
def index():
    """
    Page d'accueil de l'API
    ---
    tags:
      - Health
    responses:
      200:
        description: Informations sur le service
    """
    return jsonify({
        'service': 'APK-Scanner',
        'version': '2.0.0',
        'description': 'Android APK Security Scanner with MongoDB',
        'swagger': '/swagger/',
        'mongodb_connected': mongodb_client.is_connected()
    })


@app.route('/health', methods=['GET'])
def health_check():
    """
    Vérification de santé du service
    ---
    tags:
      - Health
    responses:
      200:
        description: Statut de santé
    """
    return jsonify({
        'status': 'healthy',
        'mongodb': mongodb_client.is_connected(),
        'timestamp': datetime.utcnow().isoformat(),
        'service': 'APK-Scanner'
    })


@app.route('/api/health', methods=['GET'])
def api_health_check():
    """Alias for health check compatible with Gateway"""
    return health_check()


@app.route('/api/scan', methods=['POST'])
def scan_apk():
    """
    Scanner un fichier APK
    ---
    tags:
      - Scan
    consumes:
      - multipart/form-data
    parameters:
      - name: file
        in: formData
        type: file
        required: true
        description: Fichier APK à analyser
      - name: force
        in: query
        type: boolean
        required: false
        description: Forcer le re-scan même si déjà analysé
    responses:
      200:
        description: Résultats du scan
      400:
        description: Requête invalide
      500:
        description: Erreur serveur
    """
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'Invalid file type. Only APK and AAB files are allowed'}), 400
        
        # Générer scan_id
        scan_id = generate_scan_id()
        
        # Sauvegarder le fichier
        filename = secure_filename(file.filename)
        filename = f"{scan_id}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        file.save(filepath)
        logger.info(f"File uploaded: {filepath}")
        
        # Vérifier si déjà scanné
        file_hash = calculate_file_hash(filepath)
        existing = mongodb_client.get_apk_results_by_hash(file_hash)
        
        if existing and request.args.get('force') != 'true':
            # FOR DEBUGGING: Force re-scan even if cached to ensure Kafka messages are sent
            # and files are restored to disk for downstream consumers.
            # logger.info(f"Using cached scan for hash: {file_hash}")
            # os.remove(filepath)
            # existing['_id'] = str(existing.get('_id', ''))
            # return jsonify({
            #     'cached': True,
            #     'message': 'Using cached scan results',
            #     'scan_id': existing.get('scan_id'),
            #     'results': existing.get('results')
            # })
            pass
        
        # Créer l'entrée de scan dans MongoDB
        mongodb_client.create_scan({
            'scan_id': scan_id,
            'app_name': filename,
            'status': 'pending',
            'stages': {
                'apk_scanner': 'pending',
                'secret_hunter': 'pending',
                'crypto_check': 'pending',
                'network_inspector': 'pending',
                'report_gen': 'pending'
            }
        })
        
        # Effectuer le scan
        results = perform_complete_scan(scan_id, filepath)
        
        # Nettoyer le fichier uploadé
        # COMMENTED OUT FOR DEBUGGING/SHARED ACCESS: NetworkInspector needs this file!
        try:
            # os.remove(filepath)
            pass
        except Exception:
            pass
        
        return jsonify(results)
        
    except Exception as e:
        logger.error(f"Error in scan endpoint: {e}", exc_info=True)
        return jsonify({'error': 'Internal server error', 'message': str(e)}), 500


@app.route('/api/analyze', methods=['POST'])
def analyze_from_scan_id():
    """
    Analyser un APK à partir d'un scan_id existant (appelé par CI-Connector)
    ---
    tags:
      - Scan
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required:
            - scan_id
            - apk_path
          properties:
            scan_id:
              type: string
              description: ID du scan
            apk_path:
              type: string
              description: Chemin vers l'APK
    responses:
      200:
        description: Analyse démarrée
      400:
        description: Paramètres manquants
    """
    try:
        data = request.get_json()
        scan_id = data.get('scan_id')
        apk_path = data.get('apk_path')
        
        if not scan_id:
            return jsonify({'error': 'scan_id is required'}), 400
        
        if not apk_path or not os.path.exists(apk_path):
            return jsonify({'error': 'Valid apk_path is required'}), 400
        
        # Effectuer le scan
        results = perform_complete_scan(scan_id, apk_path)
        
        return jsonify({
            'status': 'success',
            'scan_id': scan_id,
            'message': 'Analysis completed and stored in MongoDB'
        })
        
    except Exception as e:
        logger.error(f"Error in analyze endpoint: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500


@app.route('/api/results/<scan_id>', methods=['GET'])
def get_results(scan_id):
    """
    Récupérer les résultats d'un scan par ID
    ---
    tags:
      - Results
    parameters:
      - name: scan_id
        in: path
        type: string
        required: true
        description: ID du scan
    responses:
      200:
        description: Résultats du scan
      404:
        description: Scan non trouvé
    """
    try:
        results = mongodb_client.get_apk_results(scan_id)
        
        if not results:
            return jsonify({'error': 'Scan not found'}), 404
        
        results['_id'] = str(results.get('_id', ''))
        return jsonify(results)
        
    except Exception as e:
        logger.error(f"Error getting results: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/results', methods=['GET'])
def list_results():
    """
    Lister tous les résultats de scan
    ---
    tags:
      - Results
    parameters:
      - name: limit
        in: query
        type: integer
        required: false
        default: 100
        description: Nombre maximum de résultats
    responses:
      200:
        description: Liste des résultats
    """
    try:
        limit = request.args.get('limit', 100, type=int)
        results = mongodb_client.get_all_apk_results(limit)
        
        for r in results:
            r['_id'] = str(r.get('_id', ''))
        
        return jsonify({'count': len(results), 'results': results})
        
    except Exception as e:
        logger.error(f"Error listing results: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/results/<scan_id>', methods=['DELETE'])
def delete_results(scan_id):
    """
    Supprimer les résultats d'un scan
    ---
    tags:
      - Results
    parameters:
      - name: scan_id
        in: path
        type: string
        required: true
        description: ID du scan à supprimer
    responses:
      200:
        description: Scan supprimé
      404:
        description: Scan non trouvé
    """
    try:
        deleted = mongodb_client.delete_apk_results(scan_id)
        
        if deleted:
            return jsonify({'message': 'Scan deleted successfully', 'scan_id': scan_id})
        else:
            return jsonify({'error': 'Scan not found'}), 404
            
    except Exception as e:
        logger.error(f"Error deleting scan: {e}")
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/stats', methods=['GET'])
def get_stats():
    """
    Récupérer les statistiques des scans
    ---
    tags:
      - Statistics
    responses:
      200:
        description: Statistiques des scans
    """
    try:
        stats = mongodb_client.get_statistics()
        return jsonify(stats)
        
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        return jsonify({'error': 'Internal server error'}), 500


# Gestion des erreurs
@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({'error': 'File too large', 'max_size': f'{MAX_FILE_SIZE // (1024*1024)} MB'}), 413


@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404


@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal error: {error}")
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    logger.info("Starting APK-Scanner service...")
    
    # Connexion à MongoDB
    if not mongodb_client.connect():
        logger.warning("MongoDB connection failed, will retry on first request")
    
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('DEBUG', 'False').lower() == 'true'
    
    logger.info(f"Server starting on port {port}")
    logger.info(f"Swagger UI: http://localhost:{port}/swagger/")
    
    app.run(host='0.0.0.0', port=port, debug=debug)
