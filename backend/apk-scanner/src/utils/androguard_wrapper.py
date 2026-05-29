"""
Module wrapper pour Androguard - Analyse statique des APK
"""
import logging
import re
from androguard.core.bytecodes.apk import APK
from androguard.core.bytecodes.dvm import DalvikVMFormat
from androguard.core.analysis.analysis import Analysis

logger = logging.getLogger(__name__)


class AndroguardWrapper:
    """Classe wrapper pour simplifier l'utilisation d'Androguard"""
    
    def __init__(self, apk_path):
        """
        Initialise Androguard avec un fichier APK
        
        Args:
            apk_path (str): Chemin vers le fichier APK
        """
        self.apk_path = apk_path
        self.apk = None
        self.dalvik_vm = None
        self.analysis = None
        self.endpoints = []
        self._dex_strings = None
    
    def load_apk(self):
        """
        Charge et analyse l'APK avec Androguard
        
        Returns:
            bool: True si succès
        """
        try:
            logger.info(f"Loading APK with Androguard: {self.apk_path}")
            self.apk = APK(self.apk_path)
            
            logger.info("APK loaded successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error loading APK: {e}")
            raise
    
    def get_basic_info(self):
        """
        Récupère les informations de base de l'APK
        
        Returns:
            dict: Informations de base
        """
        if not self.apk:
            raise Exception("APK not loaded. Call load_apk() first.")
        
        try:
            # Helper for safe extraction
            def safe_get(func, default=None):
                try:
                    return func()
                except Exception as e:
                    logger.warning(f"Error extracting metadata: {e}")
                    return default

            # Extraction sécurisée des champs susceptibles de planter (ressources obfusquées)
            app_name = safe_get(lambda: self.apk.get_app_name(), "Unknown App")
            package_name = safe_get(lambda: self.apk.get_package(), "unknown.package")
            
            info = {
                'package_name': package_name,
                'app_name': app_name,
                'version_code': safe_get(lambda: self.apk.get_androidversion_code(), 0),
                'version_name': safe_get(lambda: self.apk.get_androidversion_name(), "0.0"),
                'min_sdk': safe_get(lambda: self.apk.get_min_sdk_version()),
                'target_sdk': safe_get(lambda: self.apk.get_target_sdk_version()),
                'max_sdk': safe_get(lambda: self.apk.get_max_sdk_version()),
                'is_signed': safe_get(lambda: self.apk.is_signed(), False),
                'is_signed_v1': safe_get(lambda: self.apk.is_signed_v1(), False),
                'is_signed_v2': safe_get(lambda: self.apk.is_signed_v2(), False),
                'is_signed_v3': safe_get(lambda: self.apk.is_signed_v3(), False),
                'main_activity': safe_get(lambda: self.apk.get_main_activity()),
                'permissions': safe_get(lambda: self.apk.get_permissions(), []),
                'activities': safe_get(lambda: self.apk.get_activities(), []),
                'services': safe_get(lambda: self.apk.get_services(), []),
                'receivers': safe_get(lambda: self.apk.get_receivers(), []),
                'providers': safe_get(lambda: self.apk.get_providers(), []),
                'libraries': safe_get(lambda: self.apk.get_libraries(), []),
                'files': safe_get(lambda: self.apk.get_files(), []),
                'file_count': len(safe_get(lambda: self.apk.get_files(), []))
            }
            
            logger.info(f"Retrieved basic info for {info['package_name']}")
            return info
            
        except Exception as e:
            logger.error(f"Error getting basic info: {e}")
            # Ne pas relancer l'exception pour permettre au scan de continuer
            # même si les métadonnées sont incomplètes
            return {
                'package_name': 'unknown',
                'app_name': 'Scan Error',
                'error': str(e)
            }
    
    def get_certificate_info(self):
        """
        Récupère les informations du certificat
        
        Returns:
            dict: Informations du certificat
        """
        if not self.apk:
            raise Exception("APK not loaded")
        
        try:
            cert_info = {
                'certificates': [],
                'signed': self.apk.is_signed()
            }
            
            # Récupérer les certificats
            certs = self.apk.get_certificates()
            for cert in certs:
                cert_data = {
                    'subject': str(cert.subject),
                    'issuer': str(cert.issuer),
                    'serial_number': str(cert.serial_number),
                    'not_before': str(cert.not_valid_before),
                    'not_after': str(cert.not_valid_after),
                }
                cert_info['certificates'].append(cert_data)
            
            return cert_info
            
        except Exception as e:
            logger.warning(f"Error getting certificate info: {e}")
            return {'certificates': [], 'signed': False}
    
    def extract_network_endpoints(self):
        """
        Extrait les endpoints réseau du code
        
        Returns:
            list: Liste des endpoints trouvés
        """
        if not self.apk:
            raise Exception("APK not loaded")
        
        try:
            logger.info("Extracting network endpoints...")
            
            endpoints = []
            
            # Patterns pour détecter les URLs
            url_patterns = [
                r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+',
                r'wss?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+',
            ]
            
            # Rechercher dans toutes les chaînes de caractères
            for string in self._get_dex_strings():
                for pattern in url_patterns:
                    matches = re.findall(pattern, string)
                    for match in matches:
                        if match not in endpoints:
                            endpoints.append(match)
            
            # Analyser les endpoints
            analyzed_endpoints = []
            for url in endpoints:
                endpoint_info = {
                    'url': url,
                    'protocol': self._get_protocol(url),
                    'is_secure': url.startswith('https://') or url.startswith('wss://'),
                    'domain': self._extract_domain(url)
                }
                analyzed_endpoints.append(endpoint_info)
            
            logger.info(f"Found {len(analyzed_endpoints)} network endpoints")
            self.endpoints = analyzed_endpoints
            
            return analyzed_endpoints
            
        except Exception as e:
            logger.error(f"Error extracting endpoints: {e}")
            return []
    
    def _get_protocol(self, url):
        """
        Extrait le protocole d'une URL
        
        Args:
            url (str): URL
            
        Returns:
            str: Protocole
        """
        if url.startswith('https://'):
            return 'HTTPS'
        elif url.startswith('http://'):
            return 'HTTP'
        elif url.startswith('wss://'):
            return 'WSS'
        elif url.startswith('ws://'):
            return 'WS'
        else:
            return 'UNKNOWN'
    
    def _extract_domain(self, url):
        """
        Extrait le domaine d'une URL
        
        Args:
            url (str): URL
            
        Returns:
            str: Domaine
        """
        try:
            # Supprimer le protocole
            url_without_protocol = re.sub(r'^https?://', '', url)
            url_without_protocol = re.sub(r'^wss?://', '', url_without_protocol)
            
            # Extraire le domaine
            domain = url_without_protocol.split('/')[0]
            domain = domain.split(':')[0]  # Supprimer le port
            
            return domain
        except Exception:
            return 'unknown'
    
    def detect_insecure_endpoints(self):
        """
        Détecte les endpoints non sécurisés (HTTP)
        
        Returns:
            list: Liste des endpoints non sécurisés
        """
        if not self.endpoints:
            self.extract_network_endpoints()
        
        insecure = [
            endpoint for endpoint in self.endpoints 
            if not endpoint['is_secure']
        ]
        
        logger.info(f"Found {len(insecure)} insecure endpoints")
        return insecure
    
    def get_api_keys(self):
        """
        Recherche des clés API potentielles dans le code
        
        Returns:
            list: Liste des clés API potentielles
        """
        if not self.apk:
            raise Exception("APK not loaded")
        
        try:
            logger.info("Searching for API keys...")
            
            api_keys = []
            
            # Patterns pour détecter les clés API
            key_patterns = [
                (r'api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]+)["\']', 'API_KEY'),
                (r'apikey["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]+)["\']', 'API_KEY'),
                (r'access[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]+)["\']', 'ACCESS_TOKEN'),
                (r'secret[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]+)["\']', 'SECRET_KEY'),
                (r'password["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]+)["\']', 'PASSWORD'),
            ]
            
            for string in self._get_dex_strings():
                for pattern, key_type in key_patterns:
                    matches = re.findall(pattern, string.lower())
                    for match in matches:
                        if len(match) > 8:  # Ignorer les valeurs trop courtes
                            api_keys.append({
                                'type': key_type,
                                'value': match[:20] + '...' if len(match) > 20 else match,
                                'full_string': string[:100]
                            })
            
            logger.info(f"Found {len(api_keys)} potential API keys")
            return api_keys
            
        except Exception as e:
            logger.error(f"Error searching for API keys: {e}")
            return []

    def _get_dex_strings(self):
        """Return string constants from all DEX files for Androguard 3.x."""
        if self._dex_strings is not None:
            return self._dex_strings

        strings = []
        for dex_bytes in self.apk.get_all_dex():
            try:
                strings.extend(str(value) for value in DalvikVMFormat(dex_bytes).get_strings())
            except Exception as exc:
                logger.warning(f"Unable to read DEX strings: {exc}")
        self._dex_strings = strings
        return strings
    
    def get_hardcoded_secrets(self):
        """
        Recherche des secrets codés en dur
        
        Returns:
            dict: Informations sur les secrets trouvés
        """
        secrets = {
            'api_keys': self.get_api_keys(),
            'insecure_endpoints': self.detect_insecure_endpoints()
        }
        
        return secrets
    
    def analyze_dex(self):
        """
        Analyse approfondie des fichiers DEX
        
        Returns:
            dict: Statistiques sur le code
        """
        try:
            logger.info("Analyzing DEX files...")
            
            # Obtenir les fichiers DEX
            dex_files = list(self.apk.get_all_dex())
            
            stats = {
                'dex_count': len(dex_files),
                'total_methods': 0,
                'total_classes': 0,
                'total_strings': 0
            }
            
            # Compter les strings
            stats['total_strings'] = len(self._get_dex_strings())
            
            logger.info(f"DEX analysis complete: {stats}")
            return stats
            
        except Exception as e:
            logger.warning(f"Error analyzing DEX: {e}")
            return {
                'dex_count': 0,
                'total_methods': 0,
                'total_classes': 0,
                'total_strings': 0
            }
    
    def get_security_analysis(self):
        """
        Effectue une analyse de sécurité complète
        
        Returns:
            dict: Résultats de l'analyse de sécurité
        """
        analysis = {
            'insecure_endpoints': self.detect_insecure_endpoints(),
            'hardcoded_secrets': self.get_api_keys(),
            'certificate': self.get_certificate_info(),
            'issues': []
        }
        
        # Ajouter des problèmes de sécurité
        if len(analysis['insecure_endpoints']) > 0:
            analysis['issues'].append({
                'severity': 'MEDIUM',
                'type': 'insecure_communication',
                'message': f"Found {len(analysis['insecure_endpoints'])} insecure HTTP endpoints"
            })
        
        if len(analysis['hardcoded_secrets']) > 0:
            analysis['issues'].append({
                'severity': 'HIGH',
                'type': 'hardcoded_secrets',
                'message': f"Found {len(analysis['hardcoded_secrets'])} potential hardcoded secrets"
            })
        
        return analysis
