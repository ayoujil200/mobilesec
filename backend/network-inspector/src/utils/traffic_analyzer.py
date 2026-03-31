"""
Module pour analyser le trafic réseau capturé

Ce module analyse les données capturées par mitmproxy et génère des rapports :
- Analyse TLS/SSL
- Détection d'endpoints non sécurisés
- Identification de fuites de données
- Scoring de sécurité
"""
import json
import logging
from typing import Dict, List, Any
from datetime import datetime
from collections import defaultdict

logger = logging.getLogger(__name__)


class TrafficAnalyzer:
    """Analyseur de trafic réseau"""
    
    def __init__(self, capture_file='captures/traffic.json'):
        """
        Initialise l'analyseur
        
        Args:
            capture_file (str): Fichier de capture à analyser
        """
        self.capture_file = capture_file
        self.raw_data = None
        self.analysis_result = None
    
    def load_capture(self) -> bool:
        """
        Charge les données de capture
        
        Returns:
            bool: True si chargé avec succès
        """
        try:
            with open(self.capture_file, 'r') as f:
                self.raw_data = json.load(f)
            
            logger.info(f"Loaded capture file: {self.capture_file}")
            logger.info(f"Total flows: {self.raw_data.get('summary', {}).get('total_flows', 0)}")
            return True
            
        except FileNotFoundError:
            logger.error(f"Capture file not found: {self.capture_file}")
            return False
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in capture file: {e}")
            return False
        except Exception as e:
            logger.error(f"Error loading capture: {e}")
            return False
    
    def analyze(self) -> Dict[str, Any]:
        """
        Effectue une analyse complète du trafic
        
        Returns:
            dict: Résultats de l'analyse
        """
        if not self.raw_data:
            if not self.load_capture():
                return {
                    'error': 'Failed to load capture file',
                    'status': 'failed'
                }
        
        logger.info("Starting traffic analysis...")
        
        analysis = {
            'timestamp': datetime.now().isoformat(),
            'capture_summary': self.raw_data.get('summary', {}),
            'tls_analysis': self._analyze_tls(),
            'plaintext_analysis': self._analyze_plaintext(),
            'endpoints_analysis': self._analyze_endpoints(),
            'data_leaks_analysis': self._analyze_data_leaks(),
            'security_score': None,
            'recommendations': []
        }
        
        # Calculer le score de sécurité
        analysis['security_score'] = self._calculate_security_score(analysis)
        
        # Générer des recommandations
        analysis['recommendations'] = self._generate_recommendations(analysis)
        
        self.analysis_result = analysis
        
        logger.info("Traffic analysis completed")
        return analysis
    
    def _analyze_tls(self) -> Dict[str, Any]:
        """
        Analyse les problèmes TLS/SSL
        
        Returns:
            dict: Analyse TLS
        """
        tls_issues = self.raw_data.get('tls_issues', [])
        
        # Grouper les problèmes par type
        issues_by_type = defaultdict(list)
        severity_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        
        for issue in tls_issues:
            issue_type = issue.get('type', 'unknown')
            severity = issue.get('severity', 'MEDIUM').upper()
            
            issues_by_type[issue_type].append(issue)
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Analyser les versions TLS
        outdated_tls = [i for i in tls_issues if i.get('type') == 'outdated_tls_version']
        insecure_cookies = [i for i in tls_issues if i.get('type') == 'insecure_cookie']
        missing_headers = [i for i in tls_issues if i.get('type') == 'missing_security_headers']
        
        return {
            'total_issues': len(tls_issues),
            'severity_breakdown': severity_counts,
            'issues_by_type': dict(issues_by_type),
            'outdated_tls_count': len(outdated_tls),
            'insecure_cookies_count': len(insecure_cookies),
            'missing_security_headers_count': len(missing_headers),
            'critical_issues': [
                i for i in tls_issues 
                if i.get('severity') == 'HIGH'
            ][:10]  # Limiter à 10
        }
    
    def _analyze_plaintext(self) -> Dict[str, Any]:
        """
        Analyse le trafic en clair (HTTP)
        
        Returns:
            dict: Analyse du trafic non chiffré
        """
        plaintext = self.raw_data.get('plaintext_traffic', [])
        
        # Grouper par domaine
        domains = defaultdict(int)
        methods = defaultdict(int)
        
        for traffic in plaintext:
            url = traffic.get('url', '')
            method = traffic.get('method', 'GET')
            
            # Extraire le domaine
            if '://' in url:
                domain = url.split('://')[1].split('/')[0]
                domains[domain] += 1
            
            methods[method] += 1
        
        return {
            'total_plaintext_requests': len(plaintext),
            'affected_domains': len(domains),
            'domains_breakdown': dict(sorted(domains.items(), key=lambda x: x[1], reverse=True)[:10]),
            'methods_breakdown': dict(methods),
            'risk_level': self._assess_plaintext_risk(len(plaintext)),
            'sample_requests': plaintext[:5]  # 5 exemples
        }
    
    def _analyze_endpoints(self) -> Dict[str, Any]:
        """
        Analyse les endpoints réseau
        
        Returns:
            dict: Analyse des endpoints
        """
        flows = self.raw_data.get('flows', [])
        
        # Extraire les endpoints uniques
        endpoints = set()
        secure_count = 0
        insecure_count = 0
        
        protocols = defaultdict(int)
        domains = defaultdict(int)
        
        for flow in flows:
            if flow.get('type') == 'request':
                url = flow.get('url', '')
                scheme = flow.get('scheme', '')
                host = flow.get('host', '')
                
                endpoints.add(url)
                protocols[scheme] += 1
                
                if host:
                    domains[host] += 1
                
                if flow.get('is_secure'):
                    secure_count += 1
                else:
                    insecure_count += 1
        
        return {
            'total_unique_endpoints': len(endpoints),
            'secure_endpoints': secure_count,
            'insecure_endpoints': insecure_count,
            'protocols': dict(protocols),
            'top_domains': dict(sorted(domains.items(), key=lambda x: x[1], reverse=True)[:10]),
            'security_ratio': (secure_count / max(len(endpoints), 1)) * 100
        }
    
    def _analyze_data_leaks(self) -> Dict[str, Any]:
        """
        Analyse les fuites de données sensibles
        
        Returns:
            dict: Analyse des fuites
        """
        leaks = self.raw_data.get('sensitive_data_leaks', [])
        
        # Grouper par type
        leaks_by_type = defaultdict(list)
        leaks_by_severity = defaultdict(int)
        leaks_by_location = defaultdict(int)
        
        for leak in leaks:
            leak_type = leak.get('type', 'unknown')
            severity = leak.get('severity', 'MEDIUM')
            location = leak.get('location', 'unknown')
            
            leaks_by_type[leak_type].append(leak)
            leaks_by_severity[severity] += 1
            leaks_by_location[location] += 1
        
        # Identifier les fuites critiques
        critical_leaks = [
            leak for leak in leaks
            if leak.get('severity') == 'HIGH'
        ]
        
        return {
            'total_leaks': len(leaks),
            'leaks_by_type': {k: len(v) for k, v in leaks_by_type.items()},
            'severity_breakdown': dict(leaks_by_severity),
            'location_breakdown': dict(leaks_by_location),
            'critical_leaks_count': len(critical_leaks),
            'critical_leaks_details': critical_leaks[:10],  # Limiter à 10
            'risk_assessment': self._assess_leak_risk(len(leaks), len(critical_leaks))
        }
    
    def _assess_plaintext_risk(self, count: int) -> str:
        """
        Évalue le risque du trafic en clair
        
        Args:
            count (int): Nombre de requêtes en clair
            
        Returns:
            str: Niveau de risque
        """
        if count == 0:
            return 'NONE'
        elif count <= 5:
            return 'LOW'
        elif count <= 20:
            return 'MEDIUM'
        else:
            return 'HIGH'
    
    def _assess_leak_risk(self, total_leaks: int, critical_leaks: int) -> str:
        """
        Évalue le risque des fuites de données
        
        Args:
            total_leaks (int): Nombre total de fuites
            critical_leaks (int): Nombre de fuites critiques
            
        Returns:
            str: Niveau de risque
        """
        if critical_leaks > 0:
            return 'CRITICAL'
        elif total_leaks > 10:
            return 'HIGH'
        elif total_leaks > 5:
            return 'MEDIUM'
        elif total_leaks > 0:
            return 'LOW'
        else:
            return 'NONE'
    
    def _calculate_security_score(self, analysis: Dict) -> Dict[str, Any]:
        """
        Calcule un score de sécurité global
        
        Args:
            analysis (dict): Résultats de l'analyse
            
        Returns:
            dict: Score et détails
        """
        score = 100
        deductions = []
        
        # Pénalités pour le trafic en clair
        plaintext_count = analysis['plaintext_analysis']['total_plaintext_requests']
        if plaintext_count > 0:
            penalty = min(plaintext_count * 2, 30)
            score -= penalty
            deductions.append(f'{plaintext_count} plaintext requests (-{penalty})')
        
        # Pénalités pour les problèmes TLS (pondérées par sévérité)
        tls_info = analysis['tls_analysis']
        tls_issues = tls_info.get('total_issues', 0) or 0
        if tls_issues > 0:
            severity_breakdown = tls_info.get('severity_breakdown', {}) or {}
            high_tls = severity_breakdown.get('HIGH', 0) or 0
            medium_tls = severity_breakdown.get('MEDIUM', 0) or 0
            low_tls = severity_breakdown.get('LOW', 0) or 0

            # Score de risque TLS pondéré par sévérité
            weighted_tls = (high_tls * 3) + (medium_tls * 2) + low_tls
            if weighted_tls <= 0:
                weighted_tls = tls_issues

            penalty = min(weighted_tls, 25)
            score -= penalty
            deductions.append(
                f"{tls_issues} TLS issues (H:{high_tls} M:{medium_tls} L:{low_tls}) (-{penalty})"
            )
        
        # Pénalités pour les fuites de données
        critical_leaks = analysis['data_leaks_analysis']['critical_leaks_count']
        total_leaks = analysis['data_leaks_analysis']['total_leaks']
        
        if critical_leaks > 0:
            penalty = min(critical_leaks * 10, 30)
            score -= penalty
            deductions.append(f'{critical_leaks} critical data leaks (-{penalty})')
        elif total_leaks > 0:
            penalty = min(total_leaks * 2, 15)
            score -= penalty
            deductions.append(f'{total_leaks} data leaks (-{penalty})')
        
        # Pénalité pour ratio de sécurité faible
        security_ratio = analysis['endpoints_analysis']['security_ratio']
        if security_ratio < 80:
            penalty = int((80 - security_ratio) / 4)
            score -= penalty
            deductions.append(f'Low security ratio {security_ratio:.1f}% (-{penalty})')
        
        score = max(0, score)
        
        # Déterminer le grade
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
            'deductions': deductions
        }
    
    def _generate_recommendations(self, analysis: Dict) -> List[Dict]:
        """
        Génère des recommandations de sécurité
        
        Args:
            analysis (dict): Résultats de l'analyse
            
        Returns:
            list: Liste de recommandations
        """
        recommendations = []
        
        # Recommandations pour le trafic en clair
        plaintext_count = analysis['plaintext_analysis']['total_plaintext_requests']
        if plaintext_count > 0:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'Network Security',
                'issue': 'Plaintext HTTP traffic detected',
                'recommendation': f'Migrate all {plaintext_count} HTTP requests to HTTPS. Configure network security config to block cleartext traffic.',
                'affected_domains': list(analysis['plaintext_analysis']['domains_breakdown'].keys())[:5]
            })
        
        # Recommandations pour TLS
        outdated_tls = analysis['tls_analysis'].get('outdated_tls_count', 0)
        if outdated_tls > 0:
            recommendations.append({
                'priority': 'HIGH',
                'category': 'TLS Security',
                'issue': f'{outdated_tls} connections using outdated TLS versions',
                'recommendation': 'Enforce TLS 1.2 or higher. Update server configurations to disable TLS 1.0 and 1.1.'
            })
        
        # Recommandations pour les cookies
        insecure_cookies = analysis['tls_analysis'].get('insecure_cookies_count', 0)
        if insecure_cookies > 0:
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'Cookie Security',
                'issue': f'{insecure_cookies} cookies without proper security flags',
                'recommendation': 'Add Secure, HttpOnly, and SameSite attributes to all cookies containing sensitive data.'
            })
        
        # Recommandations pour les fuites de données
        critical_leaks = analysis['data_leaks_analysis']['critical_leaks_count']
        if critical_leaks > 0:
            leak_types = list(analysis['data_leaks_analysis']['leaks_by_type'].keys())
            recommendations.append({
                'priority': 'CRITICAL',
                'category': 'Data Protection',
                'issue': f'{critical_leaks} critical data leaks detected',
                'recommendation': f'Review and secure transmission of sensitive data: {", ".join(leak_types[:5])}. Implement encryption and avoid sending sensitive data in URLs.',
                'leak_types': leak_types
            })
        
        # Recommandations pour les headers de sécurité
        missing_headers = analysis['tls_analysis'].get('missing_security_headers_count', 0)
        if missing_headers > 0:
            recommendations.append({
                'priority': 'LOW',
                'category': 'HTTP Headers',
                'issue': f'{missing_headers} responses missing security headers',
                'recommendation': 'Add security headers: Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options, Content-Security-Policy.'
            })
        
        return recommendations
    
    def export_report(self, output_file='captures/analysis_report.json') -> bool:
        """
        Exporte le rapport d'analyse
        
        Args:
            output_file (str): Fichier de sortie
            
        Returns:
            bool: True si exporté avec succès
        """
        try:
            if not self.analysis_result:
                logger.error("No analysis result to export")
                return False
            
            with open(output_file, 'w') as f:
                json.dump(self.analysis_result, f, indent=2)
            
            logger.info(f"Analysis report exported to {output_file}")
            return True
            
        except Exception as e:
            logger.error(f"Error exporting report: {e}")
            return False
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Retourne un résumé concis de l'analyse
        
        Returns:
            dict: Résumé
        """
        if not self.analysis_result:
            return {'error': 'No analysis performed'}
        
        return {
            'timestamp': self.analysis_result['timestamp'],
            'security_score': self.analysis_result['security_score'],
            'total_flows': self.analysis_result['capture_summary'].get('total_flows', 0),
            'plaintext_requests': self.analysis_result['plaintext_analysis']['total_plaintext_requests'],
            'tls_issues': self.analysis_result['tls_analysis']['total_issues'],
            'data_leaks': self.analysis_result['data_leaks_analysis']['total_leaks'],
            'critical_leaks': self.analysis_result['data_leaks_analysis']['critical_leaks_count'],
            'top_recommendations': self.analysis_result['recommendations'][:3]
        }
