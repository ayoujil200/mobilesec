import { Report } from '../models';

// Lightweight MASVS rule engine — defensive, heuristic-based checks for common issues.
export const masvsService = {
  analyze: (report: Report, normalizedServices: Record<string, any> = {}) => {
    const findings: any[] = [];

    try {
      // Helper to push findings
      const push = (f: any) => findings.push(Object.assign({ tool: 'masvs-heuristic', confidence: 0.75 }, f));

      // 1) Manifest checks (debuggable / allowBackup / exported components)
      const manifestRaw = (normalizedServices['manifest'] && normalizedServices['manifest'].rawString)
        || '';

      if (typeof manifestRaw === 'string' && manifestRaw.length) {
        if (/android:debuggable\s*=\s*"?(true|1)"?/i.test(manifestRaw)) {
          push({ title: 'Debuggable enabled in AndroidManifest', description: 'android:debuggable is set to true', severity: 'high', masvs: 'MASVS-PLATFORM-1', file: 'AndroidManifest.xml' });
        }
        if (/android:allowBackup\s*=\s*"?(true|1)"?/i.test(manifestRaw)) {
          push({ title: 'allowBackup enabled', description: 'android:allowBackup may allow sensitive data to be included in backups', severity: 'high', masvs: 'MASVS-STORAGE-1', file: 'AndroidManifest.xml' });
        }
        // exported component patterns
        const exportedMatches = manifestRaw.match(/<\s*(activity|service|receiver|provider)[^>]*android:exported\s*=\s*"?(true|1)"?[^>]*>/gi);
        if (exportedMatches && exportedMatches.length) {
          push({ title: 'Exported components detected', description: `Found ${exportedMatches.length} exported components`, severity: 'critical', masvs: 'MASVS-PLATFORM-1', file: 'AndroidManifest.xml' });
        }
      }

      // 2) Hardcoded secrets and keys (scan services raw strings and report.scanResults JSON)
      const scanTexts: string[] = [];
      for (const k of Object.keys(normalizedServices || {})) {
        const v = normalizedServices[k];
        if (v && v.rawString) scanTexts.push(String(v.rawString));
        if (v && v.findings) scanTexts.push(JSON.stringify(v.findings));
      }

      const allText = scanTexts.join('\n');
      if (allText && allText.length) {
        // common API key patterns
        const patterns: Array<{regex: RegExp, title: string, severity: string, masvs: string}> = [
          { regex: /AIza[0-9A-Za-z\-_]{35}/g, title: 'Google API key hardcoded', severity: 'critical', masvs: 'MASVS-AUTH-1' },
          { regex: /AKIA[0-9A-Z]{16}/g, title: 'AWS Access Key ID found', severity: 'critical', masvs: 'MASVS-AUTH-1' },
          { regex: /-----BEGIN\s+(?:RSA|EC|OPENSSH) PRIVATE KEY-----/g, title: 'Private key embedded in package', severity: 'critical', masvs: 'MASVS-CRYPTO-1' },
          { regex: /https?:\/\/.+username=.+&password=.+/gi, title: 'Credentials in URL', severity: 'critical', masvs: 'MASVS-NETWORK-1' },
          { regex: /(?:MD5|SHA-1|SHA1|DES|RC4)\b/gi, title: 'Deprecated or weak crypto algorithm referenced', severity: 'high', masvs: 'MASVS-CRYPTO-1' }
        ];

        for (const p of patterns) {
          if (p.regex.test(allText)) {
            push({ title: p.title, description: `Pattern matched: ${p.regex}`, severity: p.severity, masvs: p.masvs });
          }
        }

        // entropy check: detect long base64-like strings (possible secrets)
        const base64Candidates = allText.match(/[A-Za-z0-9_\-]{40,}/g) || [];
        if (base64Candidates.length > 0) {
          push({ title: 'High-entropy string(s) detected', description: `Found ${Math.min(5, base64Candidates.length)} long tokens (possible secrets)`, severity: 'high', masvs: 'MASVS-AUTH-1' });
        }
      }

      // 3) WebView risky patterns
      if (allText && /addJavascriptInterface\s*\(|setJavaScriptEnabled\s*\(|setAllowUniversalAccessFromFileURLs\s*\(/i.test(allText)) {
        push({ title: 'Risky WebView configuration', description: 'addJavascriptInterface or JS enabled with file access detected', severity: 'critical', masvs: 'MASVS-PLATFORM-1' });
      }

      // 4) Cleartext / http usage
      if (allText && /http:\/\//i.test(allText)) {
        push({ title: 'Cleartext HTTP URLs found', description: 'Found http:// URLs in code or resources', severity: 'high', masvs: 'MASVS-NETWORK-1' });
      }

      // 5) Insecure random/crypto usage hints
      if (allText && /new\s+Random\(|SecureRandom\s*\.getInstance\(|Cipher\.getInstance\(/i.test(allText)) {
        // more specific checks performed above for algorithms
        push({ title: 'Crypto / RNG usage detected', description: 'Crypto APIs referenced; validate algorithm and mode', severity: 'medium', masvs: 'MASVS-CRYPTO-1' });
      }

      // 6) Export findings into normalizedServices summary
      if (findings.length) {
        normalizedServices['MASVS'] = normalizedServices['MASVS'] || { findings: [], counts: { total: 0, bySeverity: {} } };
        normalizedServices['MASVS'].findings.push(...findings);
        normalizedServices['MASVS'].counts.total = normalizedServices['MASVS'].findings.length;
        const bySeverity: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
        for (const f of normalizedServices['MASVS'].findings) {
          const s = (f.severity || 'info').toString().toLowerCase();
          if (!bySeverity[s]) bySeverity[s] = 0;
          bySeverity[s]++;
        }
        normalizedServices['MASVS'].counts.bySeverity = bySeverity;
      }

    } catch (e) {
      // Do not throw - MASVS analysis is best-effort
      // eslint-disable-next-line no-console
      console.error('MASVS analysis failed', e && (e.stack || e.message || e));
    }

    return findings;
  }
};

export default masvsService;
