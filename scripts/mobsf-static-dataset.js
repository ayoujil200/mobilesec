#!/usr/bin/env node

const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const https = require('https');
const path = require('path');

const ALLOWED_EXTENSIONS = new Set(['.apk', '.aab']);
const DEFAULT_MOBSF_URL = process.env.MOBSF_URL || 'https://mobsf.live';

const FEATURE_COLUMNS = [
  'crypto_total_vulns',
  'crypto_high',
  'crypto_medium',
  'crypto_low',
  'crypto_info',
  'crypto_weak_cipher',
  'crypto_weak_hash',
  'crypto_insecure_random',
  'crypto_weak_rsa',
  'crypto_unique_cwes',
  'secrets_count',
  'secrets_api_keys',
  'secrets_passwords',
  'secrets_tokens',
  'secrets_aws_keys',
  'secrets_other',
  'secrets_unique_types',
  'network_findings',
  'network_endpoints',
  'network_http_issues',
  'network_cert_issues',
  'network_domain_issues',
  'total_vulnerabilities',
  'severity_score',
];

const OUTPUT_COLUMNS = [
  'scan_id',
  ...FEATURE_COLUMNS.slice(0, 10),
  'crypto_cwe_codes',
  ...FEATURE_COLUMNS.slice(10),
  'fix_category',
  'has_fix_suggestion',
  'label_source',
  'label_confidence',
  'label_review_status',
  'label_evidence',
  'candidate_fix_categories',
  'sample_id',
  'project_name',
  'apk_path',
  'mobsf_hash',
  'mobsf_app_name',
  'mobsf_package_name',
  'mobsf_security_score',
  'mobsf_report_path',
];

const CATEGORY_PRIORITY = {
  FIX_HARDCODED_PASSWORD: 100,
  FIX_EXPOSED_API_KEY: 100,
  FIX_EXPOSED_SECRET: 95,
  FIX_CERTIFICATE_ISSUE: 95,
  FIX_WEAK_CIPHER: 90,
  FIX_WEAK_HASH: 80,
  FIX_INSECURE_RANDOM: 75,
  FIX_WEAK_RSA_KEY: 75,
  FIX_INSECURE_HTTP: 70,
  FIX_CRYPTO_MEDIUM: 50,
  FIX_CRYPTO_GENERAL: 40,
  NO_CRITICAL_ISSUES: 0,
};

const SEVERITY_WEIGHT = {
  critical: 4,
  high: 3,
  warning: 2,
  medium: 2,
  low: 1,
  info: 0.25,
  secure: 0,
  good: 0,
};

function parseArgs(argv) {
  const args = {
    apkDir: null,
    mobsfUrl: DEFAULT_MOBSF_URL,
    apiKey: process.env.MOBSF_API_KEY || '',
    output: path.join('backend', 'ml-model', 'data', 'mobsf_static_dataset.csv'),
    reportsDir: path.join('backend', 'ml-model', 'data', 'mobsf_reports'),
    limit: null,
    resume: false,
    force: false,
    timeoutSeconds: 900,
    pollSeconds: 10,
  };

  for (let i = 2; i < argv.length; i += 1) {
    const value = argv[i];
    if (value === '--help' || value === '-h') {
      console.log('Usage: node scripts/mobsf-static-dataset.js <apk-dir> [--mobsf-url https://mobsf.live] [--api-key KEY] [--resume] [--limit N]');
      process.exit(0);
    }
    if (value === '--mobsf-url') args.mobsfUrl = argv[++i];
    else if (value === '--api-key') args.apiKey = argv[++i];
    else if (value === '--output') args.output = argv[++i];
    else if (value === '--reports-dir') args.reportsDir = argv[++i];
    else if (value === '--limit') args.limit = Math.max(1, Number.parseInt(argv[++i], 10) || 1);
    else if (value === '--resume') args.resume = true;
    else if (value === '--force') args.force = true;
    else if (value === '--timeout-seconds') args.timeoutSeconds = Math.max(30, Number.parseInt(argv[++i], 10) || 900);
    else if (value === '--poll-seconds') args.pollSeconds = Math.max(1, Number.parseInt(argv[++i], 10) || 10);
    else if (!args.apkDir) args.apkDir = value;
    else throw new Error(`Unknown argument: ${value}`);
  }

  if (!args.apkDir) {
    throw new Error('Usage: node scripts/mobsf-static-dataset.js <apk-dir> [--mobsf-url https://mobsf.live] [--api-key KEY] [--resume] [--limit N]');
  }
  if (!args.apiKey) {
    throw new Error('MOBSF_API_KEY is required. Pass --api-key or set the MOBSF_API_KEY environment variable.');
  }
  return args;
}

function findApps(rootDir) {
  const resolved = path.resolve(rootDir);
  if (!fs.existsSync(resolved) || !fs.statSync(resolved).isDirectory()) {
    throw new Error(`APK directory not found: ${resolved}`);
  }
  const files = [];
  const stack = [resolved];
  while (stack.length > 0) {
    const current = stack.pop();
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) stack.push(fullPath);
      else if (entry.isFile() && ALLOWED_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) files.push(fullPath);
    }
  }
  return files.sort((a, b) => a.localeCompare(b));
}

function sha256File(filePath) {
  const hash = crypto.createHash('sha256');
  hash.update(fs.readFileSync(filePath));
  return hash.digest('hex');
}

function requestJson(method, baseUrl, endpoint, apiKey, options = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(endpoint, baseUrl);
    const transport = url.protocol === 'https:' ? https : http;
    const headers = {
      Authorization: apiKey,
      Accept: 'application/json',
      'User-Agent': 'MobileSec-MobSF-Dataset/1.0',
      ...(options.headers || {}),
    };
    let body = options.body || null;

    if (options.form) {
      body = Buffer.from(new URLSearchParams(options.form).toString());
      headers['Content-Type'] = 'application/x-www-form-urlencoded';
    }
    if (body) {
      headers['Content-Length'] = Buffer.byteLength(body);
    }

    const req = transport.request(
      {
        method,
        hostname: url.hostname,
        port: url.port || (url.protocol === 'https:' ? 443 : 80),
        path: `${url.pathname}${url.search}`,
        headers,
      },
      (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf8');
          let parsed;
          try {
            parsed = JSON.parse(raw);
          } catch (error) {
            reject(new Error(`${endpoint} returned non-JSON response: ${raw.slice(0, 500)}`));
            return;
          }
          if (res.statusCode >= 200 && res.statusCode < 300) resolve(parsed);
          else reject(new Error(`${endpoint} failed HTTP ${res.statusCode}: ${raw.slice(0, 500)}`));
        });
      }
    );
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

function uploadFile(filePath, baseUrl, apiKey) {
  return new Promise((resolve, reject) => {
    const url = new URL('/api/v1/upload', baseUrl);
    const transport = url.protocol === 'https:' ? https : http;
    const boundary = `----MobileSecMobSF${Date.now()}${Math.random().toString(16).slice(2)}`;
    const filename = path.basename(filePath).replace(/"/g, '\\"');
    const fileSize = fs.statSync(filePath).size;
    const preamble = Buffer.from(
      `--${boundary}\r\n` +
      `Content-Disposition: form-data; name="file"; filename="${filename}"\r\n` +
      'Content-Type: application/vnd.android.package-archive\r\n\r\n'
    );
    const closing = Buffer.from(`\r\n--${boundary}--\r\n`);

    const req = transport.request(
      {
        method: 'POST',
        hostname: url.hostname,
        port: url.port || (url.protocol === 'https:' ? 443 : 80),
        path: `${url.pathname}${url.search}`,
        headers: {
          Authorization: apiKey,
          Accept: 'application/json',
          'User-Agent': 'MobileSec-MobSF-Dataset/1.0',
          'Content-Type': `multipart/form-data; boundary=${boundary}`,
          'Content-Length': preamble.length + fileSize + closing.length,
        },
      },
      (res) => {
        const chunks = [];
        res.on('data', (chunk) => chunks.push(chunk));
        res.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf8');
          let parsed;
          try {
            parsed = JSON.parse(raw);
          } catch (error) {
            reject(new Error(`/api/v1/upload returned non-JSON response: ${raw.slice(0, 500)}`));
            return;
          }
          if (res.statusCode >= 200 && res.statusCode < 300) resolve(parsed);
          else reject(new Error(`/api/v1/upload failed HTTP ${res.statusCode}: ${raw.slice(0, 500)}`));
        });
      }
    );

    req.on('error', reject);
    req.write(preamble);
    fs.createReadStream(filePath)
      .on('error', reject)
      .on('end', () => req.end(closing))
      .pipe(req, { end: false });
  });
}

function scan(uploadResult, baseUrl, apiKey) {
  return requestJson('POST', baseUrl, '/api/v1/scan', apiKey, {
    form: {
      scan_type: uploadResult.scan_type || 'apk',
      file_name: uploadResult.file_name || uploadResult.name || '',
      hash: uploadResult.hash,
    },
  });
}

function reportJson(hash, baseUrl, apiKey) {
  return requestJson('POST', baseUrl, '/api/v1/report_json', apiKey, { form: { hash } });
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForReport(hash, args) {
  const deadline = Date.now() + args.timeoutSeconds * 1000;
  let lastError = null;
  while (Date.now() < deadline) {
    try {
      const report = await reportJson(hash, args.mobsfUrl, args.apiKey);
      if (report && typeof report === 'object' && Object.keys(report).length > 2 && !report.error) return report;
      lastError = report;
    } catch (error) {
      lastError = error.message;
    }
    await sleep(args.pollSeconds * 1000);
  }
  throw new Error(`Timed out waiting for MobSF report for ${hash}. Last response: ${JSON.stringify(lastError).slice(0, 500)}`);
}

function iterItems(value, itemPath = '', output = []) {
  if (Array.isArray(value)) {
    value.forEach((nested, index) => iterItems(nested, `${itemPath}[${index}]`, output));
  } else if (value && typeof value === 'object') {
    output.push([itemPath, value]);
    Object.entries(value).forEach(([key, nested]) => iterItems(nested, itemPath ? `${itemPath}.${key}` : key, output));
  }
  return output;
}

function textBlob(item) {
  return Object.entries(item)
    .filter(([, value]) => ['string', 'number', 'boolean'].includes(typeof value))
    .map(([key, value]) => `${key}: ${value}`)
    .join(' ')
    .toUpperCase();
}

function severityOf(item) {
  const raw = ['severity', 'level', 'status', 'risk', 'cvss'].map((key) => item[key]).find(Boolean);
  const text = String(raw || 'warning').toLowerCase();
  if (text.includes('critical')) return 'critical';
  if (text.includes('high')) return 'high';
  if (text.includes('medium') || text.includes('warn')) return 'warning';
  if (text.includes('low')) return 'low';
  if (text.includes('info')) return 'info';
  if (text.includes('secure') || text.includes('good')) return 'secure';
  return 'warning';
}

function cweOf(item) {
  for (const key of ['cwe', 'cwe_id', 'masvs', 'owasp']) {
    if (item[key] && String(item[key]).toUpperCase().includes('CWE')) return String(item[key]);
  }
  return '';
}

function fileOf(item) {
  for (const key of ['file', 'file_path', 'path', 'component', 'name']) {
    if (item[key]) return String(item[key]);
  }
  return '';
}

function categorize(itemPath, item) {
  const text = `${itemPath} ${textBlob(item)}`;
  let category = null;
  if (['API KEY', 'API_KEY', 'GOOGLE API', 'FIREBASE', 'AWS ACCESS', 'AKIA'].some((token) => text.includes(token))) category = 'FIX_EXPOSED_API_KEY';
  else if (['PASSWORD', 'PASSWD', 'PWD', 'HARDCODED CREDENTIAL'].some((token) => text.includes(token))) category = 'FIX_HARDCODED_PASSWORD';
  else if (['SECRET', 'TOKEN', 'PRIVATE KEY', 'BEARER', 'CREDENTIAL'].some((token) => text.includes(token))) category = 'FIX_EXPOSED_SECRET';
  else if (['SSL', 'TLS', 'CERTIFICATE', 'TRUSTMANAGER', 'HOSTNAME VERIFIER'].some((token) => text.includes(token))) category = 'FIX_CERTIFICATE_ISSUE';
  else if (['HTTP://', 'CLEARTEXT', 'INSECURE HTTP', 'USES CLEARTEXT'].some((token) => text.includes(token))) category = 'FIX_INSECURE_HTTP';
  else if (['AES/ECB', ' ECB', ' DES ', 'DES/', 'DES-', '3DES', 'DESEDE', 'RC4', 'BLOWFISH', 'WEAK CIPHER'].some((token) => text.includes(token))) category = 'FIX_WEAK_CIPHER';
  else if (['MD5', 'SHA-1', 'SHA1', 'WEAK HASH'].some((token) => text.includes(token))) category = 'FIX_WEAK_HASH';
  else if (['INSECURE RANDOM', 'JAVA.UTIL.RANDOM', 'CWE-330', 'PSEUDO RANDOM'].some((token) => text.includes(token))) category = 'FIX_INSECURE_RANDOM';
  else if (['RSA', 'WEAK KEY', '1024'].some((token) => text.includes(token))) category = 'FIX_WEAK_RSA_KEY';
  else if (['CRYPTO', 'ENCRYPT', 'DECRYPT', 'CWE-327', 'CWE-326'].some((token) => text.includes(token))) category = 'FIX_CRYPTO_GENERAL';
  if (!category) return null;
  return {
    category,
    source: itemPath || 'mobsf_report',
    severity: severityOf(item),
    reason: String(item.title || item.description || item.name || category),
    cwe: cweOf(item),
    file: fileOf(item),
  };
}

function extractFindings(report) {
  return iterItems(report).map(([itemPath, item]) => categorize(itemPath, item)).filter(Boolean);
}

function scoreLabel(findings) {
  const candidates = {};
  for (const finding of findings) {
    const priority = CATEGORY_PRIORITY[finding.category] || 0;
    const weight = SEVERITY_WEIGHT[finding.severity] ?? 1;
    candidates[finding.category] ||= { count: 0, score: 0 };
    candidates[finding.category].count += 1;
    candidates[finding.category].score += priority * Math.max(weight, 0.25);
  }
  const ranked = Object.entries(candidates).sort((a, b) => {
    return b[1].score - a[1].score || (CATEGORY_PRIORITY[b[0]] || 0) - (CATEGORY_PRIORITY[a[0]] || 0) || b[1].count - a[1].count;
  });
  if (ranked.length === 0) {
    return {
      fixCategory: 'NO_CRITICAL_ISSUES',
      confidence: 1,
      reviewStatus: 'accepted',
      candidates: { NO_CRITICAL_ISSUES: { count: 1, score: 0 } },
    };
  }
  const [topCategory, top] = ranked[0];
  const secondScore = ranked[1]?.[1]?.score || 0;
  const margin = top.score - secondScore;
  const confidence = ranked.length === 1 ? 0.95 : margin >= 50 ? 0.9 : margin >= 20 ? 0.8 : 0.6;
  return {
    fixCategory: topCategory,
    confidence,
    reviewStatus: confidence >= 0.8 ? 'accepted' : 'needs_review',
    candidates: Object.fromEntries(ranked),
  };
}

function countNetworkEndpoints(report) {
  return ['urls', 'domains', 'emails'].reduce((sum, key) => {
    const value = report[key];
    if (Array.isArray(value)) return sum + value.length;
    if (value && typeof value === 'object') return sum + Object.keys(value).length;
    return sum;
  }, 0);
}

function countDomainFindings(report) {
  return iterItems(report).filter(([, item]) => ['DOMAIN', 'URL', 'IP ADDRESS', 'ENDPOINT'].some((token) => textBlob(item).includes(token))).length;
}

function buildRow(appPath, reportPath, report, sampleIndex) {
  const findings = extractFindings(report);
  const label = scoreLabel(findings);
  const categories = findings.map((finding) => finding.category);
  const cwes = [...new Set(findings.map((finding) => finding.cwe).filter(Boolean))].sort();
  const cryptoSet = new Set(['FIX_WEAK_CIPHER', 'FIX_WEAK_HASH', 'FIX_INSECURE_RANDOM', 'FIX_WEAK_RSA_KEY', 'FIX_CRYPTO_GENERAL', 'FIX_CRYPTO_MEDIUM']);
  const secretSet = new Set(['FIX_EXPOSED_API_KEY', 'FIX_HARDCODED_PASSWORD', 'FIX_EXPOSED_SECRET']);
  const networkSet = new Set(['FIX_INSECURE_HTTP', 'FIX_CERTIFICATE_ISSUE']);
  const cryptoFindings = findings.filter((finding) => cryptoSet.has(finding.category));
  const secretFindings = findings.filter((finding) => secretSet.has(finding.category));
  const networkFindings = findings.filter((finding) => networkSet.has(finding.category));
  const countCategory = (category) => categories.filter((item) => item === category).length;
  const countSeverity = (items, values) => items.filter((finding) => values.includes(finding.severity)).length;
  const severityScore = findings.reduce((sum, finding) => sum + (SEVERITY_WEIGHT[finding.severity] ?? 1), 0);
  const mobsfHash = report.md5 || report.hash || report.app_hash || sha256File(appPath);
  const evidence = findings
    .filter((finding) => finding.category === label.fixCategory)
    .slice(0, 5)
    .map((finding) => ({
      source: finding.source,
      reason: finding.reason,
      severity: finding.severity,
      file: finding.file,
      cwe: finding.cwe,
    }));

  return {
    scan_id: `mobsf-${mobsfHash}`,
    crypto_total_vulns: cryptoFindings.length,
    crypto_high: countSeverity(cryptoFindings, ['critical', 'high']),
    crypto_medium: countSeverity(cryptoFindings, ['warning', 'medium']),
    crypto_low: countSeverity(cryptoFindings, ['low']),
    crypto_info: countSeverity(cryptoFindings, ['info']),
    crypto_weak_cipher: countCategory('FIX_WEAK_CIPHER'),
    crypto_weak_hash: countCategory('FIX_WEAK_HASH'),
    crypto_insecure_random: countCategory('FIX_INSECURE_RANDOM'),
    crypto_weak_rsa: countCategory('FIX_WEAK_RSA_KEY'),
    crypto_cwe_codes: cwes.join(','),
    crypto_unique_cwes: cwes.length,
    secrets_count: secretFindings.length,
    secrets_api_keys: countCategory('FIX_EXPOSED_API_KEY'),
    secrets_passwords: countCategory('FIX_HARDCODED_PASSWORD'),
    secrets_tokens: secretFindings.filter((finding) => finding.reason.toUpperCase().includes('TOKEN')).length,
    secrets_aws_keys: secretFindings.filter((finding) => finding.reason.toUpperCase().includes('AWS')).length,
    secrets_other: Math.max(secretFindings.length - countCategory('FIX_EXPOSED_API_KEY') - countCategory('FIX_HARDCODED_PASSWORD'), 0),
    secrets_unique_types: new Set(secretFindings.map((finding) => finding.category)).size,
    network_findings: networkFindings.length,
    network_endpoints: countNetworkEndpoints(report),
    network_http_issues: countCategory('FIX_INSECURE_HTTP'),
    network_cert_issues: countCategory('FIX_CERTIFICATE_ISSUE'),
    network_domain_issues: countDomainFindings(report),
    total_vulnerabilities: findings.length,
    severity_score: Number(severityScore.toFixed(3)),
    fix_category: label.fixCategory,
    has_fix_suggestion: false,
    label_source: 'mobsf_static_rules',
    label_confidence: label.confidence,
    label_review_status: label.reviewStatus,
    label_evidence: JSON.stringify(evidence),
    candidate_fix_categories: JSON.stringify(label.candidates),
    sample_id: `mobsf-${String(sampleIndex).padStart(5, '0')}`,
    project_name: path.basename(appPath, path.extname(appPath)),
    apk_path: appPath,
    mobsf_hash: mobsfHash,
    mobsf_app_name: report.app_name || report.file_name || path.basename(appPath, path.extname(appPath)),
    mobsf_package_name: report.package_name || report.appsec?.package_name || '',
    mobsf_security_score: report.security_score || report.appsec?.security_score || '',
    mobsf_report_path: reportPath,
  };
}

function csvEscape(value) {
  if (value === null || value === undefined) return '';
  const text = String(value);
  if (/[",\r\n]/.test(text)) return `"${text.replace(/"/g, '""')}"`;
  return text;
}

function writeCsv(filePath, rows) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  const lines = [
    OUTPUT_COLUMNS.join(','),
    ...rows.map((row) => OUTPUT_COLUMNS.map((column) => csvEscape(row[column])).join(',')),
  ];
  fs.writeFileSync(filePath, `${lines.join('\n')}\n`, 'utf8');
}

async function main() {
  const args = parseArgs(process.argv);
  let apps = findApps(args.apkDir);
  if (args.limit) apps = apps.slice(0, args.limit);
  if (apps.length === 0) {
    console.log(`No APK/AAB files found in ${args.apkDir}`);
    return;
  }

  fs.mkdirSync(args.reportsDir, { recursive: true });
  const rows = [];
  console.log(`Found ${apps.length} APK/AAB file(s). MobSF: ${args.mobsfUrl}`);

  for (let index = 0; index < apps.length; index += 1) {
    const appPath = apps[index];
    const appSha = sha256File(appPath);
    const reportPath = path.join(args.reportsDir, `${appSha}.json`);
    const label = `[${index + 1}/${apps.length}] ${path.basename(appPath)}`;
    console.log(label);

    let report;
    if (fs.existsSync(reportPath) && args.resume && !args.force) {
      report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
      console.log(`  reused report ${reportPath}`);
    } else {
      const uploadResult = await uploadFile(appPath, args.mobsfUrl, args.apiKey);
      if (!uploadResult.hash) throw new Error(`MobSF upload did not return hash for ${appPath}: ${JSON.stringify(uploadResult)}`);
      console.log(`  uploaded hash=${uploadResult.hash}`);
      const scanResult = await scan(uploadResult, args.mobsfUrl, args.apiKey);
      report = scanResult && Object.keys(scanResult).length > 2 && !scanResult.error
        ? scanResult
        : await waitForReport(uploadResult.hash, args);
      fs.writeFileSync(reportPath, JSON.stringify(report, null, 2), 'utf8');
    }

    const row = buildRow(appPath, reportPath, report, index + 1);
    rows.push(row);
    console.log(`  fix_category=${row.fix_category} confidence=${row.label_confidence} findings=${row.total_vulnerabilities}`);
    writeCsv(args.output, rows);
  }

  writeCsv(args.output, rows);
  console.log(`Wrote ${rows.length} row(s) to ${args.output}`);
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
