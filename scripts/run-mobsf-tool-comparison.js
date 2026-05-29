#!/usr/bin/env node

const fs = require('fs');
const http = require('http');
const https = require('https');
const path = require('path');
const crypto = require('crypto');

const ALLOWED_EXTENSIONS = new Set(['.apk', '.aab']);
const EXPERIMENTS_DIR = path.resolve('backend', 'ml-model', 'experiments');
const REPORTS_DIR = path.join(EXPERIMENTS_DIR, 'mobsf_tool_reports');
const DETAILS_PATH = path.join(EXPERIMENTS_DIR, 'mobsf_tool_results.csv');
const EXTERNAL_PATH = path.join(EXPERIMENTS_DIR, 'external_tool_results.csv');

function parseArgs(argv) {
  const args = {
    droidbench: null,
    ghera: null,
    mobsfUrl: process.env.MOBSF_URL || 'http://localhost:8000',
    apiKey: process.env.MOBSF_API_KEY || '',
    limit: null,
    resume: false,
  };

  for (let i = 2; i < argv.length; i += 1) {
    const value = argv[i];
    if (value === '--droidbench') {
      args.droidbench = argv[++i];
    } else if (value === '--ghera') {
      args.ghera = argv[++i];
    } else if (value === '--mobsf-url') {
      args.mobsfUrl = argv[++i];
    } else if (value === '--api-key') {
      args.apiKey = argv[++i];
    } else if (value === '--limit') {
      args.limit = Math.max(1, Number.parseInt(argv[++i], 10) || 1);
    } else if (value === '--resume') {
      args.resume = true;
    } else if (value === '--help' || value === '-h') {
      printUsage();
      process.exit(0);
    } else {
      throw new Error(`Unknown argument: ${value}`);
    }
  }

  if (!args.apiKey) {
    throw new Error('MobSF API key is required. Pass --api-key or set MOBSF_API_KEY.');
  }
  if (!args.droidbench && !args.ghera) {
    throw new Error('Provide --droidbench and/or --ghera folders.');
  }

  return args;
}

function printUsage() {
  console.log(`Usage:
  node scripts/run-mobsf-tool-comparison.js --droidbench <folder> --ghera <folder> --api-key <key> [--resume]

Options:
  --mobsf-url <url>    Default: http://localhost:8000
  --limit <n>          Smoke-test only the first n APK/AAB files.
  --resume             Reuse existing MobSF reports and completed rows.`);
}

function findApkFiles(rootDir) {
  if (!rootDir) {
    return [];
  }
  const resolved = path.resolve(rootDir);
  if (!fs.existsSync(resolved) || !fs.statSync(resolved).isDirectory()) {
    throw new Error(`Folder not found: ${resolved}`);
  }

  const files = [];
  const stack = [resolved];
  while (stack.length > 0) {
    const current = stack.pop();
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        stack.push(fullPath);
      } else if (entry.isFile() && ALLOWED_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) {
        files.push(fullPath);
      }
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
      ...(options.headers || {}),
    };

    let body = options.body || null;
    if (options.form) {
      body = Buffer.from(new URLSearchParams(options.form).toString(), 'utf8');
      headers['Content-Type'] = 'application/x-www-form-urlencoded';
    }
    if (body) {
      headers['Content-Length'] = body.length;
    }

    const request = transport.request(
      {
        method,
        hostname: url.hostname,
        port: url.port || (url.protocol === 'https:' ? 443 : 80),
        path: `${url.pathname}${url.search}`,
        headers,
      },
      (response) => {
        const chunks = [];
        response.on('data', (chunk) => chunks.push(chunk));
        response.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf8');
          if (response.statusCode < 200 || response.statusCode >= 300) {
            reject(new Error(`MobSF ${endpoint} HTTP ${response.statusCode}: ${raw.slice(0, 500)}`));
            return;
          }
          try {
            resolve(JSON.parse(raw));
          } catch (error) {
            reject(new Error(`MobSF ${endpoint} returned non-JSON: ${raw.slice(0, 500)}`));
          }
        });
      }
    );

    request.on('error', reject);
    if (body) {
      request.write(body);
    }
    request.end();
  });
}

function uploadFile(filePath, args) {
  return new Promise((resolve, reject) => {
    const url = new URL('/api/v1/upload', args.mobsfUrl);
    const boundary = `----MobileSecMobSF${Date.now()}${Math.random().toString(16).slice(2)}`;
    const filename = path.basename(filePath);
    const fileSize = fs.statSync(filePath).size;
    const preamble = Buffer.from(
      `--${boundary}\r\n` +
      `Content-Disposition: form-data; name="file"; filename="${filename.replace(/"/g, '\\"')}"\r\n` +
      'Content-Type: application/vnd.android.package-archive\r\n\r\n'
    );
    const closing = Buffer.from(`\r\n--${boundary}--\r\n`);
    const transport = url.protocol === 'https:' ? https : http;

    const request = transport.request(
      {
        method: 'POST',
        hostname: url.hostname,
        port: url.port || (url.protocol === 'https:' ? 443 : 80),
        path: url.pathname,
        headers: {
          Authorization: args.apiKey,
          Accept: 'application/json',
          'Content-Type': `multipart/form-data; boundary=${boundary}`,
          'Content-Length': preamble.length + fileSize + closing.length,
        },
      },
      (response) => {
        const chunks = [];
        response.on('data', (chunk) => chunks.push(chunk));
        response.on('end', () => {
          const raw = Buffer.concat(chunks).toString('utf8');
          if (response.statusCode < 200 || response.statusCode >= 300) {
            reject(new Error(`MobSF upload HTTP ${response.statusCode}: ${raw.slice(0, 500)}`));
            return;
          }
          try {
            resolve(JSON.parse(raw));
          } catch (error) {
            reject(new Error(`MobSF upload returned non-JSON: ${raw.slice(0, 500)}`));
          }
        });
      }
    );

    request.on('error', reject);
    request.write(preamble);
    fs.createReadStream(filePath)
      .on('error', reject)
      .on('end', () => request.end(closing))
      .pipe(request, { end: false });
  });
}

async function scanWithMobSF(filePath, args) {
  const upload = await uploadFile(filePath, args);
  const appHash = upload.hash;
  if (!appHash) {
    throw new Error(`MobSF upload did not return hash for ${filePath}`);
  }

  await requestJson('POST', args.mobsfUrl, '/api/v1/scan', args.apiKey, {
    form: {
      scan_type: upload.scan_type || 'apk',
      file_name: upload.file_name || upload.name || path.basename(filePath),
      hash: appHash,
    },
  });

  return requestJson('POST', args.mobsfUrl, '/api/v1/report_json', args.apiKey, {
    form: { hash: appHash },
  });
}

function iterObjects(value, prefix = '') {
  const results = [];
  if (Array.isArray(value)) {
    value.forEach((item, index) => {
      results.push(...iterObjects(item, `${prefix}[${index}]`));
    });
  } else if (value && typeof value === 'object') {
    results.push({ path: prefix, item: value });
    for (const [key, item] of Object.entries(value)) {
      results.push(...iterObjects(item, prefix ? `${prefix}.${key}` : key));
    }
  }
  return results;
}

function objectText(pathName, item) {
  const parts = [pathName];
  for (const [key, value] of Object.entries(item)) {
    if (['string', 'number', 'boolean'].includes(typeof value)) {
      parts.push(`${key}: ${value}`);
    }
  }
  return parts.join(' ').toUpperCase();
}

function findingCategory(pathName, item) {
  const text = objectText(pathName, item);
  if (/(API KEY|API_KEY|GOOGLE API|FIREBASE|AWS ACCESS|AKIA)/.test(text)) return 'secret';
  if (/(PASSWORD|PASSWD|PWD|HARDCODED CREDENTIAL|SECRET|TOKEN|PRIVATE KEY|BEARER|CREDENTIAL)/.test(text)) return 'secret';
  if (/(SSL|TLS|CERTIFICATE|TRUSTMANAGER|HOSTNAME VERIFIER|HTTP:\/\/|CLEARTEXT|INSECURE HTTP|USES CLEARTEXT)/.test(text)) return 'network';
  if (/(AES\/ECB| ECB| DES |DES\/|DES-|3DES|DESEDE|RC4|BLOWFISH|WEAK CIPHER|MD5|SHA-1|SHA1|INSECURE RANDOM|JAVA\.UTIL\.RANDOM|CWE-330|RSA|WEAK KEY|1024|CRYPTO|ENCRYPT|DECRYPT|CWE-327|CWE-326)/.test(text)) return 'crypto';
  return null;
}

function countFindings(report) {
  let secrets = 0;
  let network = 0;
  let cryptoFindings = 0;
  const seen = new Set();

  for (const { path: pathName, item } of iterObjects(report)) {
    const category = findingCategory(pathName, item);
    if (!category) {
      continue;
    }
    const key = `${category}:${pathName}:${JSON.stringify(item).slice(0, 200)}`;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    if (category === 'secret') secrets += 1;
    if (category === 'network') network += 1;
    if (category === 'crypto') cryptoFindings += 1;
  }

  return { secrets, network, crypto: cryptoFindings };
}

function csvEscape(value) {
  if (value === null || value === undefined) return '';
  const text = String(value);
  if (/[",\r\n]/.test(text)) return `"${text.replace(/"/g, '""')}"`;
  return text;
}

function parseCsv(content) {
  const rows = [];
  let row = [];
  let field = '';
  let inQuotes = false;
  for (let i = 0; i < content.length; i += 1) {
    const char = content[i];
    const next = content[i + 1];
    if (char === '"' && inQuotes && next === '"') {
      field += '"';
      i += 1;
    } else if (char === '"') {
      inQuotes = !inQuotes;
    } else if (char === ',' && !inQuotes) {
      row.push(field);
      field = '';
    } else if ((char === '\n' || char === '\r') && !inQuotes) {
      if (char === '\r' && next === '\n') i += 1;
      row.push(field);
      field = '';
      if (row.some((value) => value !== '')) rows.push(row);
      row = [];
    } else {
      field += char;
    }
  }
  if (field !== '' || row.length > 0) {
    row.push(field);
    if (row.some((value) => value !== '')) rows.push(row);
  }
  if (rows.length === 0) return [];
  const headers = rows[0];
  return rows.slice(1).map((values) => {
    const item = {};
    headers.forEach((header, index) => {
      item[header] = values[index] || '';
    });
    return item;
  });
}

function writeCsv(filePath, rows, columns) {
  const content = [
    columns.join(','),
    ...rows.map((row) => columns.map((column) => csvEscape(row[column])).join(',')),
  ].join('\n');
  fs.writeFileSync(filePath, `${content}\n`, 'utf8');
}

function loadRows(filePath) {
  if (!fs.existsSync(filePath)) return [];
  return parseCsv(fs.readFileSync(filePath, 'utf8'));
}

function apkKey(dataset, apk) {
  return `${dataset}\t${apk}`.toLowerCase();
}

function updateExternalSummary(summary) {
  const columns = [
    'tool',
    'number_of_apks_analyzed',
    'benchmark_apks',
    'real_world_apks',
    'mean_scan_time_per_apk',
    'detected_vulnerability_categories',
    'hardcoded_secrets_detected',
    'network_issues_detected',
    'cryptographic_issues_detected',
    'pdf_export',
    'json_export',
    'sarif_export',
    'ci_cd_integration',
    'ml_based_prioritization',
    'ai_assisted_remediation',
    'reproducible_docker_deployment',
  ];
  const existing = loadRows(EXTERNAL_PATH).filter((row) => String(row.tool).toLowerCase() !== 'mobsf');
  existing.push(summary);
  writeCsv(EXTERNAL_PATH, existing, columns);
}

function buildSummary(rows) {
  const scanned = rows.filter((row) => row.status === 'completed');
  const runtimes = scanned.map((row) => Number.parseFloat(row.runtime_seconds)).filter(Number.isFinite);
  const secretTotal = scanned.reduce((sum, row) => sum + Number.parseInt(row.hardcoded_secrets_detected || '0', 10), 0);
  const networkTotal = scanned.reduce((sum, row) => sum + Number.parseInt(row.network_issues_detected || '0', 10), 0);
  const cryptoTotal = scanned.reduce((sum, row) => sum + Number.parseInt(row.cryptographic_issues_detected || '0', 10), 0);
  const categories = [secretTotal, networkTotal, cryptoTotal].filter((value) => value > 0).length;

  return {
    tool: 'MobSF',
    number_of_apks_analyzed: scanned.length,
    benchmark_apks: [...new Set(scanned.map((row) => row.dataset))].join(', '),
    real_world_apks: 0,
    mean_scan_time_per_apk: runtimes.length ? `${(runtimes.reduce((a, b) => a + b, 0) / runtimes.length).toFixed(2)} s` : '',
    detected_vulnerability_categories: categories,
    hardcoded_secrets_detected: secretTotal,
    network_issues_detected: networkTotal,
    cryptographic_issues_detected: cryptoTotal,
    pdf_export: 'Yes',
    json_export: 'Yes',
    sarif_export: 'No',
    ci_cd_integration: 'Yes',
    ml_based_prioritization: 'No',
    ai_assisted_remediation: 'No',
    reproducible_docker_deployment: 'Yes',
  };
}

async function main() {
  const args = parseArgs(process.argv);
  fs.mkdirSync(REPORTS_DIR, { recursive: true });

  let jobs = [
    ...findApkFiles(args.droidbench).map((file) => ({ dataset: 'DroidBench', file })),
    ...findApkFiles(args.ghera).map((file) => ({ dataset: 'Ghera', file })),
  ];
  if (args.limit) jobs = jobs.slice(0, args.limit);

  const rows = args.resume ? loadRows(DETAILS_PATH) : [];
  const completed = new Set(rows.filter((row) => row.status === 'completed').map((row) => apkKey(row.dataset, row.apk)));
  jobs = args.resume ? jobs.filter((job) => !completed.has(apkKey(job.dataset, path.basename(job.file)))) : jobs;

  console.log(`MobSF jobs remaining: ${jobs.length}; existing rows: ${rows.length}`);

  for (let index = 0; index < jobs.length; index += 1) {
    const job = jobs[index];
    const apk = path.basename(job.file);
    const digest = sha256File(job.file);
    const reportPath = path.join(REPORTS_DIR, `${digest}.json`);
    const startedAt = Date.now();

    console.log(`[${index + 1}/${jobs.length}] ${job.dataset} ${apk}`);
    try {
      let report;
      if (args.resume && fs.existsSync(reportPath)) {
        report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
      } else {
        report = await scanWithMobSF(job.file, args);
        fs.writeFileSync(reportPath, JSON.stringify(report, null, 2), 'utf8');
      }
      const counts = countFindings(report);
      const runtime = (Date.now() - startedAt) / 1000;
      rows.push({
        dataset: job.dataset,
        apk,
        file_path: job.file,
        sha256: digest,
        status: 'completed',
        runtime_seconds: runtime.toFixed(3),
        hardcoded_secrets_detected: counts.secrets,
        network_issues_detected: counts.network,
        cryptographic_issues_detected: counts.crypto,
        report_path: reportPath,
        error: '',
      });
    } catch (error) {
      const runtime = (Date.now() - startedAt) / 1000;
      rows.push({
        dataset: job.dataset,
        apk,
        file_path: job.file,
        sha256: digest,
        status: 'failed',
        runtime_seconds: runtime.toFixed(3),
        hardcoded_secrets_detected: 0,
        network_issues_detected: 0,
        cryptographic_issues_detected: 0,
        report_path: '',
        error: error.message,
      });
      console.error(`Failed: ${error.message}`);
    }

    writeCsv(DETAILS_PATH, rows, [
      'dataset',
      'apk',
      'file_path',
      'sha256',
      'status',
      'runtime_seconds',
      'hardcoded_secrets_detected',
      'network_issues_detected',
      'cryptographic_issues_detected',
      'report_path',
      'error',
    ]);
    updateExternalSummary(buildSummary(rows));
  }

  updateExternalSummary(buildSummary(rows));
  console.log(`Wrote ${DETAILS_PATH}`);
  console.log(`Updated ${EXTERNAL_PATH}`);
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
