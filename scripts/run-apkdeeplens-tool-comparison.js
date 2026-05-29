#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { spawnSync } = require('child_process');

const EXPERIMENTS_DIR = path.resolve('backend', 'ml-model', 'experiments');
const MOBSF_DETAILS_PATH = path.join(EXPERIMENTS_DIR, 'mobsf_tool_results.csv');
const DETAILS_PATH = path.join(EXPERIMENTS_DIR, 'apkdeeplens_tool_results.csv');
const EXTERNAL_PATH = path.join(EXPERIMENTS_DIR, 'external_tool_results.csv');
const REPORTS_ROOT = path.join(EXPERIMENTS_DIR, 'apkdeeplens_tool_reports');
const DEFAULT_IMAGE = 'apkdeeplens:mobilesec';
const DEFAULT_SOURCE = 'C:\\Users\\HP\\Desktop\\phd\\APKDeepLens';
const DEFAULT_DOCKERFILE = path.resolve('scripts', 'apkdeeplens.Dockerfile');

function parseArgs(argv) {
  const args = {
    source: process.env.APKDEEPLENS_SOURCE || DEFAULT_SOURCE,
    image: process.env.APKDEEPLENS_IMAGE || DEFAULT_IMAGE,
    fromMobsfCsv: MOBSF_DETAILS_PATH,
    limit: null,
    resume: false,
    skipBuild: false,
    dockerfile: DEFAULT_DOCKERFILE,
  };

  for (let i = 2; i < argv.length; i += 1) {
    const value = argv[i];
    if (value === '--source') {
      args.source = argv[++i];
    } else if (value === '--image') {
      args.image = argv[++i];
    } else if (value === '--from-mobsf-csv') {
      args.fromMobsfCsv = argv[++i];
    } else if (value === '--limit') {
      args.limit = Math.max(1, Number.parseInt(argv[++i], 10) || 1);
    } else if (value === '--resume') {
      args.resume = true;
    } else if (value === '--skip-build') {
      args.skipBuild = true;
    } else if (value === '--dockerfile') {
      args.dockerfile = argv[++i];
    } else if (value === '--help' || value === '-h') {
      printUsage();
      process.exit(0);
    } else {
      throw new Error(`Unknown argument: ${value}`);
    }
  }

  return args;
}

function printUsage() {
  console.log(`Usage:
  node scripts/run-apkdeeplens-tool-comparison.js --resume

Options:
  --source <folder>          APKDeepLens source folder. Default: ${DEFAULT_SOURCE}
  --image <name>             Docker image tag. Default: ${DEFAULT_IMAGE}
  --from-mobsf-csv <file>    Reuse completed MobSF APK rows as the test list.
  --limit <n>                Smoke-test only the first n APK/AAB files.
  --resume                   Reuse existing APKDeepLens rows and reports.
  --dockerfile <file>        Dockerfile used to build the image.
  --skip-build               Use an existing Docker image.`);
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

function sha256File(filePath) {
  const hash = crypto.createHash('sha256');
  hash.update(fs.readFileSync(filePath));
  return hash.digest('hex');
}

function apkKey(dataset, apk, sha256 = '') {
  return `${dataset}\t${apk}\t${sha256}`.toLowerCase();
}

function assertDockerOk(result, action) {
  if (result.status !== 0) {
    throw new Error(`${action} failed with exit code ${result.status}: ${result.stderr || result.stdout}`);
  }
}

function buildImage(args) {
  const source = path.resolve(args.source);
  if (!fs.existsSync(path.join(source, 'Dockerfile'))) {
    throw new Error(`APKDeepLens Dockerfile not found in ${source}`);
  }
  const dockerfile = path.resolve(args.dockerfile);
  if (!fs.existsSync(dockerfile)) {
    throw new Error(`Dockerfile not found: ${dockerfile}`);
  }
  const result = spawnSync('docker', ['build', '-t', args.image, '-f', dockerfile, source], {
    encoding: 'utf8',
    stdio: 'inherit',
    shell: false,
  });
  assertDockerOk(result, 'Docker build');
}

function runApkDeepLens(job, args, reportDir) {
  const apkDir = path.dirname(job.file);
  const apkName = path.basename(job.file);
  fs.mkdirSync(reportDir, { recursive: true });

  const result = spawnSync(
    'docker',
    [
      'run',
      '--rm',
      '-v',
      `${apkDir}:/apk:ro`,
      '-v',
      `${reportDir}:/out`,
      args.image,
      'python',
      'APKDeepLens.py',
      '-apk',
      `/apk/${apkName}`,
      '-report',
      'json',
      '-o',
      '/out',
      '--ignore_virtualenv',
    ],
    {
      encoding: 'utf8',
      shell: false,
      maxBuffer: 1024 * 1024 * 20,
    }
  );

  return {
    status: result.status,
    stdout: result.stdout || '',
    stderr: result.stderr || '',
  };
}

function findReport(reportDir, apkName) {
  const reportsDir = path.join(reportDir, 'reports');
  if (!fs.existsSync(reportsDir)) return null;
  const cleanName = apkName.replace(/\.apk$/i, '').replace(/[^\w.-]/g, '_');
  const expected = path.join(reportsDir, `report_${cleanName}.json`);
  if (fs.existsSync(expected)) return expected;
  const candidates = fs.readdirSync(reportsDir)
    .filter((name) => name.toLowerCase().endsWith('.json'))
    .map((name) => path.join(reportsDir, name));
  return candidates[0] || null;
}

function findingText(item) {
  if (!item || typeof item !== 'object') return '';
  return Object.entries(item)
    .filter(([, value]) => ['string', 'number', 'boolean'].includes(typeof value))
    .map(([key, value]) => `${key}: ${value}`)
    .join(' ')
    .toUpperCase();
}

function countApkDeepLensFindings(report) {
  const hardcodedSecrets = Array.isArray(report.hardcoded_secrets) ? report.hardcoded_secrets.length : 0;
  const insecureRequests = Array.isArray(report.insecure_requests) ? report.insecure_requests.length : 0;
  const codeFindings = Array.isArray(report.code_findings) ? report.code_findings : [];
  const manifestFindings = Array.isArray(report.manifest_security) ? report.manifest_security : [];

  let network = insecureRequests;
  let crypto = 0;
  for (const finding of [...codeFindings, ...manifestFindings]) {
    const text = findingText(finding);
    if (/(SSL|TLS|CERTIFICATE|CLEARTEXT|HTTP:\/\/|HTTPS?|NETWORK|WEBVIEW|TRUSTMANAGER|HOSTNAME)/.test(text)) {
      network += 1;
    }
    if (/(CRYPTO|CIPHER|AES|DES|ECB|MD5|SHA-?1|RANDOM|RSA|BLOWFISH|RC4|ENCRYPT|DECRYPT)/.test(text)) {
      crypto += 1;
    }
  }

  return {
    secrets: hardcodedSecrets,
    network,
    crypto,
  };
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
  const existing = loadRows(EXTERNAL_PATH).filter((row) => String(row.tool).toLowerCase() !== 'apkdeeplens');
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
    tool: 'APKDeepLens',
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

function loadJobs(args) {
  const rows = loadRows(path.resolve(args.fromMobsfCsv))
    .filter((row) => row.status === 'completed' && row.file_path && fs.existsSync(row.file_path));
  const seen = new Set();
  const jobs = [];
  for (const row of rows) {
    const key = apkKey(row.dataset, row.apk, row.sha256 || row.file_path);
    if (seen.has(key)) continue;
    seen.add(key);
    jobs.push({
      dataset: row.dataset,
      apk: row.apk,
      file: row.file_path,
      sha256: row.sha256 || sha256File(row.file_path),
    });
  }
  return args.limit ? jobs.slice(0, args.limit) : jobs;
}

function main() {
  const args = parseArgs(process.argv);
  fs.mkdirSync(REPORTS_ROOT, { recursive: true });

  if (!args.skipBuild) {
    buildImage(args);
  }

  let jobs = loadJobs(args);
  const rows = args.resume ? loadRows(DETAILS_PATH) : [];
  const completed = new Set(rows.filter((row) => row.status === 'completed').map((row) => apkKey(row.dataset, row.apk, row.sha256)));
  jobs = args.resume ? jobs.filter((job) => !completed.has(apkKey(job.dataset, job.apk, job.sha256))) : jobs;

  console.log(`APKDeepLens jobs remaining: ${jobs.length}; existing rows: ${rows.length}`);

  for (let index = 0; index < jobs.length; index += 1) {
    const job = jobs[index];
    const reportDir = path.join(REPORTS_ROOT, job.sha256);
    const reportPath = findReport(reportDir, job.apk);
    const startedAt = Date.now();
    console.log(`[${index + 1}/${jobs.length}] ${job.dataset} ${job.apk}`);

    try {
      let finalReportPath = reportPath;
      if (!finalReportPath) {
        const result = runApkDeepLens(job, args, reportDir);
        if (result.status !== 0) {
          throw new Error((result.stderr || result.stdout || `exit ${result.status}`).slice(0, 1000));
        }
        finalReportPath = findReport(reportDir, job.apk);
      }
      if (!finalReportPath) {
        throw new Error(`APKDeepLens completed but no JSON report was found in ${reportDir}`);
      }
      const report = JSON.parse(fs.readFileSync(finalReportPath, 'utf8'));
      const counts = countApkDeepLensFindings(report);
      const runtime = (Date.now() - startedAt) / 1000;
      rows.push({
        dataset: job.dataset,
        apk: job.apk,
        file_path: job.file,
        sha256: job.sha256,
        status: 'completed',
        runtime_seconds: runtime.toFixed(3),
        hardcoded_secrets_detected: counts.secrets,
        network_issues_detected: counts.network,
        cryptographic_issues_detected: counts.crypto,
        report_path: finalReportPath,
        error: '',
      });
    } catch (error) {
      const runtime = (Date.now() - startedAt) / 1000;
      rows.push({
        dataset: job.dataset,
        apk: job.apk,
        file_path: job.file,
        sha256: job.sha256,
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

main();
