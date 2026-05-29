#!/usr/bin/env node

const fs = require('fs');
const http = require('http');
const https = require('https');
const path = require('path');
const { execFile } = require('child_process');

const DEFAULT_API = 'http://localhost:5000';
const ALLOWED_EXTENSIONS = new Set(['.apk', '.aab']);
const DEFAULT_OUTPUT_DIR = path.resolve('backend', 'ml-model', 'experiments');

function parseArgs(argv) {
  const args = {
    droidbench: null,
    ghera: null,
    api: DEFAULT_API,
    reportgen: 'http://localhost:3005',
    limit: null,
    limitPerDataset: null,
    force: true,
    resume: false,
    skipExports: false,
    concurrency: 1,
    outputDir: DEFAULT_OUTPUT_DIR,
    containers: ['apk-scanner', 'secret-hunter', 'crypto-check', 'network-inspector', 'reportgen'],
  };

  for (let i = 2; i < argv.length; i += 1) {
    const value = argv[i];
    if (value === '--droidbench') {
      args.droidbench = argv[++i];
    } else if (value === '--ghera') {
      args.ghera = argv[++i];
    } else if (value === '--api') {
      args.api = argv[++i];
    } else if (value === '--reportgen') {
      args.reportgen = argv[++i];
    } else if (value === '--limit') {
      args.limit = Math.max(1, Number.parseInt(argv[++i], 10) || 1);
    } else if (value === '--limit-per-dataset') {
      args.limitPerDataset = Math.max(1, Number.parseInt(argv[++i], 10) || 1);
    } else if (value === '--no-force') {
      args.force = false;
    } else if (value === '--resume') {
      args.resume = true;
    } else if (value === '--skip-exports') {
      args.skipExports = true;
    } else if (value === '--concurrency') {
      args.concurrency = Math.max(1, Number.parseInt(argv[++i], 10) || 1);
    } else if (value === '--output-dir') {
      args.outputDir = path.resolve(argv[++i]);
    } else if (value === '--containers') {
      args.containers = argv[++i].split(',').map((item) => item.trim()).filter(Boolean);
    } else {
      throw new Error(`Unknown argument: ${value}`);
    }
  }

  if (!args.droidbench && !args.ghera) {
    throw new Error(
      'Usage: node scripts/run-benchmark-evaluation.js --droidbench <folder> --ghera <folder> [--api http://localhost:5000] [--limit N | --limit-per-dataset N]'
    );
  }

  return args;
}

function requestJson(url, body) {
  return new Promise((resolve, reject) => {
    const target = new URL(url);
    const transport = target.protocol === 'https:' ? https : http;
    const payload = Buffer.from(JSON.stringify(body));
    const request = transport.request({
      method: 'POST',
      hostname: target.hostname,
      port: target.port || (target.protocol === 'https:' ? 443 : 80),
      path: `${target.pathname}${target.search}`,
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': payload.length,
      },
    }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => {
        const bytes = Buffer.concat(chunks);
        if (response.statusCode >= 200 && response.statusCode < 300) {
          resolve({ statusCode: response.statusCode, bytes: bytes.length });
        } else {
          reject(new Error(`HTTP ${response.statusCode}: ${bytes.toString('utf8')}`));
        }
      });
    });
    request.on('error', reject);
    request.write(payload);
    request.end();
  });
}

function reportFinding(value, fallbackTitle, severity = 'medium') {
  const finding = typeof value === 'object' && value !== null ? value : { description: String(value) };
  const rawSeverity = String(finding.severity || severity).toLowerCase().replace('warning', 'medium');
  const normalizedSeverity = ['critical', 'high', 'medium', 'low', 'info'].includes(rawSeverity) ? rawSeverity : severity;
  const rawLine = Number(finding.line || finding.line_number || 1);
  return {
    title: String(finding.title || finding.type || finding.name || fallbackTitle),
    description: String(finding.description || finding.message || finding.detail || fallbackTitle),
    severity: normalizedSeverity,
    recommendation: String(finding.recommendation || ''),
    file: finding.file || finding.file_path || undefined,
    line: Number.isFinite(rawLine) ? rawLine : 1,
  };
}

function toReportResults(result) {
  return {
    secretHunter: (result.potential_secrets || []).map((finding) => reportFinding(finding, 'Potential embedded secret', 'high')),
    cryptoCheck: (result.security_recommendations || []).map((finding) => reportFinding(finding, 'Security recommendation', 'medium')),
    networkInspector: [
      ...(result.insecure_endpoints || []).map((finding) => reportFinding(finding, 'Insecure network endpoint', 'high')),
      ...(result.manifest_issues || []).map((finding) => reportFinding(finding, 'Manifest security issue', 'medium')),
      ...(result.exported_components || []).map((finding) => reportFinding(finding, 'Exported component', 'low')),
    ],
  };
}

async function generateMeasuredExports(result, apk, args) {
  if (args.skipExports) {
    return {
      pdf_success: null,
      json_success: null,
      sarif_success: null,
      export_bytes_total: null,
    };
  }

  const started = Date.now();
  const payload = {
    projectName: apk,
    scanId: result.scan_id || '',
    results: toReportResults(result),
    scanResults: { apkScanner: result },
  };
  const formats = ['pdf', 'json', 'sarif'];
  const outputs = await Promise.all(formats.map(async (format) => {
    try {
      const response = await requestJson(`${args.reportgen}/api/reports`, { ...payload, format });
      return { format, success: true, bytes: response.bytes };
    } catch (error) {
      return { format, success: false, bytes: 0, error: error.message };
    }
  }));
  const byFormat = Object.fromEntries(outputs.map((output) => [output.format, output]));
  return {
    pdf_success: byFormat.pdf.success,
    json_success: byFormat.json.success,
    sarif_success: byFormat.sarif.success,
    export_bytes_total: outputs.reduce((sum, output) => sum + output.bytes, 0),
    export_time_seconds: (Date.now() - started) / 1000,
    export_errors: outputs.filter((output) => !output.success).map((output) => `${output.format}: ${output.error}`).join('; '),
  };
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

function uploadFile(filePath, apiBaseUrl, force) {
  return new Promise((resolve, reject) => {
    const url = new URL(`/api/scan?force=${force ? 'true' : 'false'}`, apiBaseUrl);
    const boundary = `----MobileSecBenchmark${Date.now()}${Math.random().toString(16).slice(2)}`;
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
        path: `${url.pathname}${url.search}`,
        headers: {
          'Content-Type': `multipart/form-data; boundary=${boundary}`,
          'Content-Length': preamble.length + fileSize + closing.length,
        },
      },
      (response) => {
        const chunks = [];
        response.on('data', (chunk) => chunks.push(chunk));
        response.on('end', () => {
          const rawBody = Buffer.concat(chunks).toString('utf8');
          let body = rawBody;
          try {
            body = JSON.parse(rawBody);
          } catch (_) {
            // Keep raw body for non-JSON error responses.
          }

          if (response.statusCode >= 200 && response.statusCode < 300) {
            resolve({ statusCode: response.statusCode, body });
          } else {
            reject(new Error(`HTTP ${response.statusCode}: ${rawBody}`));
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

function parseMemoryMb(value) {
  if (!value) {
    return null;
  }
  const match = String(value).match(/([\d.]+)\s*([KMGT]?i?)B/i);
  if (!match) {
    return null;
  }
  const amount = Number.parseFloat(match[1]);
  const unit = match[2].toLowerCase();
  if (unit.startsWith('k')) return amount / 1024;
  if (unit.startsWith('g')) return amount * 1024;
  if (unit.startsWith('t')) return amount * 1024 * 1024;
  return amount;
}

function dockerStats(containers) {
  return new Promise((resolve) => {
    execFile(
      'docker',
      ['stats', '--no-stream', '--format', '{{json .}}', ...containers],
      { encoding: 'utf8' },
      (error, stdout) => {
        if (error || !stdout.trim()) {
          resolve([]);
          return;
        }

        const samples = stdout.trim().split(/\r?\n/).flatMap((line) => {
          try {
            const row = JSON.parse(line);
            const cpu = Number.parseFloat(String(row.CPUPerc || '').replace('%', ''));
            const memUsage = String(row.MemUsage || '').split('/')[0].trim();
            return [{
              container: row.Name || row.Container || '',
              cpu_percent: Number.isFinite(cpu) ? cpu : null,
              ram_mb: parseMemoryMb(memUsage),
            }];
          } catch (_) {
            return [];
          }
        });
        resolve(samples);
      }
    );
  });
}

function average(values) {
  const clean = values.filter((value) => typeof value === 'number' && Number.isFinite(value));
  if (clean.length === 0) {
    return null;
  }
  return clean.reduce((sum, value) => sum + value, 0) / clean.length;
}

function countFindings(result) {
  const arrays = [
    result.manifest_issues,
    result.security_recommendations,
    result.insecure_endpoints,
    result.potential_secrets,
    result.exported_components,
  ];
  let count = arrays.reduce((sum, value) => sum + (Array.isArray(value) ? value.length : 0), 0);

  const notifications = result.notifications || {};
  for (const service of Object.values(notifications)) {
    if (service && service.status === 'success') {
      count += 1;
    }
  }

  return count;
}

function expectedLabel(dataset, apkName, filePath = '') {
  if (dataset === 'DroidBench') {
    return 'true';
  }

  const lower = apkName.toLowerCase();
  const lowerPath = String(filePath).toLowerCase();
  if (dataset === 'Ghera') {
    if (lower.includes('-malicious') || lowerPath.includes(`${path.sep}malicious${path.sep}`.toLowerCase())) {
      return 'true';
    }
    if (lower.includes('-secure') || lowerPath.includes(`${path.sep}secure${path.sep}`.toLowerCase())) {
      return 'false';
    }
    if (lower.includes('-benign') || lowerPath.includes(`${path.sep}benign${path.sep}`.toLowerCase())) {
      return 'false';
    }
    if (lower === 'mms.apk' && lowerPath.includes('unprotectedbroadcastrecv-privescalation-fat')) {
      return 'true';
    }
    return '';
  }

  return '';
}

function csvEscape(value) {
  if (value === null || value === undefined) {
    return '';
  }
  const text = String(value);
  if (/[",\r\n]/.test(text)) {
    return `"${text.replace(/"/g, '""')}"`;
  }
  return text;
}

function writeCsv(filePath, rows, columns) {
  const content = [
    columns.join(','),
    ...rows.map((row) => columns.map((column) => csvEscape(row[column])).join(',')),
  ].join('\n');
  fs.writeFileSync(filePath, `${content}\n`, 'utf8');
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
      if (char === '\r' && next === '\n') {
        i += 1;
      }
      row.push(field);
      field = '';
      if (row.some((value) => value !== '')) {
        rows.push(row);
      }
      row = [];
    } else {
      field += char;
    }
  }

  if (field !== '' || row.length > 0) {
    row.push(field);
    if (row.some((value) => value !== '')) {
      rows.push(row);
    }
  }

  if (rows.length === 0) {
    return [];
  }

  const headers = rows[0];
  return rows.slice(1).map((values) => {
    const item = {};
    headers.forEach((header, index) => {
      item[header] = values[index] || '';
    });
    return item;
  });
}

function loadExistingRows(outputDir) {
  const detailsPath = path.join(outputDir, 'benchmark_scan_details.csv');
  if (!fs.existsSync(detailsPath)) {
    return [];
  }
  return parseCsv(fs.readFileSync(detailsPath, 'utf8'));
}

function jobKey(dataset, apk) {
  return `${dataset}\t${apk}`.toLowerCase();
}

async function scanApk(dataset, filePath, args) {
  const apk = path.basename(filePath);
  const started = Date.now();
  let statsTimer = null;
  let statsInFlight = false;
  let statsStopped = false;
  const statsSamples = [];

  const sampleStats = async () => {
    if (statsInFlight || statsStopped) {
      return;
    }
    statsInFlight = true;
    const samples = await dockerStats(args.containers);
    if (!statsStopped) {
      statsSamples.push(...samples);
    }
    statsInFlight = false;
  };
  void sampleStats();
  statsTimer = setInterval(() => {
    void sampleStats();
  }, 2000);

  try {
    const response = await uploadFile(filePath, args.api, args.force);
    const elapsed = (Date.now() - started) / 1000;
    statsStopped = true;
    clearInterval(statsTimer);

    const result = response.body || {};
    const findings = countFindings(result);
    const detected = findings > 0;
    const exports = await generateMeasuredExports(result, apk, args);

    return {
      dataset,
      apk,
      file_path: filePath,
      scan_id: result.scan_id || '',
      status: result.status || 'unknown',
      detected_findings: findings,
      detected,
      expected: expectedLabel(dataset, apk, filePath),
      scan_time_seconds: elapsed.toFixed(3),
      cpu_percent: average(statsSamples.map((item) => item.cpu_percent))?.toFixed(2) || '',
      ram_mb: average(statsSamples.map((item) => item.ram_mb))?.toFixed(2) || '',
      apk_size_bytes: fs.statSync(filePath).size,
      report_success: exports.pdf_success,
      pdf_success: exports.pdf_success,
      json_success: exports.json_success,
      sarif_success: exports.sarif_success,
      export_bytes_total: exports.export_bytes_total,
      export_time_seconds: exports.export_time_seconds,
      error: exports.export_errors || '',
    };
  } catch (error) {
    statsStopped = true;
    clearInterval(statsTimer);
    const elapsed = (Date.now() - started) / 1000;
    return {
      dataset,
      apk,
      file_path: filePath,
      scan_id: '',
      status: 'failed',
      detected_findings: 0,
      detected: false,
      expected: expectedLabel(dataset, apk, filePath),
      scan_time_seconds: elapsed.toFixed(3),
      cpu_percent: '',
      ram_mb: '',
      apk_size_bytes: fs.statSync(filePath).size,
      report_success: false,
      pdf_success: false,
      json_success: false,
      sarif_success: false,
      export_bytes_total: '',
      export_time_seconds: '',
      error: error.message,
    };
  }
}

async function main() {
  const args = parseArgs(process.argv);
  fs.mkdirSync(args.outputDir, { recursive: true });

  const datasetJobs = [
    findApkFiles(args.droidbench).map((file) => ({ dataset: 'DroidBench', file })),
    findApkFiles(args.ghera).map((file) => ({ dataset: 'Ghera', file })),
  ];
  let jobs = (args.limitPerDataset
    ? datasetJobs.flatMap((items) => items.slice(0, args.limitPerDataset))
    : datasetJobs.flat()).slice(0, args.limit || undefined);

  const rows = args.resume ? loadExistingRows(args.outputDir) : [];
  if (args.resume && rows.length > 0) {
    const completed = new Set(
      rows
        .filter((row) => String(row.status || '').toLowerCase() === 'completed')
        .map((row) => jobKey(row.dataset, row.apk))
    );
    jobs = jobs.filter((job) => !completed.has(jobKey(job.dataset, path.basename(job.file))));
    console.log(`Resume enabled: loaded ${rows.length} existing row(s), ${jobs.length} remaining job(s).`);
  }

  if (jobs.length === 0) {
    if (rows.length > 0) {
      writeOutputs(rows, args);
      console.log('No remaining APK/AAB files to scan.');
      return;
    }
    throw new Error('No APK/AAB files found.');
  }

  console.log(`Scanning ${jobs.length} APK/AAB file(s) with ${args.api}`);
  console.log(`ReportGen measurement: ${args.skipExports ? 'skipped' : args.reportgen}; concurrency=${args.concurrency}`);
  const startedAt = Date.now();
  let nextIndex = 0;
  async function worker() {
    while (nextIndex < jobs.length) {
      const index = nextIndex;
      nextIndex += 1;
      const job = jobs[index];
      const label = `[${index + 1}/${jobs.length}] ${job.dataset} ${path.basename(job.file)}`;
      console.log(`${label} scanning...`);
      const row = await scanApk(job.dataset, job.file, args);
      rows.push(row);
      console.log(
        `${label} ${row.status} scan_id=${row.scan_id || 'N/A'} findings=${row.detected_findings} time=${row.scan_time_seconds}s`
      );
      writeOutputs(rows, args, (Date.now() - startedAt) / 1000);
    }
  }
  await Promise.all(Array.from({ length: Math.min(args.concurrency, jobs.length) }, () => worker()));
  writeOutputs(rows, args, (Date.now() - startedAt) / 1000);
}

function writeOutputs(rows, args = { concurrency: 1 }, batchElapsedSeconds = null) {
  const outputDir = args.outputDir || DEFAULT_OUTPUT_DIR;
  const throughput = batchElapsedSeconds && batchElapsedSeconds > 0
    ? (rows.length * 60) / batchElapsedSeconds
    : '';
  const runtimeRows = rows.map((row) => ({
    dataset: row.dataset,
    apk: row.apk,
    scan_id: row.scan_id,
    runtime_seconds: row.scan_time_seconds,
    cpu_percent: row.cpu_percent,
    ram_mb: row.ram_mb,
    apk_size_bytes: row.apk_size_bytes,
    export_bytes_total: row.export_bytes_total,
    export_time_seconds: row.export_time_seconds,
    concurrency: args.concurrency,
    throughput_apks_per_minute: throughput,
    report_success: row.report_success,
    pdf_success: row.pdf_success,
    json_success: row.json_success,
    sarif_success: row.sarif_success,
  }));

  const groundTruthRows = rows.map((row) => ({
    dataset: row.dataset,
    apk: row.apk,
    scan_id: row.scan_id,
    expected: row.expected,
    detected: row.detected,
    detected_findings: row.detected_findings,
    category: row.category || '',
    status: row.status,
    note: row.expected === '' ? 'unlabeled by script; verify manually before publication' : '',
  }));

  writeCsv(
    path.join(outputDir, 'runtime_results.csv'),
    runtimeRows,
    ['dataset', 'apk', 'scan_id', 'runtime_seconds', 'export_time_seconds', 'cpu_percent', 'ram_mb', 'apk_size_bytes', 'export_bytes_total', 'concurrency', 'throughput_apks_per_minute', 'report_success', 'pdf_success', 'json_success', 'sarif_success']
  );
  writeCsv(
    path.join(outputDir, 'ground_truth.csv'),
    groundTruthRows,
    ['dataset', 'apk', 'scan_id', 'expected', 'detected', 'detected_findings', 'category', 'status', 'note']
  );
  writeCsv(
    path.join(outputDir, 'benchmark_scan_details.csv'),
    rows,
    [
      'dataset',
      'apk',
      'file_path',
      'scan_id',
      'status',
      'detected_findings',
      'detected',
      'expected',
      'scan_time_seconds',
      'cpu_percent',
      'ram_mb',
      'apk_size_bytes',
      'export_bytes_total',
      'export_time_seconds',
      'pdf_success',
      'json_success',
      'report_success',
      'sarif_success',
      'error',
    ]
  );
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
