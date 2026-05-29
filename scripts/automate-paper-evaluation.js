#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const EXPERIMENTS_DIR = path.resolve('backend', 'ml-model', 'experiments');
const REQUIRED_FILES = [
  'ground_truth.csv',
  'runtime_results.csv',
  'benchmark_scan_details.csv',
  'external_tool_results.csv',
];

function parseArgs(argv) {
  const args = {
    droidbench: null,
    ghera: null,
    api: 'http://localhost:5000',
    reportgen: 'http://localhost:3005',
    limit: null,
    noScan: false,
    externalToolCsv: null,
    validateOnly: false,
    deriveGroundTruth: false,
    resume: false,
    syncReportSuccess: false,
    concurrency: 1,
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
    } else if (value === '--external-tool-csv') {
      args.externalToolCsv = argv[++i];
    } else if (value === '--no-scan') {
      args.noScan = true;
    } else if (value === '--validate-only') {
      args.validateOnly = true;
      args.noScan = true;
    } else if (value === '--derive-ground-truth') {
      args.deriveGroundTruth = true;
    } else if (value === '--resume') {
      args.resume = true;
    } else if (value === '--sync-report-success') {
      args.syncReportSuccess = true;
    } else if (value === '--concurrency') {
      args.concurrency = Math.max(1, Number.parseInt(argv[++i], 10) || 1);
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
  node scripts/automate-paper-evaluation.js [options]

Options:
  --droidbench <folder>        Folder containing DroidBench APK/AAB files.
  --ghera <folder>             Folder containing Ghera APK/AAB files.
  --api <url>                  MobileSec scanner API. Default: http://localhost:5000
  --reportgen <url>            ReportGen API. Default: http://localhost:3005
  --concurrency <n>            Parallel APK scans for throughput measurement.
  --limit <n>                  Limit benchmark APKs for a smoke run.
  --external-tool-csv <file>   Copy measured MobSF/APKDeepLens rows into experiments/.
  --derive-ground-truth        Derive DroidBench/Ghera expected labels from file names.
  --resume                     Continue benchmark scans from benchmark_scan_details.csv.
  --sync-report-success        Update runtime_results.csv from MongoDB report records.
  --no-scan                    Do not run MobileSec scans; only import/validate files.
  --validate-only              Only check publication-table inputs.

The script backs up existing experiment CSVs before writing replacements.`);
}

function timestamp() {
  return new Date().toISOString().replace(/[:.]/g, '-');
}

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

function backupExistingFiles() {
  ensureDir(EXPERIMENTS_DIR);
  const backupDir = path.join(EXPERIMENTS_DIR, 'backups', timestamp());
  let copied = 0;

  for (const file of REQUIRED_FILES) {
    const source = path.join(EXPERIMENTS_DIR, file);
    if (!fs.existsSync(source)) {
      continue;
    }
    ensureDir(backupDir);
    fs.copyFileSync(source, path.join(backupDir, file));
    copied += 1;
  }

  return copied > 0 ? backupDir : null;
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

function writeCsv(filePath, rows, columns) {
  const content = [
    columns.join(','),
    ...rows.map((row) => columns.map((column) => csvEscape(row[column])).join(',')),
  ].join('\n');
  fs.writeFileSync(filePath, `${content}\n`, 'utf8');
}

function normalizeExternalToolCsv(sourcePath) {
  const resolved = path.resolve(sourcePath);
  if (!fs.existsSync(resolved)) {
    throw new Error(`External tool CSV not found: ${resolved}`);
  }

  const rows = parseCsv(fs.readFileSync(resolved, 'utf8'));
  if (rows.length === 0) {
    throw new Error(`External tool CSV is empty: ${resolved}`);
  }

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
    'true_positives',
    'false_positives',
    'false_negatives',
    'precision',
    'recall',
    'f1_score',
    'pdf_export',
    'json_export',
    'sarif_export',
    'ci_cd_integration',
    'ml_based_prioritization',
    'ai_assisted_remediation',
    'reproducible_docker_deployment',
  ];

  const normalized = rows.map((row) => {
    const normalizedRow = {};
    for (const column of columns) {
      normalizedRow[column] = firstPresent(row, [
        column,
        column.replace(/_/g, ' '),
        column.replace(/_/g, '-'),
      ]);
    }
    normalizedRow.tool = normalizedRow.tool || firstPresent(row, ['scanner', 'name']);
    return normalizedRow;
  });

  const destination = path.join(EXPERIMENTS_DIR, 'external_tool_results.csv');
  writeCsv(destination, normalized, columns);
  return destination;
}

function expectedFromBenchmarkName(dataset, apkName, filePath = '') {
  const datasetText = String(dataset || '').toLowerCase();
  const apkText = String(apkName || '').toLowerCase();
  const pathText = String(filePath || '').toLowerCase();

  if (datasetText === 'droidbench') {
    return {
      expected: 'true',
      note: 'derived from DroidBench benchmark membership; verify benchmark scope before publication',
    };
  }

  if (datasetText === 'ghera') {
    if (apkText.includes('-malicious') || pathText.includes('\\malicious\\') || pathText.includes('/malicious/')) {
      return {
        expected: 'true',
        note: 'derived from Ghera malicious filename/path marker; verify before publication',
      };
    }
    if (
      apkText.includes('-benign')
      || apkText.includes('-secure')
      || pathText.includes('\\benign\\')
      || pathText.includes('/benign/')
      || pathText.includes('\\secure\\')
      || pathText.includes('/secure/')
    ) {
      return {
        expected: 'false',
        note: 'derived from Ghera benign/secure filename/path marker; verify before publication',
      };
    }
    if (apkText === 'mms.apk' && pathText.includes('unprotectedbroadcastrecv-privescalation-fat')) {
      return {
        expected: 'true',
        note: 'derived from Ghera UnprotectedBroadcastRecv-Fat README: Mms.apk is the vulnerable target app',
      };
    }
  }

  return { expected: '', note: '' };
}

function deriveGroundTruthLabels() {
  const filePath = path.join(EXPERIMENTS_DIR, 'ground_truth.csv');
  if (!fs.existsSync(filePath)) {
    return { updated: 0, skipped: true };
  }

  const rows = parseCsv(fs.readFileSync(filePath, 'utf8'));
  const detailRows = readCsvIfExists('benchmark_scan_details.csv');
  const detailPaths = new Map(
    detailRows.map((row) => [
      `${String(row.dataset || '').toLowerCase()}\t${String(row.apk || '').toLowerCase()}`,
      row.file_path || '',
    ])
  );
  let updated = 0;

  for (const row of rows) {
    const detailPath = detailPaths.get(
      `${String(row.dataset || '').toLowerCase()}\t${String(row.apk || '').toLowerCase()}`
    );
    const derived = expectedFromBenchmarkName(row.dataset, row.apk, row.file_path || detailPath);
    if (!derived.expected) {
      continue;
    }

    const current = String(row.expected || '').trim().toLowerCase();
    if (current !== derived.expected) {
      row.expected = derived.expected;
      row.note = row.note
        ? `${row.note}; ${derived.note}`
        : derived.note;
      updated += 1;
    }
  }

  const columns = [
    'dataset',
    'apk',
    'scan_id',
    'expected',
    'detected',
    'detected_findings',
    'category',
    'status',
    'note',
  ];
  writeCsv(filePath, rows, columns);
  return { updated, skipped: false };
}

function distinctReportScanIds(format) {
  const evalScript = `JSON.stringify(db.reports.distinct('scan_id', {format:'${format}'}))`;
  const result = spawnSync(
    'docker',
    [
      'exec',
      'mongodb',
      'mongosh',
      'security_platform',
      '-u',
      'admin',
      '-p',
      'securityplatform2024',
      '--authenticationDatabase',
      'admin',
      '--quiet',
      '--eval',
      evalScript,
    ],
    { encoding: 'utf8', shell: false }
  );

  if (result.status !== 0) {
    throw new Error(`Could not query MongoDB reports for format=${format}: ${result.stderr || result.stdout}`);
  }

  const raw = String(result.stdout || '').trim();
  if (!raw) {
    return new Set();
  }
  return new Set(JSON.parse(raw));
}

function syncReportSuccessFromMongo() {
  const filePath = path.join(EXPERIMENTS_DIR, 'runtime_results.csv');
  if (!fs.existsSync(filePath)) {
    return { skipped: true, updatedReport: 0, updatedSarif: 0 };
  }

  const rows = parseCsv(fs.readFileSync(filePath, 'utf8'));
  const jsonReportIds = distinctReportScanIds('json');
  const sarifReportIds = distinctReportScanIds('sarif');
  let updatedReport = 0;
  let updatedSarif = 0;

  for (const row of rows) {
    const scanId = row.scan_id;
    const reportSuccess = jsonReportIds.has(scanId);
    const sarifSuccess = sarifReportIds.has(scanId);
    if (!row.report_success && String(row.report_success).toLowerCase() !== String(reportSuccess)) {
      updatedReport += 1;
      row.report_success = reportSuccess;
    }
    if (!row.sarif_success && String(row.sarif_success).toLowerCase() !== String(sarifSuccess)) {
      updatedSarif += 1;
      row.sarif_success = sarifSuccess;
    }
  }

  writeCsv(
    filePath,
    rows,
    Object.keys(rows[0] || { dataset: '', apk: '', scan_id: '', runtime_seconds: '', cpu_percent: '', ram_mb: '', report_success: '', sarif_success: '' })
  );
  return { skipped: false, updatedReport, updatedSarif };
}

function firstPresent(row, names) {
  for (const name of names) {
    if (Object.prototype.hasOwnProperty.call(row, name) && row[name] !== '') {
      return row[name];
    }
  }
  return '';
}

function runBenchmark(args) {
  if (!args.droidbench && !args.ghera) {
    return { skipped: true, reason: 'No benchmark folders were provided.' };
  }

  const commandArgs = [
    'scripts/run-benchmark-evaluation.js',
    '--api', args.api,
    '--reportgen', args.reportgen,
    '--concurrency', String(args.concurrency),
  ];
  if (args.droidbench) {
    commandArgs.push('--droidbench', args.droidbench);
  }
  if (args.ghera) {
    commandArgs.push('--ghera', args.ghera);
  }
  if (args.limit) {
    commandArgs.push('--limit', String(args.limit));
  }
  if (args.resume) {
    commandArgs.push('--resume');
  }

  const result = spawnSync(process.execPath, commandArgs, {
    cwd: process.cwd(),
    stdio: 'inherit',
    shell: false,
  });

  if (result.status !== 0) {
    throw new Error(`Benchmark scan failed with exit code ${result.status}`);
  }

  return { skipped: false };
}

function readCsvIfExists(fileName) {
  const filePath = path.join(EXPERIMENTS_DIR, fileName);
  if (!fs.existsSync(filePath)) {
    return [];
  }
  return parseCsv(fs.readFileSync(filePath, 'utf8'));
}

function truthy(value) {
  return ['1', 'true', 'yes', 'success', 'completed'].includes(String(value).trim().toLowerCase());
}

function countMissing(rows, column) {
  return rows.filter((row) => !row[column] && row[column] !== '0').length;
}

function validateArtifacts() {
  const messages = [];
  const groundTruth = readCsvIfExists('ground_truth.csv');
  const runtime = readCsvIfExists('runtime_results.csv');
  const external = readCsvIfExists('external_tool_results.csv');

  if (groundTruth.length === 0) {
    messages.push({
      level: 'missing',
      item: 'ground_truth.csv',
      detail: 'Run benchmark scans or add manually verified benchmark labels.',
    });
  } else {
    const unlabeled = groundTruth.filter((row) => !row.expected && !row.ground_truth && !row.truth).length;
    if (unlabeled > 0) {
      messages.push({
        level: 'action',
        item: 'ground_truth.csv',
        detail: `${unlabeled} row(s) have no expected/ground_truth/truth value.`,
      });
    }
  }

  if (runtime.length === 0) {
    messages.push({
      level: 'missing',
      item: 'runtime_results.csv',
      detail: 'Run benchmark scans to measure runtime, CPU, RAM, report success, and SARIF success.',
    });
  } else {
    const reportValues = runtime.filter((row) => row.report_success || row.pdf_success || row.report_generation_success);
    const sarifValues = runtime.filter((row) => row.sarif_success || row.sarif_export_success);
    const reportSuccess = reportValues.filter((row) => truthy(row.report_success || row.pdf_success || row.report_generation_success)).length;
    const sarifSuccess = sarifValues.filter((row) => truthy(row.sarif_success || row.sarif_export_success)).length;
    if (reportValues.length > 0 && reportSuccess === 0) {
      messages.push({
        level: 'action',
        item: 'runtime_results.csv',
        detail: 'Report-generation success is measured but currently 0%. Fix ReportGen or remove the claim.',
      });
    }
    if (sarifValues.length > 0 && sarifSuccess === 0) {
      messages.push({
        level: 'action',
        item: 'runtime_results.csv',
        detail: 'SARIF export success is measured but currently 0%. Fix SARIF export or remove the claim.',
      });
    }
    const missingRuntime = countMissing(runtime, 'runtime_seconds');
    if (missingRuntime > 0) {
      messages.push({
        level: 'action',
        item: 'runtime_results.csv',
        detail: `${missingRuntime} row(s) have no runtime_seconds value.`,
      });
    }
  }

  if (external.length === 0) {
    messages.push({
      level: 'missing',
      item: 'external_tool_results.csv',
      detail: 'Import measured MobSF and Yaazhini/Vooki summary rows with --external-tool-csv.',
    });
  } else {
    for (const tool of ['MobSF', 'APKDeepLens']) {
      const row = external.find((item) => String(item.tool || item.scanner).toLowerCase() === tool.toLowerCase());
      if (!row) {
        messages.push({
          level: 'action',
          item: 'external_tool_results.csv',
          detail: `${tool} row is missing.`,
        });
      }
    }
  }

  return messages;
}

function writeStatus(messages, backupDir, actions) {
  const status = {
    generated_at: new Date().toISOString(),
    experiments_dir: EXPERIMENTS_DIR,
    backup_dir: backupDir,
    actions,
    messages,
    ready_for_final_journal_tables: messages.length === 0,
  };
  const destination = path.join(EXPERIMENTS_DIR, 'paper_evaluation_status.json');
  fs.writeFileSync(destination, JSON.stringify(status, null, 2), 'utf8');
  return destination;
}

function main() {
  const args = parseArgs(process.argv);
  ensureDir(EXPERIMENTS_DIR);

  const backupDir = args.validateOnly ? null : backupExistingFiles();
  const actions = [];

  if (backupDir) {
    actions.push(`Backed up existing CSVs to ${backupDir}`);
  }

  if (!args.noScan) {
    const result = runBenchmark(args);
    actions.push(result.skipped ? `Skipped benchmark scan: ${result.reason}` : 'Ran MobileSec benchmark scan.');
  }

  if (args.externalToolCsv) {
    const destination = normalizeExternalToolCsv(args.externalToolCsv);
    actions.push(`Imported external tool rows to ${destination}`);
  }

  if (args.deriveGroundTruth) {
    const result = deriveGroundTruthLabels();
    actions.push(
      result.skipped
        ? 'Skipped ground-truth derivation because ground_truth.csv does not exist.'
        : `Derived or corrected ${result.updated} benchmark expected label(s).`
    );
  }

  if (args.syncReportSuccess) {
    const result = syncReportSuccessFromMongo();
    actions.push(
      result.skipped
        ? 'Skipped report-success sync because runtime_results.csv does not exist.'
        : `Synced report_success for ${result.updatedReport} row(s) and sarif_success for ${result.updatedSarif} row(s) from MongoDB reports.`
    );
  }

  const messages = validateArtifacts();
  const statusPath = writeStatus(messages, backupDir, actions);

  console.log('\nPaper evaluation automation complete.');
  for (const action of actions) {
    console.log(`- ${action}`);
  }

  if (messages.length > 0) {
    console.log('\nRemaining items:');
    for (const message of messages) {
      console.log(`- [${message.level}] ${message.item}: ${message.detail}`);
    }
  } else {
    console.log('\nAll expected paper-table inputs are present and non-empty.');
  }
  console.log(`Status file: ${statusPath}`);
}

main();
