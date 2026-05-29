#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

function parseArgs(argv) {
  const args = {
    input: path.resolve('backend', 'ml-model', 'experiments', 'security_score_expert_review.csv'),
    output: path.resolve('backend', 'ml-model', 'experiments', 'security_score_validation.json'),
  };
  for (let index = 2; index < argv.length; index += 1) {
    if (argv[index] === '--input') args.input = path.resolve(argv[++index]);
    else if (argv[index] === '--output') args.output = path.resolve(argv[++index]);
    else throw new Error(`Unknown argument: ${argv[index]}`);
  }
  return args;
}

function rowsFromCsv(content) {
  const lines = content.trim().split(/\r?\n/);
  const headers = (lines.shift() || '').split(',').map((value) => value.trim());
  return lines.filter(Boolean).map((line) => {
    const values = line.split(',').map((value) => value.trim());
    return Object.fromEntries(headers.map((header, index) => [header, values[index] || '']));
  });
}

function pearson(left, right) {
  if (left.length < 2 || right.length !== left.length) return null;
  const meanLeft = left.reduce((sum, value) => sum + value, 0) / left.length;
  const meanRight = right.reduce((sum, value) => sum + value, 0) / right.length;
  let numerator = 0;
  let squareLeft = 0;
  let squareRight = 0;
  left.forEach((value, index) => {
    const a = value - meanLeft;
    const b = right[index] - meanRight;
    numerator += a * b;
    squareLeft += a * a;
    squareRight += b * b;
  });
  const denominator = Math.sqrt(squareLeft * squareRight);
  return denominator ? numerator / denominator : null;
}

function rank(values) {
  const sorted = values.map((value, index) => ({ value, index })).sort((a, b) => a.value - b.value);
  const ranks = Array(values.length);
  sorted.forEach((entry, index) => { ranks[entry.index] = index + 1; });
  return ranks;
}

function main() {
  const args = parseArgs(process.argv);
  if (!fs.existsSync(args.input)) throw new Error(`Review CSV not found: ${args.input}`);
  const rows = rowsFromCsv(fs.readFileSync(args.input, 'utf8')).filter((row) =>
    row.mobile_risk_score !== '' && row.expert_severity_score !== '' && row.cvss_score !== ''
  );
  if (rows.length < 2) throw new Error('At least two completed expert-review rows are required.');
  const mobile = rows.map((row) => Number(row.mobile_risk_score));
  const expert = rows.map((row) => Number(row.expert_severity_score));
  const cvss = rows.map((row) => Number(row.cvss_score));
  const result = {
    generated_at: new Date().toISOString(),
    reviewed_apks: rows.length,
    interpretation: 'mobile_risk_score must be 100 minus the APKScanner security score, so higher values consistently mean higher risk.',
    pearson_mobile_risk_vs_expert: pearson(mobile, expert),
    pearson_mobile_risk_vs_cvss: pearson(mobile, cvss),
    spearman_mobile_risk_vs_expert: pearson(rank(mobile), rank(expert)),
    spearman_mobile_risk_vs_cvss: pearson(rank(mobile), rank(cvss)),
  };
  fs.mkdirSync(path.dirname(args.output), { recursive: true });
  fs.writeFileSync(args.output, `${JSON.stringify(result, null, 2)}\n`, 'utf8');
  console.log(`Security-score validation written: ${args.output}`);
}

try {
  main();
} catch (error) {
  console.error(error.message);
  process.exit(1);
}
