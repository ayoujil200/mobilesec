#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

function parseArgs(argv) {
  const args = {
    input: path.resolve('backend', 'ml-model', 'experiments', 'fixsuggest_expert_review.csv'),
    output: path.resolve('backend', 'ml-model', 'experiments', 'fixsuggest_evaluation.json'),
  };
  for (let index = 2; index < argv.length; index += 1) {
    if (argv[index] === '--input') args.input = path.resolve(argv[++index]);
    else if (argv[index] === '--output') args.output = path.resolve(argv[++index]);
    else if (argv[index] === '--help' || argv[index] === '-h') {
      console.log('Usage: node scripts/evaluate-fixsuggest-review.js [--input review.csv] [--output results.json]');
      process.exit(0);
    } else throw new Error(`Unknown argument: ${argv[index]}`);
  }
  return args;
}

function parseCsv(content) {
  const lines = content.trim().split(/\r?\n/);
  if (lines.length < 2) return [];
  const headers = lines.shift().split(',').map((header) => header.trim());
  return lines.filter(Boolean).map((line) => {
    const fields = line.split(',').map((field) => field.trim());
    return Object.fromEntries(headers.map((header, index) => [header, fields[index] || '']));
  });
}

function isTrue(value) {
  return ['true', 'yes', '1', 'accepted', 'correct'].includes(String(value).trim().toLowerCase());
}

function main() {
  const args = parseArgs(process.argv);
  if (!fs.existsSync(args.input)) {
    throw new Error(`Expert review CSV not found: ${args.input}`);
  }
  const rows = parseCsv(fs.readFileSync(args.input, 'utf8'));
  if (rows.length === 0) throw new Error('Expert review CSV has no review rows.');

  const accepted = rows.filter((row) => isTrue(row.acceptable)).length;
  const correct = rows.filter((row) => isTrue(row.correct)).length;
  const requiresModification = rows.filter((row) => isTrue(row.requires_modification)).length;
  const result = {
    generated_at: new Date().toISOString(),
    input: args.input,
    reviewed_suggestions: rows.length,
    acceptable_suggestions: accepted,
    acceptable_rate: accepted / rows.length,
    correct_suggestions: correct,
    correctness_rate: correct / rows.length,
    requires_modification: requiresModification,
    modification_rate: requiresModification / rows.length,
    methodology: 'Manual expert annotations only; no metric is inferred from LLM output.',
  };
  fs.mkdirSync(path.dirname(args.output), { recursive: true });
  fs.writeFileSync(args.output, `${JSON.stringify(result, null, 2)}\n`, 'utf8');
  console.log(`FixSuggest evaluation written: ${args.output}`);
}

try {
  main();
} catch (error) {
  console.error(error.message);
  process.exit(1);
}
