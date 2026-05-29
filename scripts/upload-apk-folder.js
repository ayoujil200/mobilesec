#!/usr/bin/env node

const fs = require('fs');
const http = require('http');
const https = require('https');
const path = require('path');

const DEFAULT_API = 'http://localhost:5000';
const ALLOWED_EXTENSIONS = new Set(['.apk', '.aab']);

function parseArgs(argv) {
  const args = {
    folder: null,
    api: DEFAULT_API,
    force: true,
    concurrency: 1,
  };

  for (let i = 2; i < argv.length; i += 1) {
    const value = argv[i];
    if (value === '--api') {
      args.api = argv[++i];
    } else if (value === '--force') {
      args.force = true;
    } else if (value === '--no-force') {
      args.force = false;
    } else if (value === '--concurrency') {
      args.concurrency = Math.max(1, Number.parseInt(argv[++i], 10) || 1);
    } else if (!args.folder) {
      args.folder = value;
    } else {
      throw new Error(`Unknown argument: ${value}`);
    }
  }

  if (!args.folder) {
    throw new Error(
      'Usage: node scripts/upload-apk-folder.js <apk-folder> [--api http://localhost:5000] [--force|--no-force] [--concurrency 1]'
    );
  }

  return args;
}

function findApkFiles(rootDir) {
  const files = [];
  const entries = fs.readdirSync(rootDir, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(rootDir, entry.name);
    if (entry.isDirectory()) {
      files.push(...findApkFiles(fullPath));
    } else if (entry.isFile() && ALLOWED_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) {
      files.push(fullPath);
    }
  }

  return files.sort((a, b) => a.localeCompare(b));
}

function uploadFile(filePath, apiBaseUrl, force) {
  return new Promise((resolve, reject) => {
    const url = new URL(`/api/scan?force=${force ? 'true' : 'false'}`, apiBaseUrl);
    const boundary = `----MobileSecBatch${Date.now()}${Math.random().toString(16).slice(2)}`;
    const filename = path.basename(filePath);
    const fileSize = fs.statSync(filePath).size;
    const preamble = Buffer.from(
      `--${boundary}\r\n` +
      `Content-Disposition: form-data; name="file"; filename="${filename.replace(/"/g, '\\"')}"\r\n` +
      'Content-Type: application/vnd.android.package-archive\r\n\r\n'
    );
    const closing = Buffer.from(`\r\n--${boundary}--\r\n`);
    const contentLength = preamble.length + fileSize + closing.length;
    const transport = url.protocol === 'https:' ? https : http;

    const request = transport.request(
      {
        method: 'POST',
        hostname: url.hostname,
        port: url.port || (url.protocol === 'https:' ? 443 : 80),
        path: `${url.pathname}${url.search}`,
        headers: {
          'Content-Type': `multipart/form-data; boundary=${boundary}`,
          'Content-Length': contentLength,
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
            resolve({
              file: filePath,
              statusCode: response.statusCode,
              scanId: body.scan_id || null,
              status: body.status || 'unknown',
              body,
            });
          } else {
            reject(new Error(`HTTP ${response.statusCode} for ${filename}: ${rawBody}`));
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

async function runPool(files, concurrency, worker) {
  const results = [];
  let nextIndex = 0;

  async function runWorker() {
    while (nextIndex < files.length) {
      const index = nextIndex;
      nextIndex += 1;
      results[index] = await worker(files[index], index);
    }
  }

  const workers = Array.from({ length: Math.min(concurrency, files.length) }, runWorker);
  await Promise.all(workers);
  return results;
}

async function main() {
  const args = parseArgs(process.argv);
  const folder = path.resolve(args.folder);

  if (!fs.existsSync(folder) || !fs.statSync(folder).isDirectory()) {
    throw new Error(`Folder not found: ${folder}`);
  }

  const files = findApkFiles(folder);
  if (files.length === 0) {
    console.log(`No APK/AAB files found in ${folder}`);
    return;
  }

  console.log(`Found ${files.length} APK/AAB file(s).`);
  console.log(`Uploading to ${args.api}/api/scan with concurrency=${args.concurrency}`);

  const startedAt = Date.now();
  const failures = [];
  const results = await runPool(files, args.concurrency, async (filePath, index) => {
    const label = `[${index + 1}/${files.length}] ${path.basename(filePath)}`;
    console.log(`${label} uploading...`);
    try {
      const result = await uploadFile(filePath, args.api, args.force);
      console.log(`${label} done scan_id=${result.scanId || 'N/A'} status=${result.status}`);
      return result;
    } catch (error) {
      failures.push({ file: filePath, error: error.message });
      console.error(`${label} failed: ${error.message}`);
      return { file: filePath, error: error.message };
    }
  });

  const outputPath = path.join(process.cwd(), `batch-upload-results-${new Date().toISOString().replace(/[:.]/g, '-')}.json`);
  fs.writeFileSync(outputPath, JSON.stringify({ api: args.api, folder, results, failures }, null, 2));

  const elapsedSeconds = ((Date.now() - startedAt) / 1000).toFixed(1);
  console.log(`Finished in ${elapsedSeconds}s. Success=${files.length - failures.length}, Failed=${failures.length}`);
  console.log(`Result file: ${outputPath}`);

  if (failures.length > 0) {
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
