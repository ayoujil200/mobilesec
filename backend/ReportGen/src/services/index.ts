import fs from 'fs/promises';
import path from 'path';
import { v4 as uuidv4 } from 'uuid';
import Handlebars from 'handlebars';
import puppeteer from 'puppeteer';

// Register helpers
Handlebars.registerHelper('escapeCode', (code: any) => {
  if (!code && code !== 0) return '';
  return Handlebars.escapeExpression(String(code));
});

import { Report, ReportOptions } from '../models';
import logger from '../utils/logger';

export const aggregatorService = {
  aggregateResults: (results: Record<string, any[]>) => {
    const all: any[] = [];
    for (const v of Object.values(results || {})) {
      if (Array.isArray(v)) all.push(...v);
    }
    return all;
  },
  aggregate: (results: Record<string, any[]>) => {
    // alias used by some code paths
    return (aggregatorService.aggregateResults as any)(results);
  }
};

export const deduplicatorService = {
  deduplicate: (arr: any[]) => arr // naive — no-op
};

export const metricsService = {
  calculateMetrics: (arr: any[]) => {
    const total = arr?.length || 0;
    const bySeverity: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const it of (arr || [])) {
      const s = (it?.severity || 'info').toString().toLowerCase();
      if (!bySeverity[s]) bySeverity[s] = 0;
      bySeverity[s]++;
    }
    return {
      total,
      bySeverity,
      byCategory: {},
      securityScore: 100
    };
  },
  generatePriorityRecommendations: (_arr: any[], _metrics: any) => []
};

export const jsonExporterService = {
  exportToJson: async (report: Report, opts: any = {}) => {
    const dir = process.env.TEMP_DIR || './tmp';
    await fs.mkdir(dir, { recursive: true });
    const fileName = `report-${report.reportId || uuidv4()}.json`;
    const p = path.join(dir, fileName);
    await fs.writeFile(p, opts.pretty ? JSON.stringify(report, null, 2) : JSON.stringify(report));
    return p;
  },
  getJsonData: async (report: Report, opts: any = {}) => {
    return opts.pretty ? JSON.stringify(report, null, 2) : JSON.stringify(report);
  }
};

export const sarifExporterService = {
  exportToSarif: async (report: Report) => {
    const dir = process.env.TEMP_DIR || './tmp';
    await fs.mkdir(dir, { recursive: true });
    const filePath = path.join(dir, `report-${report.reportId || uuidv4()}.sarif.json`);
    const findings = report.vulnerabilities || [];
    const rules = new Map<string, any>();

    const results = findings.map((finding: any, index: number) => {
      const ruleId = String(finding.ruleId || finding.rule_id || finding.category || `MOBILESEC-${index + 1}`);
      const title = String(finding.title || finding.name || ruleId);
      const severity = String(finding.severity || 'info').toLowerCase();
      const level = severity === 'critical' || severity === 'high'
        ? 'error'
        : severity === 'medium'
          ? 'warning'
          : 'note';

      if (!rules.has(ruleId)) {
        rules.set(ruleId, {
          id: ruleId,
          name: title,
          shortDescription: { text: title },
          fullDescription: { text: String(finding.description || title) },
          help: { text: String(finding.recommendation || 'Review and remediate this finding.') },
        });
      }

      const result: any = {
        ruleId,
        level,
        message: { text: String(finding.description || title) },
      };
      const sourceFile = finding.file || finding.filePath || finding.file_path;
      if (sourceFile) {
        result.locations = [{
          physicalLocation: {
            artifactLocation: { uri: String(sourceFile) },
            region: { startLine: Number(finding.line || finding.lineNumber || finding.line_number || 1) },
          },
        }];
      }
      return result;
    });

    const sarif = {
      version: '2.1.0',
      $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
      runs: [{
        tool: {
          driver: {
            name: 'MobileSec',
            informationUri: 'https://github.com/Imadait01/MobileSec',
            rules: Array.from(rules.values()),
          },
        },
        results,
      }],
    };

    await fs.writeFile(filePath, JSON.stringify(sarif, null, 2), 'utf8');
    return filePath;
  }
};

export const fileWatcherService = {
  // No-op stub for file watcher used in dev flows
  on: (_event: string, _fn: (...args: any[]) => void) => {},
  readAllInputFiles: async () => ({ files: [], errors: [] }),
  getInputDirectory: () => process.env.TEMP_DIR || './tmp',
  combineFilesToRequest: (files: any[], projectName = 'Scan', format = 'pdf', opts: any = {}) => ({
    projectName,
    scanId: undefined,
    format,
    scanResults: {},
    options: opts
  }),
  clearInputDirectory: async () => true
};

// A lightweight PDF generator fallback that writes a minimal valid PDF with the project name.
export const pdfGeneratorService = {
  templateExists: async (template: string) => {
    const candidates = [
      path.join(__dirname, '..', 'templates', `${template}.html`),
      path.join(process.cwd(), 'src', 'templates', `${template}.html`)
    ];
    for (const p of candidates) {
      try { await fs.access(p); return true; } catch (e) { /* continue */ }
    }
    return false;
  },

  generatePdf: async (report: Report, options: ReportOptions = {}, requestedPath?: string) => {
    const dir = process.env.TEMP_DIR || './tmp';
    await fs.mkdir(dir, { recursive: true });
    const out = requestedPath || path.join(dir, `report-${report.reportId || uuidv4()}.pdf`);

    const templateName = (options.template as string) || 'security_report';
    // Look for templates in dist (when running compiled) or src (when using copied templates)
    const templateCandidates = [
      path.join(__dirname, '..', 'templates', `${templateName}.html`),
      path.join(process.cwd(), 'src', 'templates', `${templateName}.html`)
    ];
    const cssCandidates = [
      path.join(__dirname, '..', 'templates', 'assets', 'css', 'security_report.css'),
      path.join(process.cwd(), 'src', 'templates', 'assets', 'css', 'security_report.css')
    ];

    // Debug: log cwd and candidate paths
    logger.debug('Template search', { cwd: process.cwd(), templateCandidates, cssCandidates });

    // Find first existing template
    let templatePath: string | null = null;
    for (const p of templateCandidates) {
      try { await fs.access(p); templatePath = p; break; } catch (err) { logger.debug('Template candidate not found', { p, err: String(err) }); }
    }

    let cssPath: string | null = null;
    for (const c of cssCandidates) {
      try { await fs.access(c); cssPath = c; break; } catch (err) { logger.debug('CSS candidate not found', { c, err: String(err) }); }
    }

    if (!templatePath) throw new Error(`Template not found: ${templateName}`);

    // If template exists, attempt Handlebars -> Puppeteer rendering
    try {
      const tplRaw = await fs.readFile(templatePath, 'utf8');
      const tpl = Handlebars.compile(tplRaw);

      // Prepare template data
      // Normalize services so templates can rely on service.findings array and provide per-service counts
      const normalizedServices: Record<string, any> = {};
      for (const [k, v] of Object.entries(report.services || {})) {
        // Normalize a variety of service shapes into an array of findings
        let findings: any[] = [];
        if (Array.isArray(v)) findings = v as any[];
        else if (v && Array.isArray((v as any).findings)) findings = (v as any).findings;
        else if (v && Array.isArray((v as any).results)) findings = (v as any).results;
        else if (v && typeof v === 'object') findings = [v];

        // Ensure a predictable minimal shape for each finding using shared normalizer
        // Lazy-require the normalizer to avoid circular import issues
        // eslint-disable-next-line @typescript-eslint/no-var-requires
        const { normalizeFinding: nf } = require('../utils/normalizeFinding');
        findings = (findings || []).map((f: any) => {
          try {
            const n = nf(f, k);
            return {
              title: n.title,
              description: n.description,
              severity: (n.severity || 'info').toString().toLowerCase(),
              file: n.file || '',
              line: n.line || 1,
              recommendation: n.recommendation,
              raw: n.raw,
              rawString: n.rawString
            } as any;
          } catch (e) {
            return {
              title: String(f && (f.title || f.rule_id || f.type) || 'Finding'),
              description: String(f && (f.description || f.message) || ''),
              severity: (f && f.severity) ? String(f.severity).toLowerCase() : 'info',
              file: (f && (f.file || f.file_path || f.filePath)) || '',
              line: (f && (f.line || f.lineNumber || f.line_number)) || 1,
              raw: f,
            };
          }
        });

        // Compute counts by severity for quick per-service summary
        const counts = { total: findings.length, bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } };
        for (const ff of findings) {
          const s = (ff.severity || 'info');
          if (!counts.bySeverity[s]) counts.bySeverity[s] = 0;
          counts.bySeverity[s]++;
        }

        // Keep raw service output if provided (useful to display original JSON per microservice)
        normalizedServices[k] = {
          findings,
          counts,
          raw: (v && ((v as any).raw || (v as any).rawString)) || undefined,
          rawString: (v && ((v as any).rawString || ((v as any).raw ? JSON.stringify((v as any).raw, null, 2) : undefined))) || undefined,
          top: findings.slice(0, options.maxFindingsPerService || 10)
        };
      }

      const data = {
        projectName: report.projectName || report.reportId,
        generatedAt: report.generatedAt || new Date().toISOString(),
        metrics: report.metrics || {},
        vulnerabilities: report.vulnerabilities || [],
        services: normalizedServices,
        riskLevel: (report.metrics && report.metrics.securityScore && report.metrics.securityScore < 50) ? 'High' : 'Medium',
        cssUrl: cssPath ? `file://${cssPath}` : undefined,
      };

      logger.info('Using template and css', { templatePath, cssPath, servicesCount: Object.keys(normalizedServices).length });

      const html = tpl(data);
      const htmlPath = path.join(dir, `report-${report.reportId || uuidv4()}.html`);
      await fs.writeFile(htmlPath, html, 'utf8');

      logger.info('Rendering PDF via Puppeteer', { htmlPath, out });

      const launchOptions: any = {
        args: ['--no-sandbox', '--disable-setuid-sandbox']
      };

      // If PUPPETEER_EXECUTABLE_PATH is set, use it
      if (process.env.PUPPETEER_EXECUTABLE_PATH) launchOptions.executablePath = process.env.PUPPETEER_EXECUTABLE_PATH;

      const browser = await puppeteer.launch(launchOptions);
      const page = await browser.newPage();

      // Use absolute file:// URL for CSS to be picked up by the template (fixes Windows relative path issues)
      const absHtmlPath = path.resolve(htmlPath);
      logger.debug('Navigating to HTML snapshot', { absHtmlPath });
      await page.goto(`file://${absHtmlPath}`, { waitUntil: 'networkidle0' });

      await page.pdf({ path: out, format: 'A4', printBackground: true });
      await browser.close();

      logger.info('Wrote PDF via Puppeteer', { out });
      return out;
    } catch (e: any) {
      logger.warn('Puppeteer/Handlebars rendering failed, falling back to minimal PDF', { error: String(e), stack: e?.stack });
      console.error('Puppeteer rendering error:', e && (e.stack || e.message || e));

      // Fallback: minimal PDF (legacy behaviour)
      const content = `%PDF-1.1
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>
endobj
4 0 obj
<< /Length 44 >>
stream
BT /F1 24 Tf 72 720 Td (${(report.projectName || report.reportId || 'Report').toString().replace(/\)/g, '')}) Tj ET
endstream
endobj
5 0 obj
<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>
endobj
xref
0 6
0000000000 65535 f 
0000000010 00000 n 
0000000067 00000 n 
0000000127 00000 n 
0000000210 00000 n 
0000000285 00000 n 
trailer
<< /Root 1 0 R >>
startxref
376
%%EOF
`;
      try {
        logger.debug('Attempting to write fallback PDF to', { path: out });
        await fs.writeFile(out, content, { encoding: 'utf8' });
        return out;
      } catch (e2: any) {
        logger.warn('Failed to write fallback PDF to requested path, attempting /tmp', { path: out, error: e2 });
        const fallback = path.join('/tmp', path.basename(out));
        await fs.writeFile(fallback, content, { encoding: 'utf8' });
        return fallback;
      }
    }
  }
};

export const jsonToPdfService = {
  convert: async (jsonPath: string, outPath?: string, _opts?: any) => {
    // naive: copy json to .pdf to provide a fallback PDF file
    const target = outPath || jsonPath.replace(/\.json$/i, '.pdf');
    const data = await fs.readFile(jsonPath, { encoding: 'utf8' });
    await fs.writeFile(target, `Fallback PDF\n\n${data}`);
    return target;
  }
};
