#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const { request, normaliseTarget } = require('../src/http');
const { runAll } = require('../src/checks');
const { narrate, loadConfig } = require('../src/llm');
const { renderTerminal, renderMarkdown, renderJson } = require('../src/report');
const { renderHtml } = require('../src/report-html');
const { score } = require('../src/scoring');
const { LIMITS } = require('../src/mapping');
const pkg = require('../package.json');

const HELP = `
dpdp-web-check ${pkg.version}

Passive DPDP posture check for a website. Zero dependencies. Your key, your machine.

USAGE
  dpdp-web-check <domain-or-url> [options]

OPTIONS
  --format <text|html|md|json>   Output format. Default: text
  --out [file]                   Save the report to a file. If you omit the
                                  filename, one is generated from the domain
                                  and date, e.g.
                                  dpdp-report-protevixinfosec-com-2026-08-18.html
  --no-ai                        Skip the narrative even if a key is configured
  --timeout <ms>                 Per-request timeout. Default: 15000
  --version                      Print version
  --help                         This message

SAVING A REPORT
  The terminal output can run long. To get a readable report instead:

    dpdp-web-check example.com --format html --out

  This opens beautifully in any browser, fully self-contained (no internet
  needed to view it, no fonts or scripts loaded from anywhere). --format html
  always saves to a file automatically, even without --out, because a raw
  HTML document dumped into a terminal isn't something you can read.

  Other formats:
    --format md --out       Markdown, good for pasting into GitHub/Notion
    --format json --out     Machine-readable, for scripts and CI
    --format text --out     Plain terminal text (colours stripped)

  There is no direct PDF export. Doing that without Puppeteer/Chromium would
  mean either losing the zero-dependency guarantee or shipping a fragile
  hand-rolled PDF writer. Open the saved HTML in a browser and use
  Print > Save as PDF instead — one extra click, and it keeps "zero
  dependencies" honest.

BRING YOUR OWN KEY (optional)
  The tool is fully functional without a key. A key only adds a plain-English
  narrative on top of the deterministic findings. Your key is sent to your
  chosen provider and nowhere else.

    export DPDP_LLM="anthropic/claude-sonnet-4-6"
    export LLM_API_KEY="sk-ant-..."

  Other providers:
    export DPDP_LLM="openai/gpt-5.4"
    export DPDP_LLM="google/gemini-3-pro-preview"
    export DPDP_LLM="llama3.1"  LLM_API_BASE="http://localhost:11434/v1"

  Or write ~/.dpdp-web-check/config.json:
    { "model": "anthropic/claude-sonnet-4-6", "apiKey": "sk-ant-..." }

EXIT CODES
  0  no failing checks
  1  one or more checks failed
  2  the target could not be reached

AUTHORISED USE ONLY
  Run this against sites you own or have written permission to assess.

Made by Protevix Infosec. Apache-2.0.
`;

function parseArgs(argv) {
  const opts = { format: 'text', out: null, wantsOut: false, ai: true, timeout: 15000, target: null };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--help' || a === '-h') return { help: true };
    if (a === '--version' || a === '-v') return { version: true };
    else if (a === '--format') opts.format = argv[++i];
    else if (a === '--out') {
      opts.wantsOut = true;
      // Only consume the next token as a filename if it's not another flag
      // and not the positional target.
      const next = argv[i + 1];
      if (next && !next.startsWith('-')) {
        opts.out = next;
        i += 1;
      }
    } else if (a === '--no-ai') opts.ai = false;
    else if (a === '--timeout') opts.timeout = parseInt(argv[++i], 10);
    else if (!a.startsWith('-') && !opts.target) opts.target = a;
  }
  return opts;
}

function extFor(format) {
  if (format === 'json') return 'json';
  if (format === 'md' || format === 'markdown') return 'md';
  if (format === 'html') return 'html';
  return 'txt';
}

function defaultOutFilename(hostname, format) {
  const date = new Date().toISOString().slice(0, 10);
  const safeHost = hostname.replace(/[^a-z0-9.-]/gi, '-');
  return `dpdp-report-${safeHost}-${date}.${extFor(format)}`;
}

function stripAnsi(text) {
  // eslint-disable-next-line no-control-regex
  return text.replace(/\u001b\[[0-9;]*m/g, '');
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));

  if (opts.help || (!opts.target && !opts.version)) {
    process.stdout.write(HELP);
    process.exit(opts.help ? 0 : 2);
  }
  if (opts.version) {
    process.stdout.write(`${pkg.version}\n`);
    process.exit(0);
  }

  let url;
  try {
    url = normaliseTarget(opts.target);
  } catch (err) {
    process.stderr.write(`Invalid target: ${err.message}\n`);
    process.exit(2);
  }

  const quiet = opts.format === 'json';
  const log = (msg) => {
    if (!quiet) process.stderr.write(`${msg}\n`);
  };

  log(`\n  Checking ${url.origin} ...`);

  const response = await request(url.toString(), { timeout: opts.timeout });
  if (!response.ok) {
    process.stderr.write(`\n  Could not reach ${url.origin}: ${response.error}\n\n`);
    process.exit(2);
  }

  const ctx = { url, response };
  const findings = await runAll(ctx, (name) => log(`    - ${name}`));

  let narrative = null;
  if (opts.ai) {
    const cfg = loadConfig();
    if (cfg.model && (cfg.apiKey || cfg.apiBase)) {
      log(`    - narrative via ${cfg.model}`);
      try {
        narrative = await narrate(url.origin, findings, LIMITS);
      } catch (err) {
        log(`      narrative skipped: ${err.message}`);
      }
    } else {
      log('    - narrative skipped (no key configured, run --help to set one up)');
    }
  }

  const result = { target: url.origin, findings, narrative, score: score(findings) };

  // HTML is unreadable dumped raw into a terminal, so it always saves to a
  // file, with or without an explicit --out.
  const isHtml = opts.format === 'html';
  if (isHtml) opts.wantsOut = true;

  let output;
  if (opts.format === 'json') output = renderJson(result);
  else if (opts.format === 'md' || opts.format === 'markdown') output = renderMarkdown(result);
  else if (isHtml) output = renderHtml(result);
  else output = renderTerminal(result);

  if (!isHtml) {
    process.stdout.write(`${output}\n`);
  }

  if (opts.wantsOut) {
    const filename = opts.out || defaultOutFilename(url.hostname, opts.format);
    const toWrite = opts.format === 'text' ? stripAnsi(output) : output;
    fs.writeFileSync(filename, toWrite, 'utf8');
    process.stderr.write(`\n  Saved report to ${filename}\n`);
    if (isHtml) {
      process.stderr.write('  Open it in any browser to view it. No internet connection needed.\n');
    } else if (opts.format === 'md') {
      process.stderr.write('  Open it in any editor, or your browser, and use Print > Save as PDF.\n');
    }
  }

  const failed = findings.some((f) => f.status === 'fail');
  process.exit(failed ? 1 : 0);
}

main().catch((err) => {
  process.stderr.write(`\nUnexpected error: ${err && err.stack ? err.stack : err}\n`);
  process.exit(2);
});
