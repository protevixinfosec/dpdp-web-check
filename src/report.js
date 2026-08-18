'use strict';

const { clause, LIMITS, ENFORCEMENT_NOTE } = require('./mapping');
const { renderBanner } = require('./banner');
const { score, tally } = require('./scoring');

const C = {
  reset: '\u001b[0m',
  dim: '\u001b[2m',
  bold: '\u001b[1m',
  red: '\u001b[31m',
  orange: '\u001b[38;5;208m',
  yellow: '\u001b[33m',
  green: '\u001b[32m',
  blue: '\u001b[34m',
  grey: '\u001b[90m',
};

const NO_COLOUR = process.env.NO_COLOR !== undefined || !process.stdout.isTTY;
const paint = (code, text) => (NO_COLOUR ? text : `${code}${text}${C.reset}`);

const STATUS_MARK = {
  pass: () => paint(C.green, 'PASS'),
  fail: () => paint(C.red, 'FAIL'),
  warn: () => paint(C.yellow, 'WARN'),
  info: () => paint(C.blue, 'INFO'),
  unknown: () => paint(C.grey, ' ?  '),
};

function renderTerminal(result) {
  const { target, findings, narrative } = result;
  const lines = [];
  const s = score(findings);
  const t = tally(findings);

  // --- Banner -----------------------------------------------------------
  lines.push(renderBanner(hostOf(target), process.stdout.columns));
  lines.push(paint(C.grey, `  ${new Date().toISOString()}`));
  lines.push('');

  // --- Summary FIRST: the thing someone glances at before scrolling -----
  lines.push(paint(C.bold, '  SUMMARY'));
  lines.push('');
  lines.push(
    `  ${paint(C.green, `${t.pass} pass`)}   ${paint(C.red, `${t.fail} fail`)}   ${paint(C.yellow, `${t.warn} warn`)}   ${paint(C.blue, `${t.info} info`)}`,
  );
  if (s !== null) {
    lines.push('');
    lines.push(`  Observable safeguards score: ${paint(C.bold, `${s}/100`)}`);
    lines.push(paint(C.grey, '  This is not a compliance score. See limits at the end of this report.'));
  }
  lines.push('');

  if (narrative) {
    lines.push(paint(C.bold, '  NARRATIVE'));
    lines.push('');
    narrative.split('\n').forEach((l) => lines.push(`  ${l}`));
    lines.push('');
  }

  // --- Findings, grouped --------------------------------------------------
  const bad = findings.filter((f) => f.status === 'fail' || f.status === 'warn');
  const good = findings.filter((f) => f.status === 'pass');
  const rest = findings.filter((f) => f.status === 'info' || f.status === 'unknown');

  const printGroup = (title, group, detailed) => {
    if (!group.length) return;
    lines.push(paint(C.bold, `  ${title}`));
    lines.push('');
    for (const f of group) {
      const refs = f.clauses.map((c) => clause(c).ref.replace('DPDP Act 2023, ', '').replace('DPDP Rules 2025, ', '')).join(', ');
      lines.push(`  [${STATUS_MARK[f.status]()}] ${paint(C.bold, f.id)}  ${f.title}`);
      lines.push(paint(C.grey, `        ${refs || 'no clause mapping'}`));
      if (detailed) {
        wrap(f.evidence, 74).forEach((l) => lines.push(paint(C.dim, `        ${l}`)));
        lines.push('');
        wrap(f.why, 74).forEach((l) => lines.push(`        ${l}`));
        if (f.fix) {
          lines.push('');
          wrap(`Fix: ${f.fix}`, 74).forEach((l) => lines.push(paint(C.green, `        ${l}`)));
        }
      }
      lines.push('');
    }
  };

  printGroup('NEEDS ATTENTION', bad, true);
  printGroup('OBSERVED AS EXPECTED', good, false);
  printGroup('CONTEXT', rest, true);

  // --- Limits LAST: the fine print, not the headline ---------------------
  lines.push(paint(C.bold, '  WHAT THIS CHECK CANNOT SEE'));
  lines.push('');
  LIMITS.forEach((l) => {
    wrap(l, 74).forEach((x, i) =>
      lines.push(paint(C.grey, i === 0 ? `  - ${x}` : `    ${x}`)),
    );
  });
  lines.push('');
  wrap(ENFORCEMENT_NOTE, 76).forEach((l) => lines.push(paint(C.grey, `  ${l}`)));
  lines.push('');
  wrap(
    'This tool performs passive observation of publicly served responses. It is an engineering aid, not legal advice, not a compliance certification, and not a penetration test.',
    76,
  ).forEach((l) => lines.push(paint(C.grey, `  ${l}`)));
  lines.push('');

  return lines.join('\n');
}

function hostOf(target) {
  try {
    return new URL(target).hostname;
  } catch (_e) {
    return String(target).replace(/^https?:\/\//, '');
  }
}

function renderMarkdown(result) {
  const { target, findings, narrative } = result;
  const s = score(findings);
  const t = tally(findings);
  const out = [];

  out.push(`# DPDP Web Check — ${target}`);
  out.push('');
  out.push(`Generated ${new Date().toISOString()}`);
  out.push('');
  out.push(`**${t.pass} pass · ${t.fail} fail · ${t.warn} warn · ${t.info} info**`);
  if (s !== null) {
    out.push('');
    out.push(`**Observable safeguards score: ${s}/100.** This is not a compliance score.`);
  }

  if (narrative) {
    out.push('');
    out.push(narrative);
  }

  out.push('');
  out.push('## Findings');
  out.push('');
  out.push('| ID | Status | Check | Clause |');
  out.push('|---|---|---|---|');
  findings.forEach((f) => {
    const refs = f.clauses.map((c) => clause(c).ref).join('; ');
    out.push(`| ${f.id} | ${f.status.toUpperCase()} | ${f.title} | ${refs || '-'} |`);
  });

  out.push('');
  out.push('## Detail');
  findings
    .filter((f) => f.status === 'fail' || f.status === 'warn' || f.status === 'info')
    .forEach((f) => {
      out.push('');
      out.push(`### ${f.id} — ${f.title} (${f.status.toUpperCase()})`);
      f.clauses.forEach((c) => {
        const cl = clause(c);
        out.push('');
        out.push(`> **${cl.ref} — ${cl.title}**  `);
        out.push(`> ${cl.text}`);
        if (cl.maxPenalty) out.push(`> _Maximum penalty: ${cl.maxPenalty}_`);
      });
      out.push('');
      out.push(`**Observed:** ${f.evidence}`);
      out.push('');
      out.push(f.why);
      if (f.fix) {
        out.push('');
        out.push(`**Fix:** ${f.fix}`);
      }
    });

  out.push('');
  out.push('## What this check cannot see');
  out.push('');
  LIMITS.forEach((l) => out.push(`- ${l}`));
  out.push('');
  out.push(`> ${ENFORCEMENT_NOTE}`);
  out.push('');
  out.push(
    '> This tool performs passive observation of publicly served responses. It is an engineering aid, not legal advice, not a compliance certification, and not a penetration test. Have the wording of any notice reviewed by a qualified advisor.',
  );
  out.push('');

  return out.join('\n');
}

function renderJson(result) {
  return JSON.stringify(
    {
      tool: 'dpdp-web-check',
      version: require('../package.json').version,
      target: result.target,
      generatedAt: new Date().toISOString(),
      observableSafeguardsScore: score(result.findings),
      tally: tally(result.findings),
      findings: result.findings.map((f) => ({
        ...f,
        clauseDetail: f.clauses.map((c) => clause(c)),
      })),
      narrative: result.narrative || null,
      limits: LIMITS,
      enforcementNote: ENFORCEMENT_NOTE,
      disclaimer:
        'Passive observation of publicly served responses. Not legal advice, not a compliance certification, not a penetration test.',
    },
    null,
    2,
  );
}

function wrap(text, width) {
  const words = String(text || '').split(/\s+/);
  const lines = [];
  let line = '';
  for (const w of words) {
    if ((line + w).length > width) {
      if (line) lines.push(line.trimEnd());
      line = '';
    }
    line += `${w} `;
  }
  if (line.trim()) lines.push(line.trimEnd());
  return lines;
}

module.exports = { renderTerminal, renderMarkdown, renderJson, score, tally };
