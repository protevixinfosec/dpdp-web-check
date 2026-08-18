'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { clause, LIMITS, ENFORCEMENT_NOTE } = require('./mapping');
const { score, tally } = require('./scoring');

const LOGO_BASE64 = (() => {
  try {
    return fs
      .readFileSync(path.join(__dirname, 'assets', 'logo-base64.txt'), 'utf8')
      .trim();
  } catch (_e) {
    return null; // report still renders fine without the logo
  }
})();

/**
 * Self-contained HTML report.
 *
 * Rules for this file, all deliberate:
 *   - No external stylesheet, font, script, or CDN reference. Someone opens
 *     this from a saved file, possibly offline, possibly years from now.
 *     Everything is inlined.
 *   - No client-side JavaScript that does anything beyond a details/summary
 *     toggle equivalent (native <details> covers that, so there is none).
 *   - Colour palette matches the KScan PDF report (see
 *     KScan_SampleReport_*.html): --bg-deep #070b12, --critical #ff2d55,
 *     --high #ff6b35, --medium #ffd60a-family, --low #30d158. Kept
 *     consistent so a report handed to a KScan customer looks like it came
 *     from the same house.
 */

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function nl2br(str) {
  return escapeHtml(str).replace(/\n/g, '<br>');
}

const STATUS_META = {
  pass: { label: 'PASS', colour: '#30d158' },
  fail: { label: 'FAIL', colour: '#ff2d55' },
  warn: { label: 'WARN', colour: '#ffd60a' },
  info: { label: 'INFO', colour: '#0e6eff' },
  unknown: { label: '?', colour: '#4a5a7a' },
};

function findingCard(f, detailed) {
  const meta = STATUS_META[f.status] || STATUS_META.unknown;
  const refs = f.clauses
    .map((c) => {
      const cl = clause(c);
      return `<span class="clause-tag" title="${escapeHtml(cl.text)}">${escapeHtml(cl.ref)}</span>`;
    })
    .join(' ');

  const detail = detailed
    ? `
      <div class="finding-evidence">${nl2br(f.evidence)}</div>
      <div class="finding-why">${escapeHtml(f.why)}</div>
      ${f.fix ? `<div class="finding-fix"><span class="fix-label">Fix</span> ${escapeHtml(f.fix)}</div>` : ''}
    `
    : '';

  return `
    <div class="finding-card status-${f.status}">
      <div class="finding-head">
        <span class="status-badge" style="border-color:${meta.colour};color:${meta.colour}">${meta.label}</span>
        <span class="finding-id">${escapeHtml(f.id)}</span>
        <span class="finding-title">${escapeHtml(f.title)}</span>
      </div>
      <div class="clause-row">${refs || '<span class="clause-tag muted">no clause mapping</span>'}</div>
      ${detail}
    </div>`;
}

function renderHtml(result) {
  const { target, findings, narrative } = result;
  const s = score(findings);
  const t = tally(findings);
  const generated = new Date().toISOString();

  const bad = findings.filter((f) => f.status === 'fail' || f.status === 'warn');
  const good = findings.filter((f) => f.status === 'pass');
  const rest = findings.filter((f) => f.status === 'info' || f.status === 'unknown');

  const scoreColour = s === null ? '#4a5a7a' : s >= 80 ? '#30d158' : s >= 50 ? '#ffd60a' : '#ff6b35';

  const narrativeHtml = narrative
    ? `<section class="narrative"><h2>Narrative</h2><div class="narrative-body">${nl2br(narrative)}</div></section>`
    : '';

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DPDP Web Check — ${escapeHtml(target)}</title>
<style>
  :root {
    --bg-deep: #070b12;
    --bg-card: #0d1520;
    --bg-panel: #111c2e;
    --border: #1e3a5f;
    --accent-blue: #0e6eff;
    --accent-cyan: #00d4ff;
    --critical: #ff2d55;
    --high: #ff6b35;
    --medium: #ffd60a;
    --low: #30d158;
    --text-primary: #e8edf5;
    --text-secondary: #8899bb;
    --text-muted: #4a5a7a;
    --mono: 'Consolas', 'SFMono-Regular', 'Menlo', monospace;
    --body: -apple-system, 'Segoe UI', Roboto, Arial, sans-serif;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    background: var(--bg-deep);
    color: var(--text-primary);
    font-family: var(--body);
    font-size: 16px;
    line-height: 1.6;
    padding: 32px 16px 64px;
  }
  .wrap { max-width: 860px; margin: 0 auto; }
  header {
    border-bottom: 1px solid var(--border);
    padding-bottom: 20px;
    margin-bottom: 24px;
  }
  h1 { font-size: 28px; font-weight: 700; word-break: break-word; }
  .timestamp { font-family: var(--mono); font-size: 13px; color: var(--text-muted); margin-top: 6px; }

  .summary-panel {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 20px 24px;
    margin-bottom: 28px;
    display: flex;
    flex-wrap: wrap;
    gap: 24px;
    align-items: center;
  }
  .score-ring {
    width: 92px; height: 92px; border-radius: 50%;
    border: 6px solid ${scoreColour};
    display: flex; align-items: center; justify-content: center;
    flex-direction: column;
    flex-shrink: 0;
  }
  .score-ring .num { font-size: 26px; font-weight: 700; font-family: var(--mono); color: ${scoreColour}; }
  .score-ring .denom { font-size: 12px; color: var(--text-muted); }
  .summary-text { flex: 1; min-width: 220px; }
  .summary-disclaimer { font-size: 14px; color: var(--text-muted); margin-top: 4px; }
  .tally-row { display: flex; gap: 14px; flex-wrap: wrap; margin-top: 10px; }
  .tally-chip {
    font-family: var(--mono); font-size: 14px;
    padding: 4px 10px; border-radius: 20px;
    background: var(--bg-panel); border: 1px solid var(--border);
  }
  .tally-chip.pass { color: var(--low); }
  .tally-chip.fail { color: var(--critical); }
  .tally-chip.warn { color: var(--medium); }
  .tally-chip.info { color: var(--accent-blue); }

  .narrative {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-left: 3px solid var(--accent-cyan);
    border-radius: 8px;
    padding: 18px 22px;
    margin-bottom: 28px;
  }
  .narrative h2 { font-size: 17px; margin-bottom: 10px; color: var(--accent-cyan); }
  .narrative-body { font-size: 15.5px; color: var(--text-secondary); }

  section.group { margin-bottom: 28px; }
  .group-title {
    font-family: var(--mono); font-size: 13px; letter-spacing: 1.5px;
    text-transform: uppercase; color: var(--text-muted);
    padding-bottom: 8px; margin-bottom: 12px;
    border-bottom: 1px solid var(--border);
  }

  .finding-card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 14px 18px;
    margin-bottom: 10px;
  }
  .finding-head { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
  .status-badge {
    font-family: var(--mono); font-size: 13px; font-weight: 700;
    letter-spacing: 1px; padding: 3px 10px; border-radius: 3px;
    border: 1px solid; flex-shrink: 0;
  }
  .finding-id { font-family: var(--mono); font-size: 13px; color: var(--text-muted); flex-shrink: 0; }
  .finding-title { font-weight: 600; font-size: 17px; }
  .clause-row { margin-top: 8px; display: flex; gap: 6px; flex-wrap: wrap; }
  .clause-tag {
    font-family: var(--mono); font-size: 13px; color: var(--accent-blue);
    background: rgba(14,110,255,0.08); padding: 3px 9px; border-radius: 3px;
    cursor: help;
  }
  .clause-tag.muted { color: var(--text-muted); background: transparent; }
  .finding-evidence {
    font-family: var(--mono); font-size: 14.5px; color: var(--text-secondary);
    background: #060d18; border-left: 2px solid var(--border);
    padding: 8px 12px; margin-top: 10px; border-radius: 4px;
    overflow-wrap: break-word;
  }
  .finding-why { font-size: 15.5px; color: var(--text-secondary); margin-top: 10px; line-height: 1.7; }
  .finding-fix {
    font-size: 15px; color: var(--low); margin-top: 8px;
    background: rgba(48,209,88,0.06); border: 1px solid rgba(48,209,88,0.2);
    padding: 8px 12px; border-radius: 5px;
  }
  .fix-label { font-family: var(--mono); font-weight: 700; margin-right: 6px; }

  .limits-section {
    margin-top: 36px; padding-top: 20px; border-top: 1px solid var(--border);
  }
  .limits-section h2 { font-size: 16px; color: var(--text-muted); margin-bottom: 10px; }
  .limits-section ul { list-style: none; }
  .limits-section li {
    font-size: 15px; color: var(--text-muted); padding: 4px 0 4px 16px;
    position: relative;
  }
  .limits-section li::before { content: '—'; position: absolute; left: 0; }
  .enforcement-note, .final-disclaimer {
    font-size: 14px; color: var(--text-muted); margin-top: 14px; line-height: 1.7;
  }

  .brand-header {
    display: flex; align-items: center; gap: 14px;
    margin-bottom: 18px;
  }
  .brand-logo { width: 44px; height: 44px; border-radius: 10px; flex-shrink: 0; }
  .brand-name { font-family: var(--body); font-size: 17px; font-weight: 700; color: var(--text-primary); }
  .brand-tagline { font-family: var(--mono); font-size: 12px; color: var(--text-muted); letter-spacing: 1px; margin-top: 1px; }

  .cta-panel {
    margin-top: 44px;
    background: linear-gradient(135deg, #caa04a, #e8c777);
    border-radius: 10px;
    padding: 22px 26px;
    display: flex; align-items: center; justify-content: space-between;
    gap: 20px; flex-wrap: wrap;
  }
  .cta-text h3 { color: #241a05; font-size: 19px; margin-bottom: 4px; }
  .cta-text p { color: #4a3a10; font-size: 15px; max-width: 480px; line-height: 1.6; }
  .cta-link {
    display: inline-block; margin-top: 10px;
    font-family: var(--mono); font-size: 14px; font-weight: 700;
    color: #241a05; text-decoration: none;
    border-bottom: 1px solid #241a05;
  }

  footer {
    margin-top: 32px; padding-top: 16px; border-top: 1px solid var(--border);
    display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;
  }
  footer .foot-left { font-family: var(--mono); font-size: 13px; color: var(--text-muted); }
  footer .foot-right { font-family: var(--mono); font-size: 13px; }
  footer .foot-right a { color: var(--accent-cyan); text-decoration: none; }

  @media print {
    body { background: #fff; color: #000; padding: 0; }
    .wrap { max-width: 100%; }
    .cta-panel { display: none; }
  }
</style>
</head>
<body>
<div class="wrap">

  <header>
    <div class="brand-header">
      ${LOGO_BASE64 ? `<img class="brand-logo" src="data:image/png;base64,${LOGO_BASE64}" alt="Protevix Infosec">` : ''}
      <div>
        <div class="brand-name">Protevix Infosec</div>
        <div class="brand-tagline">DPDP WEB CHECK</div>
      </div>
    </div>
    <h1>${escapeHtml(target)}</h1>
    <div class="timestamp">${escapeHtml(generated)}</div>
  </header>

  <div class="summary-panel">
    <div class="score-ring">
      <div class="num">${s === null ? '—' : s}</div>
      <div class="denom">/ 100</div>
    </div>
    <div class="summary-text">
      <div class="tally-row">
        <span class="tally-chip pass">${t.pass} pass</span>
        <span class="tally-chip fail">${t.fail} fail</span>
        <span class="tally-chip warn">${t.warn} warn</span>
        <span class="tally-chip info">${t.info} info</span>
      </div>
      <div class="summary-disclaimer">Observable safeguards score. This is not a compliance score — see limits at the end of this report.</div>
    </div>
  </div>

  ${narrativeHtml}

  ${bad.length ? `<section class="group"><div class="group-title">Needs attention</div>${bad.map((f) => findingCard(f, true)).join('')}</section>` : ''}
  ${good.length ? `<section class="group"><div class="group-title">Observed as expected</div>${good.map((f) => findingCard(f, false)).join('')}</section>` : ''}
  ${rest.length ? `<section class="group"><div class="group-title">Context</div>${rest.map((f) => findingCard(f, true)).join('')}</section>` : ''}

  <div class="cta-panel">
    <div class="cta-text">
      <h3>This check is passive. KScan goes further.</h3>
      <p>Real vulnerability scanning across your entire web application — a 7-phase black box pentest, OWASP Top 10 and CVE matching, AI-narrated findings. Paste your URL, no signup needed to start.</p>
      <a class="cta-link" href="https://kscan.protevixinfosec.com">Run your free scan at kscan.protevixinfosec.com &rarr;</a>
    </div>
  </div>

  <div class="limits-section">
    <h2>What this check cannot see</h2>
    <ul>${LIMITS.map((l) => `<li>${escapeHtml(l)}</li>`).join('')}</ul>
    <div class="enforcement-note">${escapeHtml(ENFORCEMENT_NOTE)}</div>
    <div class="final-disclaimer">This tool performs passive observation of publicly served responses. It is an engineering aid, not legal advice, not a compliance certification, and not a penetration test. Have the wording of any notice reviewed by a qualified advisor.</div>
  </div>

  <footer>
    <div class="foot-left">dpdp-web-check &middot; Protevix Infosec &middot; Apache-2.0</div>
    <div class="foot-right"><a href="mailto:connect@protevixinfosec.com">connect@protevixinfosec.com</a></div>
  </footer>

</div>
</body>
</html>
`;
}

module.exports = { renderHtml };
