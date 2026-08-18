'use strict';

// Weighting: what an outside observer can see, weighted by how directly the
// gap leads to disclosure of personal data. Deliberately NOT called a
// compliance score.
const SEVERITY_WEIGHT = { high: 5, medium: 3, low: 1, info: 0 };

function score(findings) {
  let earned = 0;
  let possible = 0;
  for (const f of findings) {
    const w = SEVERITY_WEIGHT[f.severity] || 0;
    if (w === 0 || f.status === 'unknown' || f.status === 'info') continue;
    possible += w;
    if (f.status === 'pass') earned += w;
    else if (f.status === 'warn') earned += w * 0.5;
  }
  if (possible === 0) return null;
  return Math.round((earned / possible) * 100);
}

function tally(findings) {
  const t = { pass: 0, fail: 0, warn: 0, info: 0, unknown: 0 };
  findings.forEach((f) => {
    t[f.status] = (t[f.status] || 0) + 1;
  });
  return t;
}

module.exports = { score, tally, SEVERITY_WEIGHT };
