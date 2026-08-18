'use strict';

const transport = require('./transport');
const headers = require('./headers');
const cookies = require('./cookies');
const privacy = require('./privacy');
const thirdparty = require('./thirdparty');
const incident = require('./incident');

const MODULES = [
  { name: 'transport', run: transport.run, async: true },
  { name: 'headers', run: headers.run, async: false },
  { name: 'cookies', run: cookies.run, async: false },
  { name: 'privacy', run: privacy.run, async: true },
  { name: 'third-party', run: thirdparty.run, async: false },
  { name: 'incident', run: incident.run, async: true },
];

/**
 * Run every check module against a prepared context.
 * A module that throws is reported as an error finding rather than
 * aborting the whole run.
 */
async function runAll(ctx, onProgress) {
  const findings = [];

  for (const mod of MODULES) {
    if (onProgress) onProgress(mod.name);
    try {
      const result = await mod.run(ctx);
      findings.push(...result);
    } catch (err) {
      findings.push({
        id: `ERR-${mod.name.toUpperCase()}`,
        title: `Check module "${mod.name}" failed`,
        severity: 'info',
        status: 'unknown',
        clauses: [],
        evidence: err && err.message ? err.message : String(err),
        why: 'This module did not complete, so its checks are absent from the result.',
        fix: 'Re-run with --verbose and open an issue if it persists.',
      });
    }
  }

  return findings;
}

module.exports = { runAll, MODULES };
