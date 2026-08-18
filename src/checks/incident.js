'use strict';

/**
 * Breach-readiness signals.
 *
 * DPDP relevance: Section 8(6) read with Rule 7 puts a hard clock on you.
 * Affected Data Principals must be intimated without delay, and the Data
 * Protection Board must receive an initial intimation without delay followed
 * by a detailed report within 72 hours of you becoming aware.
 *
 * "Becoming aware" is the load-bearing phrase. If a researcher finds a leak on
 * your site and has no way to tell you, your 72-hour clock does not start when
 * they find it. It starts when a journalist calls. A published disclosure
 * channel is the cheapest thing you can build that shortens time-to-awareness,
 * and it is the only part of Rule 7 readiness that is externally observable.
 */

const { request } = require('../http');

async function run(ctx) {
  const findings = [];
  const { url } = ctx;

  const paths = ['/.well-known/security.txt', '/security.txt'];
  let found = null;

  for (const p of paths) {
    const res = await request(`${url.origin}${p}`, { maxRedirects: 2, timeout: 8000 });
    if (
      res.ok &&
      res.status === 200 &&
      /contact\s*:/i.test(res.body || '')
    ) {
      found = { path: p, body: res.body };
      break;
    }
  }

  if (!found) {
    findings.push({
      id: 'DPDP-I01',
      title: 'A security disclosure channel is published (security.txt)',
      severity: 'medium',
      status: 'fail',
      clauses: ['S8(6)', 'R7'],
      evidence: `No parsable security.txt at ${paths.join(' or ')}.`,
      why: 'There is no published route for a researcher or customer to report a leak. Under Rule 7 your notification clock starts when you become aware. With no inbound channel, awareness arrives late and by the worst possible route, and the delay itself becomes the reportable failure.',
      fix: 'Publish /.well-known/security.txt with Contact, Expires and Preferred-Languages fields, pointing at a mailbox that is monitored daily. RFC 9116 defines the format.',
    });
    return findings;
  }

  const hasExpires = /^expires\s*:/im.test(found.body);
  const expiresMatch = /^expires\s*:\s*(.+)$/im.exec(found.body);
  const expired =
    expiresMatch && Date.parse(expiresMatch[1].trim()) < Date.now();

  findings.push({
    id: 'DPDP-I01',
    title: 'A security disclosure channel is published (security.txt)',
    severity: 'medium',
    status: expired ? 'warn' : 'pass',
    clauses: ['S8(6)', 'R7'],
    evidence: `Found at ${found.path}${expiresMatch ? `, Expires: ${expiresMatch[1].trim()}` : ', no Expires field'}`,
    why: expired
      ? 'The file exists but its Expires date has passed. Reporters are advised by RFC 9116 to treat an expired file as unmaintained, which defeats the purpose.'
      : 'A public reporting route exists, which shortens time-to-awareness and therefore time-to-notification under Rule 7.',
    fix: expired || !hasExpires
      ? 'Refresh the Expires field and set a calendar reminder to renew it annually.'
      : null,
  });

  return findings;
}

module.exports = { run };
