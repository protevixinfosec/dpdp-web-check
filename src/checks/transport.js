'use strict';

/**
 * Transport-layer checks.
 *
 * DPDP relevance: Rule 6(1)(a) requires personal data to be secured through
 * encryption. Personal data submitted by a Data Principal over a login form,
 * a contact form or a checkout is "in transit" personal data. If that channel
 * is unencrypted, downgradeable, or protected by an expired certificate, the
 * encryption obligation is not being met on the one surface an outsider can
 * actually observe.
 */

const { requestOnce } = require('../http');

function daysUntil(dateString) {
  const then = Date.parse(dateString);
  if (Number.isNaN(then)) return null;
  return Math.floor((then - Date.now()) / 86_400_000);
}

async function run(ctx) {
  const findings = [];
  const { url, response } = ctx;

  // --- 1. Is HTTPS actually serving? ---------------------------------------
  if (!response.ok) {
    findings.push({
      id: 'DPDP-T01',
      title: 'HTTPS endpoint reachable',
      severity: 'high',
      status: 'unknown',
      clauses: ['R6(a)'],
      evidence: `Request to ${url.origin} failed: ${response.error}`,
      why: 'The tool could not establish an HTTPS session, so no transport observation is possible.',
      fix: 'Confirm the host resolves, is publicly reachable, and terminates TLS on port 443.',
    });
    return findings;
  }

  findings.push({
    id: 'DPDP-T01',
    title: 'HTTPS endpoint reachable',
    severity: 'high',
    status: 'pass',
    clauses: ['R6(a)'],
    evidence: `HTTP ${response.status} from ${response.finalUrl}`,
    why: 'An encrypted channel is available for personal data submitted through this site.',
    fix: null,
  });

  // --- 2. Does plain HTTP redirect to HTTPS? -------------------------------
  const plain = await requestOnce(`http://${url.hostname}${url.pathname}`, {
    timeout: 10000,
  });

  if (!plain.ok) {
    findings.push({
      id: 'DPDP-T02',
      title: 'Plain HTTP is refused or redirected',
      severity: 'medium',
      status: 'pass',
      clauses: ['R6(a)'],
      evidence: `Port 80 request did not complete (${plain.error}). No cleartext listener observed.`,
      why: 'No cleartext channel is offered, so a Data Principal cannot be silently downgraded.',
      fix: null,
    });
  } else {
    const loc = plain.headers.location || '';
    const redirectsToHttps =
      plain.status >= 300 && plain.status < 400 && /^https:/i.test(loc);

    findings.push({
      id: 'DPDP-T02',
      title: 'Plain HTTP is refused or redirected',
      severity: 'high',
      status: redirectsToHttps ? 'pass' : 'fail',
      clauses: ['R6(a)'],
      evidence: redirectsToHttps
        ? `HTTP ${plain.status} to ${loc}`
        : `Port 80 answered HTTP ${plain.status} without an https redirect (Location: ${loc || 'none'})`,
      why: redirectsToHttps
        ? 'Cleartext requests are upgraded before any personal data can be submitted.'
        : 'The site answers over cleartext HTTP. Anything a Data Principal types on that version of the page, including credentials and contact details, travels unencrypted and is readable on any intermediate network.',
      fix: redirectsToHttps
        ? null
        : 'Return a 301 to the https equivalent for every path on port 80, and serve no content over cleartext.',
    });
  }

  // --- 3. Negotiated TLS version -------------------------------------------
  const tls = response.tls || {};
  const proto = tls.protocol || null;
  const weakProto = proto && /TLSv1(\.0|\.1)?$/i.test(proto);

  findings.push({
    id: 'DPDP-T03',
    title: 'TLS protocol version is current',
    severity: 'high',
    status: proto ? (weakProto ? 'fail' : 'pass') : 'unknown',
    clauses: ['R6(a)'],
    evidence: proto
      ? `Negotiated ${proto}${tls.cipher ? ` with ${tls.cipher}` : ''}`
      : 'TLS handshake details were not captured.',
    why: weakProto
      ? 'TLS 1.0 and 1.1 are deprecated and have practical downgrade and padding-oracle weaknesses. Personal data in transit is not adequately encrypted.'
      : 'The negotiated protocol is a currently supported version.',
    fix: weakProto
      ? 'Disable TLS 1.0 and 1.1 at the terminating proxy. Serve TLS 1.2 as the floor and prefer TLS 1.3.'
      : null,
  });

  // --- 4. Certificate validity ---------------------------------------------
  const remaining = tls.validTo ? daysUntil(tls.validTo) : null;
  let certStatus = 'unknown';
  let certWhy = 'Certificate details were not captured.';

  if (tls.authorized === false) {
    certStatus = 'fail';
    certWhy = `The certificate did not validate against the public trust store (${tls.authorizationError}). Browsers will interrupt the Data Principal with a warning, and the encryption cannot be attributed to the operator.`;
  } else if (remaining !== null && remaining < 0) {
    certStatus = 'fail';
    certWhy = 'The certificate has expired. The encrypted channel is untrusted.';
  } else if (remaining !== null && remaining < 21) {
    certStatus = 'warn';
    certWhy = `The certificate expires in ${remaining} days. Renewal automation should be verified before it lapses.`;
  } else if (remaining !== null) {
    certStatus = 'pass';
    certWhy = `The certificate is valid and expires in ${remaining} days.`;
  }

  findings.push({
    id: 'DPDP-T04',
    title: 'TLS certificate is valid and not near expiry',
    severity: 'high',
    status: certStatus,
    clauses: ['R6(a)', 'R6(d)'],
    evidence: tls.validTo
      ? `Issuer ${tls.issuer && tls.issuer.O ? tls.issuer.O : 'unknown'}, valid to ${tls.validTo}, chain authorised: ${tls.authorized}`
      : 'No certificate captured.',
    why: certWhy,
    fix:
      certStatus === 'fail' || certStatus === 'warn'
        ? 'Fix or automate certificate renewal, and add an expiry alert at 30 days.'
        : null,
  });

  // --- 5. HSTS --------------------------------------------------------------
  const hsts = response.headers['strict-transport-security'] || null;
  const maxAgeMatch = hsts ? /max-age=(\d+)/i.exec(hsts) : null;
  const maxAge = maxAgeMatch ? parseInt(maxAgeMatch[1], 10) : 0;
  const hstsOk = Boolean(hsts) && maxAge >= 31_536_000;

  findings.push({
    id: 'DPDP-T05',
    title: 'HSTS is set with a durable max-age',
    severity: 'medium',
    status: hsts ? (hstsOk ? 'pass' : 'warn') : 'fail',
    clauses: ['R6(a)'],
    evidence: hsts
      ? `Strict-Transport-Security: ${hsts}`
      : 'No Strict-Transport-Security header present.',
    why: hstsOk
      ? 'Browsers will refuse a cleartext connection to this host for at least a year.'
      : 'Without a durable HSTS policy, the first request of every session can be intercepted and downgraded before the redirect happens. Personal data typed into that first page is exposed.',
    fix: hstsOk
      ? null
      : 'Send Strict-Transport-Security: max-age=31536000; includeSubDomains. Add preload only once you are certain every subdomain serves HTTPS.',
  });

  return findings;
}

module.exports = { run };
