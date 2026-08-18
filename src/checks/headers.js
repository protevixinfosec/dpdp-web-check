'use strict';

/**
 * Response-header checks.
 *
 * DPDP relevance: these headers are the browser-side half of Rule 6(1)(b)
 * access control. A missing CSP or Referrer-Policy is not an abstract "best
 * practice" gap. It is a live route by which personal data already rendered
 * in an authenticated session leaves the Data Fiduciary's control and reaches
 * a third party, which is exactly the outcome Section 8(5) is written to
 * prevent.
 */

function run(ctx) {
  const findings = [];
  const { response } = ctx;
  if (!response.ok) return findings;
  const h = response.headers;

  // --- Content-Security-Policy ---------------------------------------------
  const csp = h['content-security-policy'] || null;
  const cspReportOnly = h['content-security-policy-report-only'] || null;
  const cspWeak =
    csp && /unsafe-inline|unsafe-eval|(^|\s)default-src\s+\*/i.test(csp);

  findings.push({
    id: 'DPDP-C01',
    title: 'Content-Security-Policy restricts script sources',
    severity: 'high',
    status: csp ? (cspWeak ? 'warn' : 'pass') : 'fail',
    clauses: ['R6(b)'],
    evidence: csp
      ? `Content-Security-Policy: ${truncate(csp, 240)}`
      : cspReportOnly
        ? `Only report-only policy present: ${truncate(cspReportOnly, 200)}`
        : 'No Content-Security-Policy header present.',
    why: csp
      ? cspWeak
        ? "The policy permits unsafe-inline, unsafe-eval, or a wildcard default source. An injected script still executes, so the policy does not meaningfully contain a cross-site scripting payload."
        : 'Script execution is restricted to declared origins, which limits the blast radius of an injection.'
      : 'With no policy, any successful script injection runs with full page privilege. It can read the DOM of an authenticated session, exfiltrate personal data to an attacker-controlled host, and do so without touching your servers or appearing in your logs.',
    fix: csp && !cspWeak
      ? null
      : "Start with Content-Security-Policy-Report-Only, collect violations, then enforce script-src 'self' with per-request nonces. Remove unsafe-inline before enforcing.",
  });

  // --- Framing protection ---------------------------------------------------
  const xfo = h['x-frame-options'] || null;
  const frameAncestors = csp && /frame-ancestors/i.test(csp);

  findings.push({
    id: 'DPDP-C02',
    title: 'Framing is restricted (clickjacking protection)',
    severity: 'medium',
    status: xfo || frameAncestors ? 'pass' : 'fail',
    clauses: ['R6(b)'],
    evidence: xfo
      ? `X-Frame-Options: ${xfo}`
      : frameAncestors
        ? 'CSP frame-ancestors directive present.'
        : 'Neither X-Frame-Options nor CSP frame-ancestors is set.',
    why:
      xfo || frameAncestors
        ? 'The page cannot be embedded by an unrelated origin.'
        : 'The page can be invisibly framed by an attacker site. A Data Principal can be tricked into approving an action, changing a setting, or consenting to processing they never saw.',
    fix:
      xfo || frameAncestors
        ? null
        : "Add Content-Security-Policy: frame-ancestors 'self' and, for older clients, X-Frame-Options: SAMEORIGIN.",
  });

  // --- MIME sniffing --------------------------------------------------------
  const nosniff = (h['x-content-type-options'] || '').toLowerCase() === 'nosniff';
  findings.push({
    id: 'DPDP-C03',
    title: 'MIME sniffing is disabled',
    severity: 'low',
    status: nosniff ? 'pass' : 'fail',
    clauses: ['R6(b)'],
    evidence: nosniff
      ? 'X-Content-Type-Options: nosniff'
      : 'No X-Content-Type-Options header.',
    why: nosniff
      ? 'Browsers honour the declared content type.'
      : 'A browser may reinterpret an uploaded file as executable script. On any site that accepts Data Principal uploads, this converts a file upload into script execution.',
    fix: nosniff ? null : 'Send X-Content-Type-Options: nosniff on every response.',
  });

  // --- Referrer-Policy ------------------------------------------------------
  const referrer = (h['referrer-policy'] || '').toLowerCase();
  const referrerSafe =
    referrer &&
    /no-referrer|same-origin|strict-origin/.test(referrer) &&
    !/unsafe-url/.test(referrer);

  findings.push({
    id: 'DPDP-C04',
    title: 'Referrer-Policy prevents URL leakage to third parties',
    severity: 'medium',
    status: referrer ? (referrerSafe ? 'pass' : 'fail') : 'fail',
    clauses: ['R6(b)', 'R15'],
    evidence: referrer
      ? `Referrer-Policy: ${referrer}`
      : 'No Referrer-Policy header present.',
    why: referrerSafe
      ? 'Outbound requests do not carry the full URL of the originating page.'
      : 'Without a restrictive policy the full URL of the current page, including any identifier, token, email address or order reference in the path or query string, is sent to every third-party host the page loads from. This is a routine and entirely silent disclosure of personal data to processors you may not have named in your notice, frequently outside India.',
    fix: referrerSafe
      ? null
      : 'Send Referrer-Policy: strict-origin-when-cross-origin as a baseline, or no-referrer on pages that carry identifiers in the URL.',
  });

  // --- Permissions-Policy ---------------------------------------------------
  const permissions = h['permissions-policy'] || h['feature-policy'] || null;
  findings.push({
    id: 'DPDP-C05',
    title: 'Permissions-Policy restricts sensitive browser APIs',
    severity: 'low',
    status: permissions ? 'pass' : 'warn',
    clauses: ['R6(b)'],
    evidence: permissions
      ? `Permissions-Policy: ${truncate(permissions, 200)}`
      : 'No Permissions-Policy header present.',
    why: permissions
      ? 'Access to camera, microphone, geolocation and similar APIs is explicitly scoped.'
      : 'Every embedded frame and script inherits permission to request geolocation, camera and microphone. Location and biometric-adjacent input are personal data; permitting them by default widens what a compromised third-party script can collect.',
    fix: permissions
      ? null
      : 'Send Permissions-Policy: geolocation=(), camera=(), microphone=() and enable only what the product genuinely uses.',
  });

  // --- Stack disclosure -----------------------------------------------------
  const disclosures = [];
  ['server', 'x-powered-by', 'x-aspnet-version', 'x-generator'].forEach((key) => {
    if (h[key] && /[0-9]/.test(h[key])) disclosures.push(`${key}: ${h[key]}`);
  });

  findings.push({
    id: 'DPDP-D01',
    title: 'Response headers do not disclose exact software versions',
    severity: 'low',
    status: disclosures.length ? 'fail' : 'pass',
    clauses: ['R6(b)'],
    evidence: disclosures.length
      ? disclosures.join(' | ')
      : 'No versioned server or framework headers observed.',
    why: disclosures.length
      ? 'Exact version strings let an attacker map the host straight to published CVEs for that build, skipping reconnaissance entirely. This is not a breach by itself, but it materially shortens the path to one.'
      : 'No version fingerprint is being advertised.',
    fix: disclosures.length
      ? 'Suppress the version token at the proxy. In Nginx set server_tokens off; in Express call app.disable("x-powered-by").'
      : null,
  });

  return findings;
}

function truncate(value, max) {
  const s = String(value);
  return s.length > max ? `${s.slice(0, max)}...` : s;
}

module.exports = { run };
