'use strict';

/**
 * Cookie checks.
 *
 * DPDP relevance: a session cookie is the access-control token for everything
 * a Data Principal can see about themselves. Rule 6(1)(b) requires appropriate
 * measures to control access to computer resources. A session cookie without
 * HttpOnly is readable by any injected script; without Secure it can be
 * transmitted in cleartext; without SameSite it is replayed cross-site. Each
 * of those is an access-control failure with a direct route to unauthorised
 * disclosure of personal data.
 */

const SESSION_HINTS =
  /sess|sid|auth|token|login|jwt|csrf|remember|user|account|_id$/i;

function parseCookie(raw) {
  const parts = String(raw).split(';').map((p) => p.trim());
  const [pair] = parts;
  const eq = pair.indexOf('=');
  const name = eq === -1 ? pair : pair.slice(0, eq);
  const attrs = new Set(parts.slice(1).map((p) => p.split('=')[0].toLowerCase()));
  const sameSiteRaw = parts
    .slice(1)
    .find((p) => /^samesite=/i.test(p));
  return {
    raw,
    name,
    secure: attrs.has('secure'),
    httpOnly: attrs.has('httponly'),
    sameSite: sameSiteRaw ? sameSiteRaw.split('=')[1] : null,
    sessionLike: SESSION_HINTS.test(name),
    prefixed: /^__(Host|Secure)-/.test(name),
  };
}

function run(ctx) {
  const findings = [];
  const { response } = ctx;
  if (!response.ok) return findings;

  const cookies = (response.setCookie || []).map(parseCookie);

  if (cookies.length === 0) {
    findings.push({
      id: 'DPDP-A00',
      title: 'Cookies observed on first response',
      severity: 'info',
      status: 'info',
      clauses: ['R6(b)'],
      evidence: 'No Set-Cookie headers on the landing response.',
      why: 'Nothing to assess here. Authenticated areas may still set cookies; re-run against a post-login URL if you have one.',
      fix: null,
    });
    return findings;
  }

  const insecure = cookies.filter((c) => !c.secure);
  const noHttpOnly = cookies.filter((c) => c.sessionLike && !c.httpOnly);
  const noSameSite = cookies.filter((c) => !c.sameSite);

  findings.push({
    id: 'DPDP-A01',
    title: 'All cookies carry the Secure attribute',
    severity: 'high',
    status: insecure.length ? 'fail' : 'pass',
    clauses: ['R6(a)', 'R6(b)'],
    evidence: insecure.length
      ? `Missing Secure on: ${insecure.map((c) => c.name).join(', ')}`
      : `${cookies.length} cookie(s) set, all Secure.`,
    why: insecure.length
      ? 'A cookie without Secure is attached to plain HTTP requests. Any downgrade, any stray http:// link, and the token travels in cleartext where it can be captured and replayed to read that account holder\'s personal data.'
      : 'Cookies are restricted to encrypted transport.',
    fix: insecure.length ? 'Add the Secure attribute to every cookie the application sets.' : null,
  });

  findings.push({
    id: 'DPDP-A02',
    title: 'Session-like cookies carry HttpOnly',
    severity: 'high',
    status: noHttpOnly.length ? 'fail' : 'pass',
    clauses: ['R6(b)'],
    evidence: noHttpOnly.length
      ? `Session-like cookie(s) readable by JavaScript: ${noHttpOnly.map((c) => c.name).join(', ')}`
      : 'No session-like cookie is exposed to JavaScript.',
    why: noHttpOnly.length
      ? 'These cookies are readable through document.cookie. Combined with any script injection, or a compromised third-party tag, the session token is exfiltrated and the attacker reads the account as the Data Principal.'
      : 'Session tokens are not reachable from page script.',
    fix: noHttpOnly.length
      ? 'Set HttpOnly on every cookie that is not deliberately read by front-end code.'
      : null,
  });

  findings.push({
    id: 'DPDP-A03',
    title: 'Cookies declare a SameSite policy',
    severity: 'medium',
    status: noSameSite.length ? 'fail' : 'pass',
    clauses: ['R6(b)'],
    evidence: noSameSite.length
      ? `No SameSite on: ${noSameSite.map((c) => c.name).join(', ')}`
      : cookies.map((c) => `${c.name}=SameSite:${c.sameSite}`).join(', '),
    why: noSameSite.length
      ? 'Without an explicit SameSite value, browser defaults vary and cross-site requests may carry the cookie. That is the precondition for cross-site request forgery, where a Data Principal is made to change or delete their own record without knowing.'
      : 'Cross-site cookie transmission is explicitly controlled.',
    fix: noSameSite.length
      ? 'Set SameSite=Lax for session cookies, or Strict where no cross-site entry flow is required.'
      : null,
  });

  return findings;
}

module.exports = { run };
