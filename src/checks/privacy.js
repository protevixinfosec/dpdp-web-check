'use strict';

/**
 * Notice, consent, grievance and rights checks.
 *
 * This is the part of the tool that does not exist anywhere else. Generic
 * header scanners will tell you about CSP. None of them will tell you that
 * Section 13 of the DPDP Act requires a readily available grievance redressal
 * mechanism, or that Rule 3 requires the notice to be independent, itemised
 * and in plain language, or that Rule 14 requires you to publish the means by
 * which a Data Principal exercises their rights.
 *
 * Everything here is a discoverability signal derived from public markup.
 * It cannot judge whether the text of a policy is legally adequate. It can
 * tell you, with certainty, when the required artefact is not findable at all,
 * which is the failure mode that actually shows up in Indian SMB estates.
 */

const { request } = require('../http');

const POLICY_PATHS = [
  '/privacy',
  '/privacy-policy',
  '/privacypolicy',
  '/legal/privacy',
  '/policies/privacy',
  '/privacy-notice',
  '/data-protection',
];

const GRIEVANCE_PATTERNS = [
  /grievance\s*officer/i,
  /grievance\s*redressal/i,
  /data\s*protection\s*officer/i,
  /\bDPO\b/,
  /nodal\s*officer/i,
];

const RIGHTS_PATTERNS = [
  /data\s*principal/i,
  /right\s*to\s*(erasure|correction|access)/i,
  /withdraw\s*(your\s*)?consent/i,
  /request\s*(the\s*)?(deletion|erasure)/i,
];

const DPDP_PATTERNS = [
  /digital\s*personal\s*data\s*protection/i,
  /DPDP\s*(Act|Rules)?/,
  /Data\s*Protection\s*Board\s*of\s*India/i,
];

const CONSENT_PATTERNS = [
  /cookieconsent/i,
  /cookiebot/i,
  /onetrust/i,
  /cookieyes/i,
  /osano/i,
  /termly/i,
  /klaro/i,
  /consent[-_]?manager/i,
  /gdpr[-_]?cookie/i,
  /id=["']?cookie[-_]?(banner|notice|consent)/i,
  /class=["'][^"']*cookie[-_]?(banner|notice|consent)/i,
];

function anyMatch(patterns, text) {
  return patterns.some((p) => p.test(text));
}

function stripTags(html) {
  return String(html)
    .replace(/<script[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/\s+/g, ' ');
}

/**
 * Find a privacy policy: first from links on the landing page, then by
 * probing a short list of conventional paths.
 */
async function locatePolicy(ctx) {
  const { response, url } = ctx;
  const body = response.body || '';

  const linkRe = /<a\b[^>]*href=["']([^"']+)["'][^>]*>([\s\S]{0,120}?)<\/a>/gi;
  let match;
  while ((match = linkRe.exec(body)) !== null) {
    const href = match[1];
    const label = stripTags(match[2]);
    if (/privacy|data\s*protection|gdpr|dpdp/i.test(`${href} ${label}`)) {
      try {
        return { url: new URL(href, response.finalUrl).toString(), via: 'link on landing page' };
      } catch (_e) {
        /* ignore malformed href */
      }
    }
  }

  for (const path of POLICY_PATHS) {
    const candidate = `${url.origin}${path}`;
    const res = await request(candidate, { maxRedirects: 3, timeout: 10000 });
    if (res.ok && res.status === 200 && (res.body || '').length > 500) {
      return { url: res.finalUrl, via: 'conventional path probe', body: res.body };
    }
  }

  return null;
}

async function run(ctx) {
  const findings = [];
  const { response } = ctx;
  if (!response.ok) return findings;

  const landingText = stripTags(response.body || '');
  const located = await locatePolicy(ctx);

  // --- Rule 3: is a notice discoverable at all? ----------------------------
  findings.push({
    id: 'DPDP-N01',
    title: 'A privacy notice is discoverable from the public site',
    severity: 'high',
    status: located ? 'pass' : 'fail',
    clauses: ['R3'],
    evidence: located
      ? `Found at ${located.url} (${located.via})`
      : `No privacy notice found via landing-page links or the ${POLICY_PATHS.length} conventional paths probed.`,
    why: located
      ? 'A notice exists and is reachable without authentication.'
      : 'Rule 3 requires the notice to be presented to the Data Principal independently and in clear, plain language. If it cannot be found from the public site at all, no valid consent has been obtained for any processing that depends on it.',
    fix: located
      ? null
      : 'Publish a DPDP notice at a stable path, link it from the global footer, and surface it at the point of collection rather than only in the footer.',
  });

  let policyText = '';
  if (located) {
    if (located.body) {
      policyText = stripTags(located.body);
    } else {
      const res = await request(located.url, { maxRedirects: 3, timeout: 12000 });
      policyText = res.ok ? stripTags(res.body || '') : '';
    }
  }

  const corpus = `${landingText} ${policyText}`;

  // --- Section 13: grievance redressal -------------------------------------
  const hasGrievance = anyMatch(GRIEVANCE_PATTERNS, corpus);
  findings.push({
    id: 'DPDP-N02',
    title: 'A Grievance Officer or DPO contact is published',
    severity: 'high',
    status: hasGrievance ? 'pass' : 'fail',
    clauses: ['S13', 'R14'],
    evidence: hasGrievance
      ? 'Grievance Officer, Nodal Officer or DPO language found in the public notice.'
      : 'No Grievance Officer, Nodal Officer or DPO reference found on the landing page or privacy notice.',
    why: hasGrievance
      ? 'A named channel for grievance redressal is publicly visible.'
      : 'Section 13 gives every Data Principal the right to readily available means of grievance redressal, and Rule 14 requires the Data Fiduciary to publish how a rights request is made. A contact form with no named officer does not satisfy this. It is also the single most common omission on Indian SMB sites and the cheapest one to fix.',
    fix: hasGrievance
      ? null
      : 'Publish the name, designation and a monitored email address of the Grievance Officer in the privacy notice and in the site footer. Route it to a mailbox with a defined response SLA.',
  });

  // --- Rule 14: rights language --------------------------------------------
  const hasRights = anyMatch(RIGHTS_PATTERNS, corpus);
  findings.push({
    id: 'DPDP-N03',
    title: 'Data Principal rights and the means to exercise them are described',
    severity: 'medium',
    status: hasRights ? 'pass' : 'fail',
    clauses: ['R14', 'R8'],
    evidence: hasRights
      ? 'Rights language (access, correction, erasure or consent withdrawal) found.'
      : 'No description of access, correction, erasure or consent-withdrawal rights found.',
    why: hasRights
      ? 'The notice describes at least some of the rights and how to act on them.'
      : 'Rule 14 requires publication of the means by which a request is made and the particulars needed to identify the requester. Without it, a Data Principal has no route to correction or erasure, and you have no defensible record of having offered one.',
    fix: hasRights
      ? null
      : 'Add a rights section naming access, correction, completion, updating, erasure, grievance and nomination, with the exact submission channel and the identifiers you require.',
  });

  // --- DPDP-specific language (not GDPR copy-paste) ------------------------
  const mentionsDpdp = anyMatch(DPDP_PATTERNS, corpus);
  const mentionsGdprOnly =
    /GDPR|General Data Protection Regulation/i.test(corpus) && !mentionsDpdp;

  findings.push({
    id: 'DPDP-N04',
    title: 'Notice references the Indian DPDP framework, not only foreign law',
    severity: 'medium',
    status: mentionsDpdp ? 'pass' : mentionsGdprOnly ? 'fail' : 'warn',
    clauses: ['R3'],
    evidence: mentionsDpdp
      ? 'DPDP Act / DPDP Rules / Data Protection Board of India referenced.'
      : mentionsGdprOnly
        ? 'The notice references GDPR but makes no reference to the DPDP Act or Rules.'
        : 'No recognisable data protection framework referenced in the notice.',
    why: mentionsDpdp
      ? 'The notice is written against the applicable Indian framework.'
      : 'A GDPR-derived template does not map cleanly onto DPDP. The terminology differs (Data Principal, Data Fiduciary, Consent Manager), the lawful bases differ, and Rule 3 has itemisation requirements GDPR does not. Reusing a European template is the most common shortcut and it leaves specific, checkable gaps.',
    fix: mentionsDpdp
      ? null
      : 'Rewrite the notice against the DPDP Act 2023 and DPDP Rules 2025 using Indian terminology, and itemise the personal data collected against each purpose as Rule 3 requires.',
  });

  // --- Rule 3 / consent mechanism ------------------------------------------
  const rawBody = response.body || '';
  const hasConsentUi = anyMatch(CONSENT_PATTERNS, rawBody);
  findings.push({
    id: 'DPDP-N05',
    title: 'A consent mechanism is present before non-essential processing',
    severity: 'medium',
    status: hasConsentUi ? 'pass' : 'warn',
    clauses: ['R3'],
    evidence: hasConsentUi
      ? 'A consent or cookie-preference component was detected in the landing markup.'
      : 'No consent or cookie-preference component detected in the landing markup.',
    why: hasConsentUi
      ? 'A consent surface exists. Whether it genuinely blocks processing before acceptance is not verifiable from markup alone and should be tested manually.'
      : 'If any non-essential tracking runs on load, it is running without consent. Note that DPDP consent must be free, specific, informed and unconditional, so a banner whose only option is Accept does not satisfy it even when present.',
    fix: hasConsentUi
      ? 'Manually verify that non-essential tags do not fire until consent is recorded, and that refusal is as easy as acceptance.'
      : 'Implement a consent gate for non-essential processing, with an equally prominent reject action and a durable, auditable consent record.',
  });

  ctx.policyUrl = located ? located.url : null;
  return findings;
}

module.exports = { run };
