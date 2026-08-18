'use strict';

/**
 * Third-party inventory.
 *
 * DPDP relevance: every third-party origin the page loads is, in DPDP terms, a
 * candidate Data Processor. Rule 6(1)(e) requires equivalent security
 * safeguards to be secured by contract with each of them, and Rule 15 governs
 * transfer of personal data outside India. Most operators cannot name their
 * own third parties. This check produces the list, which is the first artefact
 * a processor register needs.
 *
 * This is deliberately reported as INFO, not as a failure. Loading a third
 * party is not a violation. Loading one you have never contracted with, and
 * cannot name, is where the exposure sits.
 */

const KNOWN = [
  [/google-analytics\.com|googletagmanager\.com|analytics\.google\.com/i, 'Google Analytics / Tag Manager', 'analytics', 'US'],
  [/facebook\.net|facebook\.com\/tr|connect\.facebook/i, 'Meta Pixel', 'advertising', 'US'],
  [/doubleclick\.net|googlesyndication\.com|googleadservices/i, 'Google Ads', 'advertising', 'US'],
  [/hotjar\.com|clarity\.ms|fullstory\.com|logrocket\.com|smartlook\.com/i, 'Session recording / heatmaps', 'behavioural (high sensitivity)', 'US/EU'],
  [/intercom\.io|crisp\.chat|tawk\.to|zendesk\.com|freshchat|drift\.com/i, 'Live chat / support', 'support (collects identifiers)', 'varies'],
  [/hubspot|marketo|mailchimp|klaviyo|sendinblue|brevo/i, 'Marketing automation', 'marketing', 'US/EU'],
  [/segment\.com|segment\.io|mixpanel\.com|amplitude\.com|posthog/i, 'Product analytics', 'analytics', 'US'],
  [/sentry\.io|bugsnag\.com|rollbar\.com|datadoghq/i, 'Error / APM telemetry', 'diagnostics', 'US'],
  [/razorpay\.com|payu\.in|cashfree\.com|ccavenue|instamojo|paytm/i, 'Payment gateway (India)', 'payments', 'IN'],
  [/stripe\.com|paypal\.com|checkout\.com/i, 'Payment gateway (foreign)', 'payments', 'US/EU'],
  [/linkedin\.com|licdn\.com|twitter\.com|x\.com|tiktok\.com/i, 'Social platform tag', 'advertising', 'US'],
  [/recaptcha|hcaptcha|turnstile/i, 'Bot protection', 'security', 'US'],
  [/fonts\.googleapis\.com|fonts\.gstatic\.com/i, 'Google Fonts', 'assets (leaks IP address)', 'US'],
];

function classify(host) {
  for (const [re, name, category, region] of KNOWN) {
    if (re.test(host)) return { name, category, region };
  }
  return { name: null, category: 'unclassified', region: 'unknown' };
}

function collectHosts(body, baseUrl) {
  const hosts = new Map();
  const base = new URL(baseUrl);
  const patterns = [
    /<script\b[^>]*\bsrc=["']([^"']+)["']/gi,
    /<iframe\b[^>]*\bsrc=["']([^"']+)["']/gi,
    /<link\b[^>]*\bhref=["']([^"']+)["'][^>]*\brel=["']stylesheet["']/gi,
    /<img\b[^>]*\bsrc=["'](https?:\/\/[^"']+)["']/gi,
  ];

  for (const re of patterns) {
    let m;
    while ((m = re.exec(body)) !== null) {
      let host;
      try {
        host = new URL(m[1], baseUrl).hostname;
      } catch (_e) {
        continue;
      }
      if (!host || host === base.hostname) continue;
      if (host.endsWith(`.${base.hostname}`)) continue; // own subdomain
      hosts.set(host, (hosts.get(host) || 0) + 1);
    }
  }
  return hosts;
}

function collectForeignForms(body, baseUrl) {
  const base = new URL(baseUrl);
  const out = [];
  const re = /<form\b[^>]*\baction=["']([^"']+)["']/gi;
  let m;
  while ((m = re.exec(body)) !== null) {
    try {
      const target = new URL(m[1], baseUrl);
      if (target.hostname !== base.hostname && !target.hostname.endsWith(`.${base.hostname}`)) {
        out.push(target.hostname);
      }
    } catch (_e) {
      /* ignore */
    }
  }
  return [...new Set(out)];
}

function run(ctx) {
  const findings = [];
  const { response } = ctx;
  if (!response.ok) return findings;

  const body = response.body || '';
  const hosts = collectHosts(body, response.finalUrl);

  const inventory = [...hosts.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([host, count]) => {
      const c = classify(host);
      return { host, refs: count, ...c };
    });

  const highSensitivity = inventory.filter(
    (i) => /behavioural|advertising/.test(i.category),
  );

  findings.push({
    id: 'DPDP-P01',
    title: 'Third-party origins loaded by the page (candidate Data Processors)',
    severity: 'info',
    status: 'info',
    clauses: ['R6(e)', 'R15', 'R3'],
    evidence: inventory.length
      ? inventory
          .map((i) => `${i.host}${i.name ? ` [${i.name}]` : ''} (${i.category}, ${i.refs} ref${i.refs > 1 ? 's' : ''})`)
          .join('\n')
      : 'No third-party origins observed on the landing page.',
    why: inventory.length
      ? `Each of these ${inventory.length} origin(s) receives, at minimum, the visitor IP address, user agent and referring URL on every page load. Under Rule 6(1)(e) each needs a contract carrying equivalent security safeguards, and under Rule 3 the categories of recipient belong in your notice. Cross-check this list against your processor register; anything here that is not in the register is an unmanaged data flow.`
      : 'No external data flows detected from the landing page markup.',
    fix: inventory.length
      ? 'Reconcile this list against your processor register and your privacy notice. Terminate anything nobody can justify.'
      : null,
    data: { inventory },
  });

  if (highSensitivity.length) {
    findings.push({
      id: 'DPDP-P02',
      title: 'Advertising or behavioural tracking present on first load',
      severity: 'medium',
      status: 'warn',
      clauses: ['R3', 'R15'],
      evidence: highSensitivity.map((i) => `${i.host} (${i.category})`).join(', '),
      why: 'Advertising and session-recording tags are non-essential processing. If any of these execute before the Data Principal has given consent, the processing has no lawful basis under the DPDP consent model. Session recorders are the sharper risk: they can capture form input, including data typed and then deleted.',
      fix: 'Gate these behind the consent mechanism, and configure input masking on any session recorder.',
    });
  }

  const foreignForms = collectForeignForms(body, response.finalUrl);
  findings.push({
    id: 'DPDP-P03',
    title: 'Forms submit to the first-party origin',
    severity: 'high',
    status: foreignForms.length ? 'warn' : 'pass',
    clauses: ['R6(e)', 'R15'],
    evidence: foreignForms.length
      ? `Form action(s) posting off-origin: ${foreignForms.join(', ')}`
      : 'No off-origin form actions found on the landing page.',
    why: foreignForms.length
      ? 'Personal data typed into these forms is delivered directly to a third party before it reaches you. That third party is a Data Processor by conduct, and the transfer may be cross-border. It must be contracted and disclosed.'
      : 'Collected data is delivered to your own origin.',
    fix: foreignForms.length
      ? 'Confirm a data processing agreement exists with each destination and name the category of recipient in the notice.'
      : null,
  });

  // Data-collection surface: does this page collect personal data at all?
  const inputs = [...body.matchAll(/<input\b[^>]*\btype=["']([^"']+)["']/gi)].map(
    (m) => m[1].toLowerCase(),
  );
  const sensitive = [...new Set(inputs.filter((t) =>
    ['password', 'email', 'tel', 'file', 'date'].includes(t),
  ))];

  findings.push({
    id: 'DPDP-S01',
    title: 'Personal data collection surface on the landing page',
    severity: 'info',
    status: 'info',
    clauses: ['S8(5)', 'R3'],
    evidence: sensitive.length
      ? `Input types present: ${sensitive.join(', ')}`
      : 'No obvious personal-data inputs on the landing page.',
    why: sensitive.length
      ? 'This page collects personal data directly, which means every transport and access-control finding above applies to a live collection point rather than a brochure page. Rule 3 requires the notice to be available at this point of collection, not only in the footer.'
      : 'No direct collection observed here. Inner pages such as signup, checkout or contact are likely to differ. Re-run against those URLs.',
    fix: null,
  });

  return findings;
}

module.exports = { run };
