'use strict';

/**
 * Minimal HTTP(S) client built on Node core only.
 *
 * Why not `fetch`? We need three things the fetch API hides:
 *   1. The negotiated TLS protocol version and the peer certificate.
 *   2. The raw, un-merged `Set-Cookie` header list.
 *   3. Full control over redirects, so we can inspect each hop
 *      (an HTTP -> HTTPS upgrade is itself a DPDP-relevant observation).
 *
 * Every request here is a plain GET or HEAD. Nothing in this module
 * sends a payload, mutates state, or attempts to bypass a control.
 */

const https = require('node:https');
const http = require('node:http');
const { URL } = require('node:url');

const DEFAULT_TIMEOUT_MS = 15000;
const MAX_BODY_BYTES = 1_500_000; // 1.5 MB is plenty for a landing page

/**
 * Perform a single request with no redirect following.
 *
 * @param {string} rawUrl
 * @param {object} [opts]
 * @param {string} [opts.method='GET']
 * @param {number} [opts.timeout]
 * @param {string} [opts.userAgent]
 * @returns {Promise<object>} response record
 */
function requestOnce(rawUrl, opts = {}) {
  const url = new URL(rawUrl);
  const isHttps = url.protocol === 'https:';
  const lib = isHttps ? https : http;
  const timeout = opts.timeout || DEFAULT_TIMEOUT_MS;

  const requestOptions = {
    method: opts.method || 'GET',
    protocol: url.protocol,
    hostname: url.hostname,
    port: url.port || (isHttps ? 443 : 80),
    path: url.pathname + url.search,
    headers: {
      'User-Agent':
        opts.userAgent ||
        'dpdp-web-check/0.1 (+https://github.com/protevixinfosec/dpdp-web-check)',
      Accept: 'text/html,application/xhtml+xml,*/*;q=0.8',
      'Accept-Language': 'en-IN,en;q=0.9',
    },
    // We deliberately do NOT reject unauthorised certificates. An expired or
    // self-signed certificate is a finding we want to report, not an error
    // that aborts the run.
    rejectUnauthorized: false,
    servername: url.hostname,
  };

  return new Promise((resolve) => {
    const started = Date.now();
    let tls = null;

    const req = lib.request(requestOptions, (res) => {
      const chunks = [];
      let bytes = 0;
      let truncated = false;

      res.on('data', (chunk) => {
        bytes += chunk.length;
        if (bytes > MAX_BODY_BYTES) {
          truncated = true;
          res.destroy();
          return;
        }
        chunks.push(chunk);
      });

      const finish = () => {
        resolve({
          ok: true,
          url: rawUrl,
          finalUrl: rawUrl,
          status: res.statusCode,
          headers: res.headers,
          rawHeaders: res.rawHeaders,
          setCookie: res.headers['set-cookie'] || [],
          body: Buffer.concat(chunks).toString('utf8'),
          truncated,
          tls,
          elapsedMs: Date.now() - started,
        });
      };

      res.on('end', finish);
      res.on('close', finish);
    });

    req.on('socket', (socket) => {
      socket.on('secureConnect', () => {
        try {
          const cert = socket.getPeerCertificate(false) || {};
          tls = {
            protocol: socket.getProtocol(),
            cipher: socket.getCipher() ? socket.getCipher().name : null,
            authorized: socket.authorized === true,
            authorizationError: socket.authorizationError
              ? String(socket.authorizationError)
              : null,
            subject: cert.subject || null,
            issuer: cert.issuer || null,
            validFrom: cert.valid_from || null,
            validTo: cert.valid_to || null,
            subjectAltName: cert.subjectaltname || null,
          };
        } catch (_err) {
          tls = null;
        }
      });
    });

    req.setTimeout(timeout, () => {
      req.destroy();
      resolve({
        ok: false,
        url: rawUrl,
        error: `timeout after ${timeout}ms`,
        tls,
      });
    });

    req.on('error', (err) => {
      resolve({ ok: false, url: rawUrl, error: err.message, tls });
    });

    req.end();
  });
}

/**
 * Request a URL, following redirects and recording every hop.
 *
 * @param {string} rawUrl
 * @param {object} [opts]
 * @param {number} [opts.maxRedirects=5]
 * @returns {Promise<object>} response record with a `chain` array
 */
async function request(rawUrl, opts = {}) {
  const maxRedirects = opts.maxRedirects === undefined ? 5 : opts.maxRedirects;
  const chain = [];
  let current = rawUrl;

  for (let hop = 0; hop <= maxRedirects; hop += 1) {
    const res = await requestOnce(current, opts);
    chain.push({
      url: current,
      status: res.status || null,
      location: res.headers ? res.headers.location || null : null,
      error: res.error || null,
    });

    if (!res.ok) return { ...res, chain };

    const isRedirect =
      res.status >= 300 && res.status < 400 && res.headers.location;

    if (!isRedirect || hop === maxRedirects) {
      return { ...res, finalUrl: current, chain };
    }

    current = new URL(res.headers.location, current).toString();
  }

  return { ok: false, url: rawUrl, error: 'redirect limit exceeded', chain };
}

/**
 * Normalise whatever the user typed into a usable https URL.
 * `example.com` -> `https://example.com/`
 */
function normaliseTarget(input) {
  let value = String(input || '').trim();
  if (!value) throw new Error('empty target');
  if (!/^https?:\/\//i.test(value)) value = `https://${value}`;
  const url = new URL(value);
  if (!url.pathname) url.pathname = '/';
  return url;
}

module.exports = { request, requestOnce, normaliseTarget, DEFAULT_TIMEOUT_MS };
