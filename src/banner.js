'use strict';

/**
 * Zero-dependency block-letter ASCII banner.
 *
 * This is a hand-built font table, not the `figlet` npm package. Pulling in
 * figlet for one banner would mean explaining a new dependency for a cosmetic
 * feature; the font table below keeps the "zero npm dependencies" claim in
 * the README literally true.
 *
 * Only covers what a domain name + a short title can contain: A-Z, 0-9,
 * space, dot, dash. Anything outside that set is dropped from the banner
 * text (never crashes, never prints garbage).
 */

const NO_COLOUR = process.env.NO_COLOR !== undefined || !process.stdout.isTTY;
const CYAN = '\u001b[36m';
const BOLD = '\u001b[1m';
const RESET = '\u001b[0m';

const H = 6; // glyph height in rows

// Each glyph is 6 equal-length rows. Widths vary by letter, like a real
// proportional font, so letters aren't artificially stretched to match.
const FONT = {
  A: [' ## ', '#  #', '#  #', '####', '#  #', '#  #'],
  B: ['### ', '#  #', '### ', '#  #', '#  #', '### '],
  C: [' ###', '#   ', '#   ', '#   ', '#   ', ' ###'],
  D: ['### ', '#  #', '#  #', '#  #', '#  #', '### '],
  E: ['####', '#   ', '### ', '#   ', '#   ', '####'],
  F: ['####', '#   ', '### ', '#   ', '#   ', '#   '],
  G: [' ###', '#   ', '# ##', '#  #', '#  #', ' ###'],
  H: ['#  #', '#  #', '####', '#  #', '#  #', '#  #'],
  I: ['###', ' # ', ' # ', ' # ', ' # ', '###'],
  J: ['  ##', '   #', '   #', '   #', '#  #', ' ## '],
  K: ['#  #', '# # ', '##  ', '# # ', '#  #', '#  #'],
  L: ['#   ', '#   ', '#   ', '#   ', '#   ', '####'],
  M: ['#   #', '## ##', '# # #', '#   #', '#   #', '#   #'],
  N: ['#   #', '##  #', '# # #', '#  ##', '#   #', '#   #'],
  O: [' ## ', '#  #', '#  #', '#  #', '#  #', ' ## '],
  P: ['### ', '#  #', '### ', '#   ', '#   ', '#   '],
  Q: [' ## ', '#  #', '#  #', '# ##', '#  #', ' ###'],
  R: ['### ', '#  #', '### ', '# # ', '#  #', '#  #'],
  S: [' ###', '#   ', ' ## ', '   #', '   #', '### '],
  T: ['####', ' #  ', ' #  ', ' #  ', ' #  ', ' #  '],
  U: ['#  #', '#  #', '#  #', '#  #', '#  #', ' ## '],
  V: ['#  #', '#  #', '#  #', '#  #', ' ## ', ' ## '],
  W: ['#   #', '#   #', '#   #', '# # #', '## ##', '#   #'],
  X: ['#  #', '#  #', ' ## ', ' ## ', '#  #', '#  #'],
  Y: ['#  #', '#  #', ' ## ', ' #  ', ' #  ', ' #  '],
  Z: ['####', '   #', '  # ', ' #  ', '#   ', '####'],
  0: [' ## ', '#  #', '# ##', '## #', '#  #', ' ## '],
  1: [' # ', '## ', ' # ', ' # ', ' # ', '###'],
  2: [' ## ', '#  #', '   #', '  # ', ' #  ', '####'],
  3: ['####', '   #', ' ## ', '   #', '   #', '### '],
  4: ['  # ', ' ## ', '# # ', '####', '  # ', '  # '],
  5: ['####', '#   ', '### ', '   #', '   #', '### '],
  6: [' ###', '#   ', '### ', '#  #', '#  #', ' ## '],
  7: ['####', '   #', '  # ', ' #  ', ' #  ', ' #  '],
  8: [' ## ', '#  #', ' ## ', '#  #', '#  #', ' ## '],
  9: [' ## ', '#  #', '#  #', ' ###', '   #', ' ## '],
  '.': [' ', ' ', ' ', ' ', ' ', '#'],
  '-': ['   ', '   ', '###', '   ', '   ', '   '],
  ' ': ['  ', '  ', '  ', '  ', '  ', '  '],
};

/**
 * Render text as block letters. Unsupported characters are silently
 * dropped rather than crashing or leaving a gap full of undefined.
 */
function blockText(text) {
  const chars = String(text)
    .toUpperCase()
    .split('')
    .filter((ch) => FONT[ch] !== undefined);

  if (chars.length === 0) return [];

  const rows = new Array(H).fill('');
  chars.forEach((ch) => {
    const g = FONT[ch];
    for (let r = 0; r < H; r += 1) {
      rows[r] += `${g[r]} `;
    }
  });

  return rows.map((r) => r.replace(/\s+$/, ''));
}

/**
 * @param {string} hostname e.g. "protevixinfosec.com"
 * @param {number} [width] terminal width to fit within
 * @returns {string}
 */
function renderBanner(hostname, width) {
  const cols = Math.max(60, Math.min(width || 100, 140));

  if (NO_COLOUR) {
    return ['', `  DPDP WEB CHECK  --  ${hostname}`, ''].join('\n');
  }

  const title = blockText('DPDP WEB CHECK');
  const lines = ['', `  ${CYAN}${BOLD}`];
  title.forEach((row) => lines.push(`  ${row}`));
  lines.push(`${RESET}`);

  // Truncate very long hostnames so block letters don't wrap and mangle.
  const domainBlock = blockText(
    hostname.length <= 22 ? hostname : hostname.slice(0, 22),
  );
  const domainWidth = domainBlock.length ? domainBlock[0].length : 0;

  if (domainBlock.length && domainWidth <= cols - 4) {
    lines.push(`  ${CYAN}`);
    domainBlock.forEach((row) => lines.push(`  ${row}`));
    lines.push(`${RESET}`);
  } else {
    lines.push(`  ${BOLD}${hostname}${RESET}`);
  }

  lines.push('');
  return lines.join('\n');
}

module.exports = { renderBanner, blockText };
