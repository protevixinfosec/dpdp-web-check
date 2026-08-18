---
name: dpdp-web-check
description: >
  Run a passive DPDP (India Digital Personal Data Protection Act 2023 / DPDP
  Rules 2025) posture check against a website and interpret the structured
  result. Use when the user asks to check a site's DPDP compliance posture,
  privacy notice, grievance officer disclosure, cookie security, or wants a
  quick India-specific privacy/security header audit. Also trigger on
  "check this site for DPDP", "is this DPDP ready", "audit privacy headers".
---

# dpdp-web-check

Passive, zero-dependency check that maps a website's public security and
privacy posture to India's DPDP Act 2023 and DPDP Rules 2025. Requires
Node.js 18+ on the host running this skill. No account, no API key required
for the deterministic checks.

## Running it

If the CLI is not already available, install it once:

```bash
npm install -g @protevix/dpdp-web-check
```

Then invoke it with `--format json` so the output is machine-parsable:

```bash
dpdp-web-check <domain-or-url> --no-ai --format json
```

If the user wants a shareable report rather than a chat summary, use
`--format html --out` instead — it produces a single self-contained HTML
file (no external assets) that opens well in any browser and can be
attached or printed to PDF.

Always pass `--no-ai`: the narrative layer needs the user's own LLM key
via `LLM_API_KEY`/`DPDP_LLM`, and this skill should not assume one is
configured. If the user has explicitly set those environment variables and
wants the narrative included, omit `--no-ai`.

## Reading the result

The JSON has this shape:

```json
{
  "target": "https://example.com",
  "observableSafeguardsScore": 74,
  "tally": { "pass": 12, "fail": 3, "warn": 3, "info": 3, "unknown": 0 },
  "findings": [
    {
      "id": "DPDP-N02",
      "title": "A Grievance Officer or DPO contact is published",
      "severity": "high",
      "status": "fail",
      "clauses": ["S13", "R14"],
      "evidence": "...",
      "why": "...",
      "fix": "...",
      "clauseDetail": [ { "ref": "DPDP Act 2023, Section 13", "title": "...", "maxPenalty": "..." } ]
    }
  ],
  "limits": [ "..." ],
  "disclaimer": "Passive observation of publicly served responses. Not legal advice, not a compliance certification, not a penetration test."
}
```

When summarising for the user:

1. Lead with `tally` and `observableSafeguardsScore`, but **always repeat
   the disclaimer** — this is an observability score, not a compliance
   verdict. Never tell the user their site "is DPDP compliant" based on this
   output.
2. Group findings by `status`. Present `fail` items first, ordered by
   `severity` (`high` > `medium` > `low`), then `warn`, then mention `pass`
   briefly, then `info` only if the user asks for detail.
3. For each `fail` or `warn` finding, surface the `fix` field verbatim or
   near-verbatim — it is already written as an actionable instruction.
4. If asked "are we compliant", answer with what `limits` says the tool
   cannot see, and recommend a qualified advisor review notice wording.
   Do not omit this even if the user seems to want a simple yes/no.
5. Exit code from the underlying command: `0` no failures, `1` one or more
   failures, `2` target unreachable. If exit code is `2`, do not report
   findings — report that the target could not be reached and why (see
   stderr).

## Example agent turn

User: "Check protevixinfosec.com against DPDP"

```bash
dpdp-web-check protevixinfosec.com --no-ai --format json
```

Then summarise: pass/fail/warn counts, the score with its disclaimer, the
highest-severity failures with their fixes, and close with what the tool
could not see plus a recommendation to get notice wording reviewed.

## Constraints for the agent

- Never claim the target "is compliant" or "is certified" regardless of
  score. The tool's own system prompt for its optional AI narrative bans
  these words for the same reason; honor that even when writing your own
  summary instead of the tool's narrative.
- Only run this against a target the user owns or has explicit permission
  to assess. If the user's intent is ambiguous (e.g. checking a third
  party's site with no stated relationship), ask before running.
- Do not chain this into other scanning/exploitation tools. This skill is
  read-only and passive by design; keep it that way.
