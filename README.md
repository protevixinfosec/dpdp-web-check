# dpdp-web-check

**Passive DPDP posture check for any website. Zero dependencies. Your key, your machine.**

India's DPDP Rules 2025 were notified on 13 November 2025. The substantive obligations under Section 8 — Rule 6 security safeguards and Rule 7 breach intimation become enforceable at the end of an 18-month runway in May 2027. Most Indian businesses have no idea what their public web surface looks like against that.

Header scanners will tell you about CSP. None of them will tell you that **Section 13 requires a readily available grievance redressal mechanism**, or that **Rule 14 requires you to publish how a Data Principal exercises their rights**, or that your privacy notice is a GDPR template that never mentions the Act you're actually governed by.

This does.

```
npx @protevix/dpdp-web-check yourdomain.com
```

---

## What it checks

| Group | Checks | Mapped to |
|---|---|---|
| **Transport** | HTTPS reachable, cleartext redirect, TLS version, certificate validity, HSTS | Rule 6(1)(a) |
| **Browser controls** | CSP, framing, MIME sniffing, Referrer-Policy, Permissions-Policy, version disclosure | Rule 6(1)(b) |
| **Session** | Cookie `Secure`, `HttpOnly`, `SameSite` | Rule 6(1)(a), 6(1)(b) |
| **Notice & rights** | Privacy notice discoverable, **Grievance Officer published**, Data Principal rights described, **DPDP-specific (not GDPR-copy) language**, consent mechanism | Rule 3, Rule 14, Section 13 |
| **Processors** | Third-party origin inventory, behavioural/ad tags on first load, off-origin form actions | Rule 6(1)(e), Rule 15 |
| **Breach readiness** | `security.txt` disclosure channel and its freshness | Section 8(6), Rule 7 |

Every finding carries the clause reference, the observed evidence, why it matters in terms of a real person's data, and a concrete fix.

---

## Saving a report instead of scrolling

```bash
# self-contained HTML, opens beautifully in any browser, works offline
dpdp-web-check example.com --format html --out

# auto-named: dpdp-report-example.com-2026-08-18.html
```

The HTML report is fully self-contained no external CSS, fonts, or scripts, nothing loaded from a CDN. It opens the same whether you're online or not, months from now, on any machine. Colour-coded findings, a score ring, clause references you can hover for the full legal text, and the Protevix Infosec logo and contact embedded directly as base64 so branding survives even when the file is emailed or saved standalone. `--format html` always saves to a file automatically, with or without `--out`, since a raw HTML document dumped into a terminal isn't something you can read.

There's no direct PDF export. Doing that without Puppeteer/Chromium would mean either losing the zero-dependency guarantee or hand-rolling a fragile PDF writer neither is worth it for a report you can open and use *Print → Save as PDF* on in one extra click from the HTML file.

Other formats, if you want them:

```bash
dpdp-web-check example.com --format md --out     # Markdown, for GitHub/Notion
dpdp-web-check example.com --format json --out   # machine-readable, for scripts and CI
dpdp-web-check example.com --format text --out   # plain terminal text, colours stripped
```

## Using it from Claude Code, Cursor, or any SKILL.md-compatible agent

```bash
npx skills add protevixinfosec/dpdp-web-check
```

This installs a `SKILL.md` that teaches the agent how to invoke the CLI with `--format json`, interpret the structured findings, and critically never claim a passing score means "DPDP compliant." The skill is agent-agnostic: works in Claude Code, and anywhere else that reads SKILL.md files.

Without the skill installed, any agent with shell access can still call it directly:

```bash
dpdp-web-check example.com --no-ai --format json
```

and parse the JSON shown in [What it checks](#what-it-checks) above.

## Install and run

Requires Node 18 or newer. Nothing else. No npm dependencies at all.

```bash
# One-off
npx @protevix/dpdp-web-check example.com

# Installed
npm install -g @protevix/dpdp-web-check
dpdp-web-check example.com

# Markdown report for your compliance folder
dpdp-web-check example.com --format md --out dpdp-report.md

# JSON for CI
dpdp-web-check example.com --format json --out result.json
```

Exit codes: `0` clean, `1` one or more failures, `2` target unreachable. Wire it into CI as a gate if you want.

---

## Bring your own key (optional)

**The tool is fully useful with no key.** Every check, clause mapping and remediation string is deterministic and computed locally. A key only adds a plain-English narrative on top for people who don't read security output for a living.

```bash
export DPDP_LLM="anthropic/claude-sonnet-4-6"
export LLM_API_KEY="sk-ant-..."
dpdp-web-check example.com
```

Other providers:

```bash
export DPDP_LLM="openai/gpt-5.4"
export DPDP_LLM="google/gemini-3-pro-preview"

# Any OpenAI-compatible endpoint, including local models
export DPDP_LLM="llama3.1"
export LLM_API_BASE="http://localhost:11434/v1"
```

Or persist it in `~/.dpdp-web-check/config.json`:

```json
{ "model": "anthropic/claude-sonnet-4-6", "apiKey": "sk-ant-..." }
```

### What is sent where

- Your key goes to **your chosen provider endpoint and nowhere else**. It is never logged, never written into a report, and never transmitted to Protevix Infosec.
- Only the **findings** are sent upstream: check IDs, statuses, short evidence strings and clause references. **Page bodies never leave your machine.**
- Run with `--no-ai` to disable the narrative entirely even when a key is configured.

There is no telemetry in this tool. There is no account. There is no server.

---

## What this is not

Read this bit. It is the whole reason the tool is honest enough to be worth running.

- **It is not a compliance assessment.** It observes a website from outside. Most DPDP obligations are organisational and structurally invisible from there.
- **It is not legal advice.** Clause references are engineering context. Have any notice wording reviewed by a qualified advisor.
- **It is not a penetration test.** Every request is a plain GET. Nothing is injected, fuzzed, brute-forced, or bypassed.
- **A passing check is not a met obligation.** It means the externally observable half looks right.

Things this cannot see, and says so in every report:

- Encryption at rest and key management — Rule 6(1)(a)
- Internal access control and privileged access review — Rule 6(1)(b)
- Whether logs exist, are monitored, and are kept for a year — Rules 6(1)(c) and 6(1)(f)
- Backup, recovery and continuity — Rule 6(1)(d)
- Data Processor contracts — Rule 6(1)(e)
- Whether a working 72-hour breach process exists — Rule 7
- Actual retention and erasure practice — Rule 8
- Whether consent was validly obtained and is genuinely withdrawable — Rule 3

The "observable safeguards score" is deliberately **not** called a compliance score, and no output of this tool should be presented to a regulator, auditor or customer as one.

---

## Authorised use only

Run this against sites you own or have written permission to assess. It is passive, but "passive" is not a legal defence in every jurisdiction and it is not one here either. You are responsible for authorisation.

---

## Contributing

New checks are welcome, especially ones that are specific to Indian regulatory practice rather than generic header hygiene. A good check has:

1. A clause it genuinely maps to, cited precisely.
2. Evidence that is observable without touching anything.
3. A `why` written in terms of what happens to a real person's data.
4. A fix a developer can act on in under an hour.

Checks that produce noise, or that require active probing, will be declined.

---

## Who made this

Built by [Protevix Infosec](https://protevixinfosec.com), Pune.

We also run [KScan](https://kscan.protevixinfosec.com), a paid automated web application security assessment that goes considerably deeper than this actual vulnerability discovery across the application, with a written analyst narrative. `dpdp-web-check` is free and always will be. It is not a trial, a demo, or a lead-capture form. It does what it says and it does not phone home.

Apache-2.0.
