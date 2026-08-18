'use strict';

/**
 * Bring-your-own-key narrative layer.
 *
 * Design rules, in order of importance:
 *
 *   1. The tool is fully useful with NO key. Every check, every clause
 *      mapping, every remediation string is deterministic and local. The LLM
 *      only rewrites findings into a narrative a non-engineer can act on.
 *      If this file never runs, you still get the whole assessment.
 *
 *   2. The key is read from the environment or a local config file and is sent
 *      to exactly one place: the provider endpoint the user chose. It is never
 *      logged, never written to the report, and never transmitted to Protevix.
 *
 *   3. Only findings are sent upstream, never raw page bodies. The prompt
 *      carries check IDs, statuses, evidence strings and clause references.
 *      Response bodies stay on the machine that ran the scan.
 *
 * Configure:
 *   export DPDP_LLM="anthropic/claude-sonnet-4-6"
 *   export LLM_API_KEY="..."
 *   export LLM_API_BASE="http://localhost:11434/v1"   # optional, local models
 */

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const CONFIG_PATH = path.join(os.homedir(), '.dpdp-web-check', 'config.json');

function loadConfig() {
  const fromFile = (() => {
    try {
      return JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
    } catch (_e) {
      return {};
    }
  })();

  return {
    model: process.env.DPDP_LLM || fromFile.model || null,
    apiKey: process.env.LLM_API_KEY || fromFile.apiKey || null,
    apiBase: process.env.LLM_API_BASE || fromFile.apiBase || null,
  };
}

function parseModel(spec) {
  const idx = String(spec).indexOf('/');
  if (idx === -1) return { provider: 'openai', model: spec };
  return { provider: spec.slice(0, idx), model: spec.slice(idx + 1) };
}

const SYSTEM_PROMPT = `You are writing the narrative section of a DPDP posture report for an Indian business owner who is not a security engineer.

Hard rules:
- Never say the organisation is "compliant", "DPDP compliant", "certified", or "audit ready". This tool observes a website from outside; it cannot determine compliance. Say what was observed and what it implies.
- Never invent a finding. Use only the findings supplied. If evidence is thin, say so.
- Do not give legal advice. Refer to clauses as context for a technical observation, and recommend that legal wording be reviewed by a qualified advisor.
- Write in plain English. Use contractions. No em dashes. No filler phrases like "it is important to note".
- Be specific about consequence: what could actually happen to a real customer's data, not abstract risk language.
- Indian context. Rupees, Indian regulator names, Indian business reality.

Structure your output as markdown with exactly these sections:
## What this means for your business
Three to five sentences. Lead with the single most consequential observation.

## Fix these first
A numbered list of at most five items. Each item: what to do, why it matters in one sentence, and roughly how long it takes.

## What this check could not see
Two to four sentences restating the stated limits honestly.`;

function buildUserPrompt(target, findings, limits) {
  const compact = findings.map((f) => ({
    id: f.id,
    title: f.title,
    status: f.status,
    severity: f.severity,
    clauses: f.clauses,
    evidence: typeof f.evidence === 'string' ? f.evidence.slice(0, 600) : '',
    why: f.why,
    fix: f.fix,
  }));

  return [
    `Target: ${target}`,
    '',
    'Findings (JSON):',
    JSON.stringify(compact, null, 1),
    '',
    'Stated limits of this tool:',
    limits.map((l) => `- ${l}`).join('\n'),
  ].join('\n');
}

async function callAnthropic({ model, apiKey, apiBase }, system, user) {
  const base = apiBase || 'https://api.anthropic.com';
  const res = await fetch(`${base}/v1/messages`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model,
      max_tokens: 2000,
      system,
      messages: [{ role: 'user', content: user }],
    }),
  });
  if (!res.ok) throw new Error(`Anthropic ${res.status}: ${await res.text()}`);
  const data = await res.json();
  return (data.content || [])
    .filter((b) => b.type === 'text')
    .map((b) => b.text)
    .join('\n');
}

async function callOpenAiCompatible({ model, apiKey, apiBase }, system, user) {
  const base = apiBase || 'https://api.openai.com/v1';
  const res = await fetch(`${base}/chat/completions`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      ...(apiKey ? { authorization: `Bearer ${apiKey}` } : {}),
    },
    body: JSON.stringify({
      model,
      max_tokens: 2000,
      messages: [
        { role: 'system', content: system },
        { role: 'user', content: user },
      ],
    }),
  });
  if (!res.ok) throw new Error(`OpenAI-compatible ${res.status}: ${await res.text()}`);
  const data = await res.json();
  return data.choices && data.choices[0] ? data.choices[0].message.content : '';
}

async function callGoogle({ model, apiKey, apiBase }, system, user) {
  const base = apiBase || 'https://generativelanguage.googleapis.com/v1beta';
  const res = await fetch(
    `${base}/models/${model}:generateContent?key=${encodeURIComponent(apiKey)}`,
    {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        systemInstruction: { parts: [{ text: system }] },
        contents: [{ role: 'user', parts: [{ text: user }] }],
      }),
    },
  );
  if (!res.ok) throw new Error(`Google ${res.status}: ${await res.text()}`);
  const data = await res.json();
  const cand = data.candidates && data.candidates[0];
  return cand ? cand.content.parts.map((p) => p.text).join('') : '';
}

/**
 * Generate the narrative. Returns null (never throws) when no key is
 * configured, so the CLI degrades cleanly to deterministic output.
 */
async function narrate(target, findings, limits) {
  const cfg = loadConfig();
  if (!cfg.model || (!cfg.apiKey && !cfg.apiBase)) return null;

  const { provider, model } = parseModel(cfg.model);
  const args = { model, apiKey: cfg.apiKey, apiBase: cfg.apiBase };
  const system = SYSTEM_PROMPT;
  const user = buildUserPrompt(target, findings, limits);

  switch (provider) {
    case 'anthropic':
      return callAnthropic(args, system, user);
    case 'google':
    case 'gemini':
      return callGoogle(args, system, user);
    default:
      // openai, groq, together, openrouter, ollama, lmstudio, deepseek, etc.
      return callOpenAiCompatible(args, system, user);
  }
}

module.exports = { narrate, loadConfig, CONFIG_PATH, SYSTEM_PROMPT };
