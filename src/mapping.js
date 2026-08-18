'use strict';

/**
 * Clause reference table for the Digital Personal Data Protection Act, 2023
 * and the Digital Personal Data Protection Rules, 2025 (notified 13 Nov 2025).
 *
 * IMPORTANT — read this before trusting the output:
 *
 * This table exists so that a technical finding can be pointed at the part of
 * the law it plausibly relates to. It is an engineering aid, not a legal
 * opinion. A passing check does NOT mean the obligation is met: most DPDP
 * obligations are organisational (contracts, logs, retention, breach process)
 * and are simply not visible from outside a website. See LIMITS below.
 */

const CLAUSES = {
  'S8(5)': {
    ref: 'DPDP Act 2023, Section 8(5)',
    title: 'Reasonable security safeguards',
    text:
      'A Data Fiduciary shall protect personal data in its possession or under its control by taking reasonable security safeguards to prevent personal data breach.',
    maxPenalty: 'Up to Rs 250 crore (Schedule to the Act)',
  },
  'S8(6)': {
    ref: 'DPDP Act 2023, Section 8(6)',
    title: 'Personal data breach intimation',
    text:
      'On becoming aware of a personal data breach, the Data Fiduciary shall give intimation to the Board and to each affected Data Principal.',
    maxPenalty: 'Up to Rs 200 crore (Schedule to the Act)',
  },
  S13: {
    ref: 'DPDP Act 2023, Section 13',
    title: 'Right to grievance redressal',
    text:
      'A Data Principal shall have the right to readily available means of grievance redressal provided by the Data Fiduciary.',
    maxPenalty: null,
  },
  R3: {
    ref: 'DPDP Rules 2025, Rule 3',
    title: 'Notice given by Data Fiduciary',
    text:
      'Notice must be presented independently, in clear and plain language, itemising the personal data collected and the purpose, and must describe how to withdraw consent and exercise rights.',
    maxPenalty: null,
  },
  'R6(a)': {
    ref: 'DPDP Rules 2025, Rule 6(1)(a)',
    title: 'Data security measures',
    text:
      'Securing personal data through encryption, obfuscation, masking, or the use of virtual tokens mapped to that personal data.',
    maxPenalty: 'Rolls up to Section 8(5)',
  },
  'R6(b)': {
    ref: 'DPDP Rules 2025, Rule 6(1)(b)',
    title: 'Access control',
    text:
      'Appropriate measures to control access to the computer resources used by the Data Fiduciary or Data Processor.',
    maxPenalty: 'Rolls up to Section 8(5)',
  },
  'R6(c)': {
    ref: 'DPDP Rules 2025, Rule 6(1)(c)',
    title: 'Logging, monitoring and review',
    text:
      'Visibility on the accessing of personal data through appropriate logs, monitoring and review, to enable detection, investigation and remediation of unauthorised access.',
    maxPenalty: 'Rolls up to Section 8(5)',
  },
  'R6(d)': {
    ref: 'DPDP Rules 2025, Rule 6(1)(d)',
    title: 'Continuity and recovery',
    text:
      'Reasonable measures for continued processing where confidentiality, integrity or availability of personal data is compromised.',
    maxPenalty: 'Rolls up to Section 8(5)',
  },
  'R6(e)': {
    ref: 'DPDP Rules 2025, Rule 6(1)(e)',
    title: 'Processor safeguards by contract',
    text:
      'Where processing is carried out by a Data Processor on behalf of the Data Fiduciary, equivalent reasonable security safeguards must be secured contractually.',
    maxPenalty: 'Rolls up to Section 8(5)',
  },
  'R6(f)': {
    ref: 'DPDP Rules 2025, Rule 6(1)(f)',
    title: 'Log retention',
    text:
      'Retention of logs and personal data for a period of one year unless a longer period is required by law.',
    maxPenalty: 'Rolls up to Section 8(5)',
  },
  R7: {
    ref: 'DPDP Rules 2025, Rule 7',
    title: 'Intimation of personal data breach',
    text:
      'Affected Data Principals must be intimated without delay; the Board must receive an initial intimation without delay and a detailed report within 72 hours of awareness.',
    maxPenalty: 'Rolls up to Section 8(6)',
  },
  R8: {
    ref: 'DPDP Rules 2025, Rule 8',
    title: 'Retention and erasure',
    text:
      'Personal data must be erased on expiry of the specified retention period, with prior notice to the Data Principal.',
    maxPenalty: null,
  },
  R14: {
    ref: 'DPDP Rules 2025, Rule 14',
    title: 'Exercise of Data Principal rights',
    text:
      'The Data Fiduciary must publish the means by which a Data Principal may make a request to exercise their rights, and the particulars required to identify them.',
    maxPenalty: null,
  },
  R15: {
    ref: 'DPDP Rules 2025, Rule 15',
    title: 'Cross-border transfer',
    text:
      'Transfer of personal data outside India is subject to such restrictions as the Central Government may specify.',
    maxPenalty: null,
  },
};

/**
 * What this tool structurally cannot see. Printed in every report so nobody
 * mistakes a green result for a compliance position.
 */
const LIMITS = [
  'Encryption at rest, key management and database controls (Rule 6(1)(a)) are invisible from outside.',
  'Internal access control, RBAC and privileged access review (Rule 6(1)(b)) are invisible from outside.',
  'Whether logs exist, are monitored, and are retained for one year (Rules 6(1)(c) and 6(1)(f)) is invisible from outside.',
  'Backup, recovery and continuity arrangements (Rule 6(1)(d)) are invisible from outside.',
  'Data Processor contracts and their security clauses (Rule 6(1)(e)) are invisible from outside.',
  'Whether a working 72-hour breach notification process exists (Rule 7) is invisible from outside.',
  'Actual retention periods and erasure practice (Rule 8) are invisible from outside.',
  'Whether consent was validly obtained, recorded and is withdrawable in practice (Rule 3) cannot be confirmed by inspecting markup.',
];

const ENFORCEMENT_NOTE =
  'The DPDP Rules 2025 were notified on 13 November 2025. The substantive obligations under Section 8, including Rule 6 security safeguards and Rule 7 breach intimation, become enforceable after an 18-month runway ending in May 2027. Verify the current position before relying on any date here.';

function clause(key) {
  return CLAUSES[key] || { ref: key, title: 'Unmapped', text: '', maxPenalty: null };
}

module.exports = { CLAUSES, LIMITS, ENFORCEMENT_NOTE, clause };
