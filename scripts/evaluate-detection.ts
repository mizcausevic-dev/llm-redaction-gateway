// Curated synthetic probes. These are regression evidence, not a population
// sample or a measured real-world detection rate.
import { redactText } from '../src/governance/redaction-engine';
import { processGatewayRequest, type PolicyDecision } from '../src/governance/policy-engine';

interface Probe {
  id: string;
  text: string;
  expectedPattern: string | null;
  expectedDecision: PolicyDecision;
}

const supported: Probe[] = [
  { id: 'clean-text', text: 'Summarize the public meeting agenda.', expectedPattern: null, expectedDecision: 'allow' },
  { id: 'short-ticket', text: 'Ticket 12345678 is in progress.', expectedPattern: null, expectedDecision: 'allow' },
  { id: 'ssn-hyphen', text: 'SSN 123-45-6789', expectedPattern: 'ssn-us', expectedDecision: 'redact' },
  { id: 'ssn-space', text: 'SSN 123 45 6789', expectedPattern: 'ssn-us', expectedDecision: 'redact' },
  { id: 'ssn-dot', text: 'SSN 123.45.6789', expectedPattern: 'ssn-us', expectedDecision: 'redact' },
  { id: 'phone-parentheses', text: 'Call (212) 555-0123', expectedPattern: 'us-phone', expectedDecision: 'redact' },
  { id: 'email-plus', text: 'Email user+tag@example.com', expectedPattern: 'email', expectedDecision: 'redact' },
  { id: 'credit-card', text: 'Card 4532 1234 5678 9014', expectedPattern: 'credit-card', expectedDecision: 'block' },
  { id: 'aws-access-id', text: 'Use AKIA' + 'A'.repeat(16), expectedPattern: 'aws-access-key', expectedDecision: 'block' },
  { id: 'generic-api-key-spaced', text: 'api key: abcdefghijklmnopqrstuvwxyz123456', expectedPattern: 'generic-api-key', expectedDecision: 'block' },
  { id: 'github-pat', text: 'ghp_' + 'A'.repeat(36), expectedPattern: 'github-pat', expectedDecision: 'block' },
  { id: 'medical-record', text: 'Medical record number 12345678', expectedPattern: 'mrn', expectedDecision: 'block' },
  { id: 'classified-marker', text: 'CONFIDENTIAL project notes', expectedPattern: 'classified-marker', expectedDecision: 'block' },
  { id: 'database-url', text: 'postgres://' + 'admin:fakepass@db.internal:5432/test', expectedPattern: 'connection-string', expectedDecision: 'redact' },
];

// Expected misses and false positives are visible in the report. They keep
// production detection accuracy blocked until the threat model and data exist.
const challenge: Probe[] = [
  { id: 'obfuscated-email', text: 'user [at] example [dot] com', expectedPattern: 'email', expectedDecision: 'redact' },
  { id: 'joined-ssn', text: 'SSN 123456789', expectedPattern: 'ssn-us', expectedDecision: 'redact' },
  { id: 'phone-spaces', text: 'Call 212 555 0123', expectedPattern: 'us-phone', expectedDecision: 'redact' },
  { id: 'card-shaped-ticket', text: 'Ticket 1234-5678-9012-3456', expectedPattern: null, expectedDecision: 'allow' },
];

function evaluate(probes: Probe[]) {
  const cases = probes.map((probe) => {
    const result = redactText(probe.text);
    const decision = processGatewayRequest(result).decision;
    const observedPatterns = result.hits.map((hit) => hit.patternName);
    const patternMatches = probe.expectedPattern === null
      ? observedPatterns.length === 0
      : observedPatterns.includes(probe.expectedPattern);
    return {
      id: probe.id,
      passed: patternMatches && decision === probe.expectedDecision,
      expectedPattern: probe.expectedPattern,
      observedPatterns,
      expectedDecision: probe.expectedDecision,
      observedDecision: decision,
    };
  });
  return {
    total: cases.length,
    passed: cases.filter((item) => item.passed).length,
    mismatches: cases.filter((item) => !item.passed),
  };
}

const report = {
  syntheticOnly: true,
  supported: evaluate(supported),
  challenge: evaluate(challenge),
  limitation: 'Curated examples do not establish real-world recall, precision, or safe provider egress.',
};

console.log(JSON.stringify(report, null, 2));
if (report.supported.mismatches.length > 0) process.exitCode = 1;
