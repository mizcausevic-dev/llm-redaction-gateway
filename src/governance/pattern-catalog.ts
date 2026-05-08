// Detection pattern catalog. Each pattern carries a category, severity,
// and policy default (block / redact / warn). The catalog is deliberately
// expanded vs shadow-ai-detector because this gateway is the LAST line of
// defense before egress — false negatives here mean leaked secrets.

export type Category =
  | 'credential'
  | 'pii'
  | 'pci'
  | 'health'
  | 'internal-marker'
  | 'source-code';

export type Severity = 'critical' | 'high' | 'medium' | 'low';

export type DefaultPolicy = 'block' | 'redact' | 'warn';

export interface DetectionPattern {
  name: string;
  category: Category;
  severity: Severity;
  regex: RegExp;
  description: string;
  defaultPolicy: DefaultPolicy;
  // Token format used in redacted output (e.g., '[SSN_X]')
  tokenLabel: string;
}

export const PATTERN_CATALOG: DetectionPattern[] = [
  // Credentials
  { name: 'private-key-block', category: 'credential', severity: 'critical', regex: /-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----[\s\S]+?-----END\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----/i, description: 'Private key block.', defaultPolicy: 'block', tokenLabel: 'PRIVATE_KEY' },
  { name: 'aws-access-key', category: 'credential', severity: 'critical', regex: /\bAKIA[0-9A-Z]{16}\b/g, description: 'AWS access key ID.', defaultPolicy: 'block', tokenLabel: 'AWS_KEY' },
  { name: 'aws-secret-key', category: 'credential', severity: 'critical', regex: /\b[A-Za-z0-9/+=]{40}\b(?=\s*["']?(?:\s*(?:#|\/\/).*)?$|\s*[,}])/gm, description: 'Possible AWS secret key.', defaultPolicy: 'redact', tokenLabel: 'AWS_SECRET' },
  { name: 'github-pat', category: 'credential', severity: 'critical', regex: /\bghp_[A-Za-z0-9]{36,}\b/g, description: 'GitHub PAT.', defaultPolicy: 'block', tokenLabel: 'GITHUB_PAT' },
  { name: 'github-fine-pat', category: 'credential', severity: 'critical', regex: /\bgithub_pat_[A-Za-z0-9_]{60,}\b/g, description: 'GitHub fine-grained PAT.', defaultPolicy: 'block', tokenLabel: 'GITHUB_FINE_PAT' },
  { name: 'slack-token', category: 'credential', severity: 'critical', regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g, description: 'Slack token.', defaultPolicy: 'block', tokenLabel: 'SLACK_TOKEN' },
  { name: 'openai-key', category: 'credential', severity: 'critical', regex: /\bsk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{30,}\b/g, description: 'OpenAI-style secret key.', defaultPolicy: 'block', tokenLabel: 'OPENAI_KEY' },
  { name: 'anthropic-key', category: 'credential', severity: 'critical', regex: /\bsk-ant-[A-Za-z0-9_-]{40,}\b/g, description: 'Anthropic API key.', defaultPolicy: 'block', tokenLabel: 'ANTHROPIC_KEY' },
  { name: 'jwt-token', category: 'credential', severity: 'high', regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g, description: 'JWT token.', defaultPolicy: 'redact', tokenLabel: 'JWT' },
  { name: 'generic-api-key', category: 'credential', severity: 'high', regex: /\b(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token)\s*[:=]\s*["']?([A-Za-z0-9_-]{20,})["']?/gi, description: 'Generic API/secret key assignment.', defaultPolicy: 'block', tokenLabel: 'API_KEY' },
  { name: 'password-assign', category: 'credential', severity: 'high', regex: /\b(?:password|passwd|pwd)\s*[:=]\s*["']([^"'\s]{6,})["']/gi, description: 'Password assignment.', defaultPolicy: 'redact', tokenLabel: 'PASSWORD' },

  // PII
  { name: 'ssn-us', category: 'pii', severity: 'high', regex: /\b\d{3}-\d{2}-\d{4}\b/g, description: 'US SSN.', defaultPolicy: 'redact', tokenLabel: 'SSN' },
  { name: 'iban', category: 'pii', severity: 'high', regex: /\b[A-Z]{2}\d{2}[A-Z0-9]{12,28}\b/g, description: 'IBAN.', defaultPolicy: 'redact', tokenLabel: 'IBAN' },
  { name: 'us-phone', category: 'pii', severity: 'low', regex: /\b(?:\(\d{3}\)\s*|\d{3}[-.])\d{3}[-.]\d{4}\b/g, description: 'US phone number.', defaultPolicy: 'redact', tokenLabel: 'PHONE' },
  { name: 'email', category: 'pii', severity: 'low', regex: /\b[\w.+-]+@[\w-]+\.[\w.-]+\b/g, description: 'Email address.', defaultPolicy: 'redact', tokenLabel: 'EMAIL' },
  { name: 'date-of-birth', category: 'pii', severity: 'medium', regex: /\b(?:DOB|date of birth|d\.o\.b\.)[:\s]+\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}/gi, description: 'Date of birth marker.', defaultPolicy: 'redact', tokenLabel: 'DOB' },
  { name: 'ipv4', category: 'pii', severity: 'low', regex: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, description: 'IPv4 address.', defaultPolicy: 'warn', tokenLabel: 'IPV4' },

  // Payment / financial
  { name: 'credit-card', category: 'pci', severity: 'critical', regex: /\b(?:\d{4}[- ]?){3}\d{4}\b/g, description: 'Credit card number.', defaultPolicy: 'block', tokenLabel: 'CC' },
  { name: 'cvv', category: 'pci', severity: 'high', regex: /\b(?:CVV|CVC|CVV2)[:\s]+\d{3,4}\b/gi, description: 'CVV/CVC marker.', defaultPolicy: 'block', tokenLabel: 'CVV' },

  // Health
  { name: 'mrn', category: 'health', severity: 'high', regex: /\b(?:MRN|medical record (?:number|no\.?))[:\s]+[A-Z0-9-]{6,}/gi, description: 'Medical record number.', defaultPolicy: 'block', tokenLabel: 'MRN' },

  // Internal markers
  { name: 'classified-marker', category: 'internal-marker', severity: 'critical', regex: /\b(?:CONFIDENTIAL|SECRET|TOP[- ]SECRET|INTERNAL ONLY|RESTRICTED|FOUO|PROPRIETARY)\b/g, description: 'Document classification marker.', defaultPolicy: 'block', tokenLabel: 'CLASSIFIED' },
  { name: 'merger-codename', category: 'internal-marker', severity: 'high', regex: /\b(?:project (?:codename|cobalt|titan|orion|atlas|phoenix)|deal (?:codename|alpha|bravo|delta))\b/gi, description: 'M&A codename pattern.', defaultPolicy: 'block', tokenLabel: 'CODENAME' },

  // Source code
  { name: 'aws-sdk-creds', category: 'source-code', severity: 'critical', regex: /aws_secret_access_key\s*=\s*["']?[A-Za-z0-9\/+=]{30,}["']?/gi, description: 'AWS SDK credentials in code.', defaultPolicy: 'block', tokenLabel: 'AWS_SDK_CREDS' },
  { name: 'connection-string', category: 'source-code', severity: 'high', regex: /\b(?:postgres|mysql|mongodb|redis):\/\/[^:\/\s]+:[^@\/\s]+@[^\s"']+/gi, description: 'Database connection string with embedded creds.', defaultPolicy: 'redact', tokenLabel: 'CONN_STRING' },
];

export function patternsByCategory(category: Category): DetectionPattern[] {
  return PATTERN_CATALOG.filter((p) => p.category === category);
}

export function patternByName(name: string): DetectionPattern | undefined {
  return PATTERN_CATALOG.find((p) => p.name === name);
}
