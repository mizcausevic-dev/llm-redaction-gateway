// Redaction engine. Two responsibilities:
// 1. Detect pattern hits in input text.
// 2. Replace each hit with a stable token (e.g., [SSN_1]) and maintain a
//    reversal map so post-LLM responses can be un-tokenized if needed.
//
// The token map is deterministic per call: same value → same token, so
// the LLM sees consistent placeholders ([EMAIL_1] referenced twice in
// the prompt → same token both times → response can refer back).

import { PATTERN_CATALOG, type DetectionPattern, type Category, type Severity } from './pattern-catalog';

export interface DetectionHit {
  patternName: string;
  category: Category;
  severity: Severity;
  matchedValue: string;
  matchedSnippet: string;
  startIndex: number;
  endIndex: number;
  tokenLabel: string;
  token: string; // e.g., '[SSN_1]'
}

export interface RedactionResult {
  original: string;
  redacted: string;
  hits: DetectionHit[];
  tokenMap: Record<string, string>; // token → original value (for reversal)
  highestSeverity: Severity | null;
  byCategory: Record<Category, number>;
}

const SEV_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 };

function redactSnippet(s: string): string {
  if (s.length <= 6) return '****';
  return s.slice(0, 3) + '****' + s.slice(-2);
}

export interface RedactionOptions {
  patterns?: DetectionPattern[]; // default: full catalog
  excludePatternNames?: string[];
}

export function redactText(input: string, options: RedactionOptions = {}): RedactionResult {
  const exclude = new Set(options.excludePatternNames ?? []);
  const patterns = (options.patterns ?? PATTERN_CATALOG).filter((p) => !exclude.has(p.name));

  // Find all matches across all patterns. Track index ranges so we can
  // detect overlaps and resolve them by severity.
  type RawMatch = { pattern: DetectionPattern; value: string; start: number; end: number };
  const rawMatches: RawMatch[] = [];

  for (const pattern of patterns) {
    // Reset regex state by creating a fresh global regex from the source
    const flags = pattern.regex.flags.includes('g') ? pattern.regex.flags : pattern.regex.flags + 'g';
    const re = new RegExp(pattern.regex.source, flags);
    let m: RegExpExecArray | null;
    while ((m = re.exec(input)) !== null) {
      // For patterns with capture groups (api-key, password), match the full match;
      // the capture group is just for testing intent
      rawMatches.push({
        pattern,
        value: m[0],
        start: m.index,
        end: m.index + m[0].length,
      });
      if (m.index === re.lastIndex) re.lastIndex++; // avoid zero-length infinite loop
    }
  }

  // Resolve overlaps: when two matches overlap, keep the higher-severity one.
  // Sort by start, then by severity descending so higher severity wins ties.
  rawMatches.sort((a, b) => {
    if (a.start !== b.start) return a.start - b.start;
    return SEV_RANK[b.pattern.severity] - SEV_RANK[a.pattern.severity];
  });

  const accepted: RawMatch[] = [];
  for (const m of rawMatches) {
    const overlapping = accepted.find((a) => a.start < m.end && a.end > m.start);
    if (!overlapping) {
      accepted.push(m);
    } else if (SEV_RANK[m.pattern.severity] > SEV_RANK[overlapping.pattern.severity]) {
      // Replace lower-severity overlap with higher-severity one
      const idx = accepted.indexOf(overlapping);
      accepted[idx] = m;
    }
    // else: keep existing (higher- or equal-severity)
  }

  // Build deterministic token map: same value → same token across the call
  const valueToToken = new Map<string, string>();
  const tokenToValue = new Map<string, string>();
  const tokenLabelCounters = new Map<string, number>();

  for (const m of accepted) {
    if (!valueToToken.has(m.value)) {
      const counter = (tokenLabelCounters.get(m.pattern.tokenLabel) ?? 0) + 1;
      tokenLabelCounters.set(m.pattern.tokenLabel, counter);
      const token = `[${m.pattern.tokenLabel}_${counter}]`;
      valueToToken.set(m.value, token);
      tokenToValue.set(token, m.value);
    }
  }

  // Apply replacements in reverse order to keep indices stable
  accepted.sort((a, b) => b.start - a.start);
  let redacted = input;
  for (const m of accepted) {
    const token = valueToToken.get(m.value)!;
    redacted = redacted.slice(0, m.start) + token + redacted.slice(m.end);
  }

  // Build hit records (in original order)
  accepted.sort((a, b) => a.start - b.start);
  const hits: DetectionHit[] = accepted.map((m) => ({
    patternName: m.pattern.name,
    category: m.pattern.category,
    severity: m.pattern.severity,
    matchedValue: m.value,
    matchedSnippet: redactSnippet(m.value),
    startIndex: m.start,
    endIndex: m.end,
    tokenLabel: m.pattern.tokenLabel,
    token: valueToToken.get(m.value)!,
  }));

  let highestSeverity: Severity | null = null;
  const byCategory: Record<Category, number> = {
    credential: 0, pii: 0, pci: 0, 'internal-marker': 0, 'source-code': 0, health: 0,
  };
  for (const h of hits) {
    byCategory[h.category]++;
    if (highestSeverity === null || SEV_RANK[h.severity] > SEV_RANK[highestSeverity]) {
      highestSeverity = h.severity;
    }
  }

  return {
    original: input,
    redacted,
    hits,
    tokenMap: Object.fromEntries(tokenToValue),
    highestSeverity,
    byCategory,
  };
}

// Reverse a token map back into the original — useful for un-tokenizing
// LLM responses that referred to redacted placeholders.
export function unredact(text: string, tokenMap: Record<string, string>): string {
  let out = text;
  // Replace longer tokens first to avoid prefix collisions
  const entries = Object.entries(tokenMap).sort((a, b) => b[0].length - a[0].length);
  for (const [token, original] of entries) {
    // Escape regex special chars in the token literal
    const escaped = token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    out = out.replace(new RegExp(escaped, 'g'), original);
  }
  return out;
}
