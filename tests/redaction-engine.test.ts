import { test } from 'node:test';
import assert from 'node:assert/strict';
import { redactText, unredact } from '../src/governance/redaction-engine';

test('redactText: clean text yields no hits, no redaction', () => {
  const r = redactText('Just summarize this article about cats please.');
  assert.equal(r.hits.length, 0);
  assert.equal(r.redacted, r.original);
  assert.equal(r.highestSeverity, null);
});

test('redactText: SSN replaced with stable token', () => {
  const r = redactText('Customer SSN is 123-45-6789, please verify.');
  assert.equal(r.hits.length, 1);
  assert.equal(r.hits[0].patternName, 'ssn-us');
  assert.match(r.redacted, /\[SSN_1\]/);
  assert.doesNotMatch(r.redacted, /123-45-6789/);
});

test('redactText: same value gets same token across the call', () => {
  const r = redactText('Email a@x.com and b@x.com and a@x.com again.');
  // a@x.com appears twice, b@x.com once → two unique tokens, one reused
  const tokens = new Set(r.hits.map((h) => h.token));
  assert.equal(tokens.size, 2);
  // a@x.com → [EMAIL_1] in both occurrences
  const aHits = r.hits.filter((h) => h.matchedValue === 'a@x.com');
  assert.equal(aHits.length, 2);
  assert.equal(aHits[0].token, aHits[1].token);
});

test('redactText: AWS key flagged critical', () => {
  const r = redactText('Use AKIAIOSFODNN7EXAMPLE for S3 bucket.');
  assert.ok(r.hits.some((h) => h.patternName === 'aws-access-key'));
  assert.equal(r.highestSeverity, 'critical');
});

test('redactText: GitHub PAT detected', () => {
  const r = redactText('Set GH_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789');
  assert.ok(r.hits.some((h) => h.patternName === 'github-pat'));
  assert.match(r.redacted, /\[GITHUB_PAT_1\]/);
  assert.doesNotMatch(r.redacted, /aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789/);
});

test('redactText: credit card detected and redacted', () => {
  const r = redactText('Card 4532-1234-5678-9010 expired');
  assert.ok(r.hits.some((h) => h.patternName === 'credit-card'));
  assert.match(r.redacted, /\[CC_1\]/);
});

test('redactText: classified marker detected', () => {
  const r = redactText('CONFIDENTIAL: Do not share outside the company.');
  assert.ok(r.hits.some((h) => h.patternName === 'classified-marker'));
});

test('redactText: snippet is redacted in hit metadata', () => {
  const r = redactText('Token ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789 here');
  const hit = r.hits.find((h) => h.patternName === 'github-pat');
  assert.ok(hit);
  assert.match(hit!.matchedSnippet, /\*+/);
  // The redacted snippet should NOT contain the full original token
  assert.ok(hit!.matchedSnippet.length < hit!.matchedValue.length);
});

test('redactText: multiple categories aggregated', () => {
  const r = redactText('CONFIDENTIAL: SSN 123-45-6789 and email user@corp.com');
  assert.ok(r.byCategory.pii >= 1);
  assert.ok(r.byCategory['internal-marker'] >= 1);
  assert.equal(r.highestSeverity, 'critical');
});

test('redactText: excludePatternNames disables specific patterns', () => {
  const r = redactText('Email me at user@corp.com', {
    excludePatternNames: ['email'],
  });
  assert.equal(r.hits.length, 0);
});

test('redactText: token map round-trips via unredact', () => {
  const r = redactText('SSN 123-45-6789 and email a@b.com');
  // Now reverse via unredact
  const restored = unredact(r.redacted, r.tokenMap);
  assert.equal(restored, r.original);
});

test('redactText: connection string detected and redacted', () => {
  const r = redactText('Use postgres://admin:S3cret123@db-prod.internal:5432/users for testing');
  assert.ok(r.hits.some((h) => h.patternName === 'connection-string'));
});

test('redactText: hit indices are correct', () => {
  const text = 'prefix 123-45-6789 suffix';
  const r = redactText(text);
  const hit = r.hits[0];
  assert.equal(hit.startIndex, 7);
  assert.equal(hit.endIndex, 18);
  assert.equal(text.slice(hit.startIndex, hit.endIndex), '123-45-6789');
});

test('unredact: handles overlapping token prefixes correctly', () => {
  const tokenMap = { '[A_1]': 'long-original-value', '[A_10]': 'second-value' };
  const text = 'Reference [A_10] and [A_1] here';
  const restored = unredact(text, tokenMap);
  assert.match(restored, /second-value/);
  assert.match(restored, /long-original-value/);
});
