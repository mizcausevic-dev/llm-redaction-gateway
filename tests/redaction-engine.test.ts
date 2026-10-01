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

test('redactText: common SSN separators are tokenized', () => {
  for (const value of ['123-45-6789', '123 45 6789', '123.45.6789']) {
    const result = redactText(`SSN: ${value}`);
    assert.ok(result.hits.some((hit) => hit.patternName === 'ssn-us'), value);
    assert.equal(result.redacted.includes(value), false, value);
  }
});

test('redactText: joined SSN needs a label, and unrelated nine-digit IDs stay untouched', () => {
  for (const value of ['SSN 123456789', 'SSN:123456789', 'Social Security Number: 321654987']) {
    const labeled = redactText(value);
    assert.deepEqual(labeled.hits.map((hit) => hit.patternName), ['ssn-us']);
    assert.equal(labeled.redacted.includes(value), false);
  }

  const unrelated = redactText('Ticket 123456789');
  assert.equal(unrelated.hits.some((hit) => hit.patternName === 'ssn-us'), false);
  assert.equal(unrelated.redacted, unrelated.original);
  assert.equal(redactText('SSN 1234567890').hits.some((hit) => hit.patternName === 'ssn-us'), false);
});

test('redactText: parenthesized US phone and spaced API key label are detected', () => {
  const phone = redactText('Call (212) 555-0123');
  assert.ok(phone.hits.some((hit) => hit.patternName === 'us-phone'));
  assert.equal(phone.redacted.includes('(212) 555-0123'), false);

  const key = redactText('api key: abcdefghijklmnopqrstuvwxyz123456');
  assert.ok(key.hits.some((hit) => hit.patternName === 'generic-api-key'));
  assert.equal(key.redacted.includes('abcdefghijklmnopqrstuvwxyz123456'), false);
});

test('redactText: space-separated phone needs a call label', () => {
  for (const value of ['Call 212 555 0123', 'Call: 212 555 0123', 'Phone: 415 555 0199']) {
    const labeled = redactText(value);
    assert.deepEqual(labeled.hits.map((hit) => hit.patternName), ['us-phone']);
    assert.equal(labeled.redacted.includes(value), false);
  }

  const unrelated = redactText('Invoice 212 555 0123');
  assert.equal(unrelated.hits.some((hit) => hit.patternName === 'us-phone'), false);
  assert.equal(unrelated.redacted, unrelated.original);
  assert.equal(redactText('Call 212 555 0123x').hits.some((hit) => hit.patternName === 'us-phone'), false);
});

test('redactText: literal [at]/[dot] address is tokenized without matching plain prose', () => {
  for (const value of ['user [at] example [dot] com', 'PERSON[AT]EXAMPLE[DOT]ORG']) {
    const address = redactText(value);
    assert.deepEqual(address.hits.map((hit) => hit.patternName), ['email']);
    assert.equal(address.redacted.includes(value), false);
  }

  const prose = redactText('Look at the example dot com instructions.');
  assert.equal(prose.hits.some((hit) => hit.patternName === 'email'), false);
  assert.equal(prose.redacted, prose.original);
  assert.equal(redactText('user [at] example [dot] com9').hits.some((hit) => hit.patternName === 'email'), false);
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
  const r = redactText('Card 4532-1234-5678-9014 expired');
  assert.ok(r.hits.some((h) => h.patternName === 'credit-card'));
  assert.match(r.redacted, /\[CC_1\]/);
});

test('redactText: card-shaped ticket failing checksum is not hard-blocked', () => {
  const r = redactText('Ticket 1234-5678-9012-3456');
  assert.equal(r.hits.some((h) => h.patternName === 'credit-card'), false);
  assert.equal(r.redacted, r.original);
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
