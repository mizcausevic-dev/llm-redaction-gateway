# Synthetic detection evaluation

Run `npm run eval:detection` from the repository root. The script emits JSON with case IDs, expected pattern and decision, observed pattern names and decision, and mismatch counts. It never prints the probe text. Every probe is synthetic and stored in `scripts/evaluate-detection.ts` for review.

The supported group is a regression gate for formats this prototype says it handles. The script exits nonzero if any supported case fails. The challenge group deliberately measures gaps and does not turn a passing regression run into a release approval.

| Group | Cases | Observed on 2026-10-01 candidate | Meaning |
| --- | ---: | --- | --- |
| Supported fixtures | 14 | 14 matched expectations | The listed examples work locally. |
| Challenge fixtures | 4 | 1 matched expectation | Three false negatives remain. |

The false negatives are an obfuscated email, an unseparated nine-digit SSN, and a space-separated US phone. A card-shaped ticket number failing the Luhn checksum is no longer hard-blocked. Luhn only filters some false positives; a Luhn-valid reference number can still be misclassified. Broadening the other patterns without a labeled corpus can increase false positives, so those remain visible limits.

This is a hand-curated corpus, not a sample of customer prompts. It cannot establish recall, precision, provider safety, or compliance. A production gate needs permissioned, representative, human-labeled data with provenance and retention rules; measured false-negative and false-positive costs; adversarial variants; authenticated tenant binding; an enforcing provider boundary; and a hosted deployment and rollback drill. The disposable local process-switch drill in the README does not satisfy those production gates.
