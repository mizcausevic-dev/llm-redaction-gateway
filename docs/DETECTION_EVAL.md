# Synthetic detection evaluation

Run `npm run eval:detection` from the repository root. The script emits JSON with case IDs, expected pattern and decision, observed pattern names and decision, and mismatch counts. It never prints the probe text. Every probe is synthetic and stored in `scripts/evaluate-detection.ts` for review.

The supported group is a regression gate for formats this prototype says it handles. The script exits nonzero if any supported case fails. The challenge group deliberately measures gaps and does not turn a passing regression run into a release approval.

| Group | Cases | Observed on 2026-09-30 candidate | Meaning |
| --- | ---: | --- | --- |
| Supported fixtures | 14 | 14 matched expectations | The listed examples work locally. |
| Challenge fixtures | 4 | 0 matched expectations | Three false negatives and one false positive remain. |

The false negatives are an obfuscated email, an unseparated nine-digit SSN, and a space-separated US phone. A card-shaped ticket number is falsely classified as a credit card and blocked. Broadening those patterns without a labeled corpus can increase false positives, so these are visible limits rather than silent changes.

This is a hand-curated corpus, not a sample of customer prompts. It cannot establish recall, precision, provider safety, or compliance. A production gate needs permissioned, representative, human-labeled data with provenance and retention rules; measured false-negative and false-positive costs; adversarial variants; authenticated tenant binding; an enforcing provider boundary; and a deployment and rollback drill. None is claimed here.
