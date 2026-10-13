# Why This Exists

This repository explores a decision that applications need before sending prompts to an LLM provider: allow the text, replace detected sensitive spans, or block it. The TypeScript library contains pattern detectors, sample policy overrides, hard-block rules, and reversible token mapping.

The HTTP service is a **local prototype**. Its default demo returns decisions without authentication, provider forwarding, or persisted audit records. A separately opted-in loopback private-pilot mode checks signed caller identity and an explicit client-to-tenant grant, but still returns advice only and has not been validated against a real issuer. The demo audit endpoints read a bundled synthetic fixture. The separate browser demo and console image are illustrations, not evidence of production traffic.

The next engineering step would be a deployed tenant-bound enforcing proxy with provider adapters, response handling, durable redacted audit evidence, abuse controls, and independent false-negative evaluation. Until those exist, use this repository for design review and synthetic tests only.

The local API also checks the loopback peer and Host headers, rejects proxy forwarding headers, and sends no-store responses. These are local exposure controls; only the private-pilot route checks signed callers. The [synthetic detection evaluation](DETECTION_EVAL.md) records known misses and a false positive; it does not validate production detection accuracy.
