# Why This Exists

This repository explores a decision that applications need before sending prompts to an LLM provider: allow the text, replace detected sensitive spans, or block it. The TypeScript library contains pattern detectors, sample policy overrides, hard-block rules, and reversible token mapping.

The HTTP service is a **local prototype**. It returns decisions but does not forward requests, authenticate callers or tenants, or persist audit records. Its audit endpoints read a bundled synthetic fixture. The separate browser demo and console image are illustrations, not evidence of production traffic.

The next engineering step would be an authenticated, tenant-bound enforcing proxy with provider adapters, response handling, durable redacted audit evidence, abuse controls, and independent false-negative evaluation. Until those exist, use this repository for design review and synthetic tests only.
