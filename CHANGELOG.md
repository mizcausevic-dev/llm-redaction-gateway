# Changelog

All notable changes to this project are documented here.

## [1.0.0] - 2026-05-12

### Released
- Released **llm-redaction-gateway** publicly as a reviewable operating system for identity governance.
- Packaged the current implementation, documentation, validation flow, and proof surfaces into a repo that can be reviewed by technical and operating stakeholders.
- Clarified the core problem the project is addressing: identity sprawl, tenant-boundary mistakes, and access-review workflows that are technically complete but poorly explained.

### Why this mattered
- Existing approaches in IGA suites, ticket approvals, and access review campaigns were useful for parts of the workflow.
- They still left out a fast, legible control layer for access reasoning at the moment decisions are made.
- This release made the repo read like an operational capability rather than a narrow technical demo.

## [0.1.0] - 2026-02-16

### Shipped
- Cut the first coherent internal version of **llm-redaction-gateway** with stable domain objects, review surfaces, and decision outputs.
- Established the first reviewable version of the architecture described as: PII and secret redaction gateway for LLM API calls. 25+ detection patterns across 6 categories, reversible token-mapped redaction, layered tenant policy with hardpinned safety rails, full audit trail.
- Focused the repo around actionability instead of passive reporting.

## [Prototype] - 2025-04-16

### Built
- Built the first runnable prototype for the repo's main workflow and decision model.
- Validated the concept against pressure points such as identity sprawl, least-privilege drift, tenant-boundary mistakes, and approval latency.
- Used the prototype phase to test whether the project could drive action, not just present information.

## [Design Phase] - 2024-12-16

### Designed
- Defined the system around operator-first and decision-legible outputs.
- Chose interfaces and examples that made sense for IAM, platform security, compliance, and internal platform teams.
- Avoided reducing the project to a generic dashboard, CRUD app, or fashionable wrapper around the stack.

## [Idea Origin] - 2024-02-16

### Observed
- The original idea surfaced while looking at how teams were handling identity sprawl, tenant-boundary mistakes, and access-review workflows that are technically complete but poorly explained.
- The recurring pattern was that teams had data and tools, but still lacked a usable operating layer for the hardest decisions.

## [Background Signals] - 2022-08-09

### Context
- Earlier platform, governance, and operator-tooling work made one pattern hard to ignore: the systems that create the most drag are often the ones with partial controls and weak operational coherence, not the ones with no controls at all.
- That pattern shaped the thinking behind this repo well before the public version existed.