# Project Review and Change Record

This file records review findings, corrections, and verification results for the project.

## Baseline Review

Date: 2026-07-16

- Confirmed that all 56 original tests pass.
- Confirmed that 35 unique rules load across six categories.
- Confirmed that the supplied exfiltration sample triggers the five detections described in the README.
- Found no subprocess execution, unsafe YAML loading, dynamic code execution, or embedded live credentials.
- Reproduced a functional failure with namespaced Windows Event XML. The parser returned an empty list without an error.
- Confirmed that the existing project handoff listed Windows Event Log namespace support as unfinished.
- Found that command-line credentials detected by the tool were reproduced in full in JSON output.
- Found no runtime validation for malformed rule files, unsupported match fields, or duplicate IDs.
- Found no dependency manifest or license file despite related README claims.

## Pass 1: Parser and Rule-Loader Hardening

Status: Complete

Changes:

- Replaced whole-document XML parsing with streaming `iterparse` processing.
- Added namespace-independent element matching for Windows Event XML.
- Added rejection of DTD and entity declarations before XML parsing.
- Added output redaction for common AI API keys and bearer tokens.
- Added detection-rule schema validation.
- Added runtime duplicate rule-ID detection.
- Added a 1 MiB limit for individual YAML rule files.
- Added `.venv/` to `.gitignore` for isolated development environments.

Verification:

- Expanded the suite from 56 to 64 tests.
- Confirmed that all 64 tests pass on Python 3.12.
- Confirmed that a namespaced Windows Event XML fixture produces the expected Event ID 1 record.
- Confirmed that DTD and entity declarations raise a parsing error.
- Confirmed that the supplied exfiltration sample still triggers five detections.
- Confirmed that the sample credential is absent from CLI JSON output and replaced with `[REDACTED]`.
- Confirmed that both Python source files compile successfully.
- Confirmed that `git diff --check` reports no whitespace errors.

## Pass 2: Detection Content and ATT&CK Review

Status: Complete

Review goals:

- Separate observed AI activity from evidence of malicious or unauthorized activity.
- Check rule names, descriptions, categories, and severity levels against what Event ID 1 can prove.
- Validate ATT&CK technique mappings and remove mappings that cannot be supported by the available telemetry.
- Identify broad substrings that create predictable false positives.
- Add benign and adversarial test cases for corrected behavior.

Changes:

- Removed ATT&CK mappings from rules whose Event ID 1 evidence does not establish the mapped adversary behavior.
- Renamed the `exfiltration` category to `suspicious_context`. The rules identify activity worth investigating but do not prove data theft.
- Rewrote suspicious-context rule names and descriptions as observable facts.
- Reduced severity for ordinary AI API, autonomous-agent, code-assistant, and GPU-tool activity.
- Retained critical severity for an AI service credential exposed in process arguments.
- Added exact executable-basename matching with Windows path handling.
- Migrated named desktop, inference, GPU, and command-line applications away from broad image substring matching.
- Removed broad patterns including `model`, `predict`, `textgen`, and bare `aider` where they created foreseeable false positives.
- Stopped treating an API-key environment-variable name, without a credential value, as credential exposure.
- Omitted empty ATT&CK objects from detection output.

Verification:

- Expanded the suite from 64 to 69 tests.
- Added negative cases for `claudette.exe`, `chatgpt-notes.exe`, `raider.exe`, and an unset API-key variable.
- Confirmed that all 69 tests pass.
- Confirmed that the exfiltration-themed sample still produces five contextual detections.
- Confirmed that severities now resolve to one critical, two high, and two medium findings.
- Confirmed that no unsupported ATT&CK metadata appears in the sample output.
- Confirmed that credential redaction remains active.
- Corrected overlapping redaction patterns after the macOS sample check produced two adjacent placeholders for one bearer token.
- Strengthened the bearer-token regression test to require exactly one `[REDACTED]` placeholder.

## Pass 3: Packaging, Naming, and Public Documentation

Status: Complete

Planned work:

- Add reproducible runtime and development dependency metadata.
- Add the license file promised by the repository.
- Select a project name that describes Windows AI activity detection without claiming prevention or authorization knowledge.
- Replace the generated README with factual installation, use, rule, limitation, and validation guidance.
- Reconcile or remove stale internal handoff files before publication.

Changes:

- Renamed the public project identity to lowercase `aismon`.
- Confirmed that the name has no obvious conflicting GitHub repository in the same tool space.
- Replaced the generated README with factual documentation of scope, setup, use, rules, security behavior, testing, and limitations.
- Documented the WiCyS and Just Hacking Training project origin and the use of Claude Code for the initial prototype.
- Added `requirements.txt` for runtime dependencies.
- Added `requirements-dev.txt` for test dependencies.
- Added the MIT license promised by the original README.
- Removed stale `CLAUDE.md`, `HANDOFF.md`, and `STATE.md` files from the public project.
- Moved this review record to `docs/PROJECT_REVIEW.md`.
- Updated the command help text with the `aismon` name.
- Removed the remaining unused ATT&CK-output path from the detection engine.

Verification:

- Installed runtime and test dependencies into a clean target directory using the new requirements files.
- Confirmed that all 69 tests pass with the clean dependency set.
- Confirmed that both Python source files compile successfully.
- Confirmed that CLI help identifies the project as `aismon`.
- Confirmed that the primary sample still produces five detections with the documented output fields.
- Confirmed that credential redaction remains active.
- Confirmed that `git diff --check` reports no whitespace errors.
- Scanned public text for the former repository name, em dashes, stock contrast phrasing, and the generated README's rhetorical patterns. No matches remain.
- Added a least-privilege GitHub Actions workflow with read-only repository permissions.
- Pinned third-party actions to full commit hashes instead of mutable version tags.
- Added CI coverage for Python 3.10, 3.12, and 3.14.
- Raised the documented minimum to Python 3.10 because Python 3.8 and 3.9 are end-of-life.
- Pending repository rename and link verification after publication.
