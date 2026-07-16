# HANDOFF.md

## What We Built

A Python tool that parses Sysmon XML logs and detects unauthorized AI/LLM activity on endpoints. It extracts 10 key fields from Event ID 1 (Process Creation) events and runs them through a YAML-based detection engine with 35 rules across six threat categories.

### Components

- **parser.py**: CLI entry point. Reads Sysmon XML, extracts fields, supports filtering (by process image, user, integrity level), and optionally runs detection. Outputs JSON to stdout.
- **detector.py**: Rule engine. Loads YAML rule files, matches events against conditions using AND logic, and returns severity-tagged alerts with MITRE ATT&CK mappings.
- **detections/**: Six YAML rule files covering local inference tools (Ollama, llama.cpp, vLLM, LM Studio, GPT4All), model downloads (HuggingFace, GGUF, SafeTensors), GPU/compute abuse (PyTorch, CUDA, nvidia-smi), AI attack tooling (AutoGPT, PentestGPT, API key exposure), exfiltration patterns (script engine spawns, SYSTEM-context AI tools, curl to AI APIs), and shadow AI (ChatGPT/Claude desktop, Stable Diffusion, Whisper).
- **samples/**: Six Sysmon XML files. Three benign (whoami, cmd spawning PowerShell, encoded PowerShell) and three AI-specific (Ollama pulling llama2, curl exfiltrating data to OpenAI as SYSTEM, intern running AutoGPT with a leaked API key).
- **tests/**: 56 pytest tests covering parsing, filtering, rule loading, detection matching, false positive validation, and end-to-end integration.

## How to Use It

```bash
# Install dependency
pip install pyyaml

# Parse a Sysmon XML file
python parser.py samples/event1.xml

# Parse with filtering
python parser.py samples/event1.xml --image whoami
python parser.py samples/event1.xml --user "DESKTOP-ABC1234\analyst"
python parser.py samples/event1.xml --integrity-level Medium

# Parse with AI/LLM threat detection
python parser.py samples/event_ollama.xml --detect

# Only show events that triggered detection rules
python parser.py samples/event_exfil_ai.xml --detect-only

# Run tests
python -m pytest tests/ -v
```

Output is JSON. Single events produce a JSON object; multiple events produce a JSON array. When `--detect` is used, flagged events include a `detections` array with rule ID, name, severity, category, and MITRE ATT&CK mapping.

## Decisions Made

**YAML for detection rules, not hardcoded Python.** Users can add, modify, or disable rules without touching source code. Security teams can contribute signatures without knowing the internals of the parser.

**AND logic for multi-condition rules.** A rule with both `image_contains` and `commandline_contains` requires both conditions to match. This reduces false positives on rules like "curl to AI API" (needs both curl as the process AND an AI API URL in the command line).

**Case-insensitive matching for image and command line.** Process paths and command lines vary in casing across Windows environments. All substring matching is lowercased before comparison.

**User filter is exact match, image filter is substring.** Users are specific identities (DOMAIN\username) where partial matching would be misleading. Process images benefit from substring matching because the full path varies by installation.

**Separate `--detect` and `--detect-only` flags.** `--detect` annotates all events (useful for bulk processing where you want the full picture). `--detect-only` filters down to flagged events only (useful for alerting pipelines).

**No external dependencies beyond PyYAML.** The parser uses only stdlib (`xml.etree.ElementTree`, `argparse`, `json`). PyYAML is the single added dependency for rule loading. This keeps the tool easy to drop onto analyst workstations.

## What's Left to Do

- [ ] Write a README.md for the GitHub repo (project description, install steps, usage examples, sample output screenshots)
- [ ] Add support for multiple XML files as input (glob or directory scanning)
- [ ] Add CSV output format alongside JSON
- [ ] Add a `--rules-dir` flag to load custom detection rules from an alternate directory
- [ ] Add time-range filtering (`--after`, `--before` on UtcTime)
- [ ] Support Windows Event Log XML exports (slightly different schema with namespace prefixes)
- [ ] Add a summary/stats mode that counts detections by severity and category
- [ ] Add CI (GitHub Actions) to run tests on push
- [ ] Publish to PyPI as an installable CLI tool
- [ ] Set repo to public once reviewed
