# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Python tool that parses Sysmon XML logs, extracts key fields from Event ID 1 (Process Creation) events, and runs AI/LLM threat detection rules against them. Output is JSON.

## Dependencies

- Python 3.8+
- PyYAML (`pip install pyyaml`)
- pytest (dev only)

## Target Fields (Event ID 1)

EventID, UtcTime, Image (process path), CommandLine, User, IntegrityLevel, ParentImage, ParentCommandLine, Computer, Hashes

## Build & Run

```bash
python parser.py <input.xml>                          # parse and output JSON
python parser.py <input.xml> --detect                  # parse + run AI threat detection
python parser.py <input.xml> --detect-only             # only output events that trigger rules
python parser.py <input.xml> --image whoami            # filter by process name (substring)
python parser.py <input.xml> --user "DOMAIN\user"      # filter by user (exact match)
python parser.py <input.xml> --integrity-level High    # filter by integrity level
python -m pytest tests/                                # run all tests
python -m pytest tests/test_parser.py -k "test_name"   # run a single test
```

## Architecture

- `parser.py` — CLI entry point; parses XML, filters events, optionally runs detection, outputs JSON
- `detector.py` — detection engine; loads YAML rules, matches events, returns severity-tagged alerts with MITRE ATT&CK mappings
- `detections/` — YAML rule files organized by category:
  - `local_inference_tools.yml` — Ollama, llama.cpp, KoboldCpp, vLLM, LM Studio, GPT4All, etc.
  - `model_download.yml` — HuggingFace, GGUF/SafeTensors file refs, Ollama pulls, CivitAI
  - `gpu_compute_abuse.yml` — PyTorch/TensorFlow, CUDA tools, nvidia-smi
  - `ai_attack_tooling.yml` — AutoGPT, PentestGPT, AI API keys in CLI, vendor API calls
  - `exfiltration_ai.yml` — AI tools from script engines, temp dirs, SYSTEM context, curl to AI APIs
  - `shadow_ai.yml` — ChatGPT/Claude desktop, Copilot CLI, Stable Diffusion, Whisper
- `samples/` — sample Sysmon XML files for testing (benign and malicious)
- `tests/` — pytest test suite (`test_parser.py` for parsing/filtering, `test_detector.py` for detection)

## Detection Rule Format

Each YAML rule file contains a `rules` list. Each rule has: `id`, `name`, `description`, `severity` (low/medium/high/critical), `category`, `mitre` (tactic/technique), and `match` conditions. Match conditions use AND logic and support: `image_contains`, `commandline_contains`, `parent_image_contains`, `integrity_level`.
