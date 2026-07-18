# aismon

`aismon` examines Windows Sysmon process-creation events for AI-related activity.

It reads Sysmon Event ID 1 XML exports, extracts the process details that matter during triage, and compares each event with a set of YAML detection rules. Matches can identify local model runners, AI desktop applications, model downloads, AI API references, exposed API credentials, and AI activity running in a suspicious context.

The tool reports observable activity. A match does not determine whether the activity was authorized or malicious. That decision belongs to the analyst and the organization's AI usage policy.

## Project origin

This project began as a Sysmon parser assignment in Just Hacking Training’s (JHT) AI Cyber Defense Ops course, offered through the Women in CyberSecurity (WiCyS) Cyber Competency Builder program in partnership with JHT.

The initial prototype was built iteratively with Claude Code. I expanded the assignment into an AI activity detector, then reviewed the code, corrected its handling of real Windows Event XML, hardened its inputs, recalibrated the detection logic, and added tests for security and false-positive cases.

The review history is documented in [`docs/PROJECT_REVIEW.md`](docs/PROJECT_REVIEW.md).
A reproducible Windows-to-Splunk demonstration is documented in [`docs/HOME_LAB_DEMO.md`](docs/HOME_LAB_DEMO.md).

## What it detects

The repository contains 35 rules across seven output categories.

| Category | Examples |
|---|---|
| Local inference | Ollama, llama.cpp, vLLM, KoboldCpp, LM Studio, GPT4All |
| Model acquisition | Hugging Face references, Ollama pulls, GGUF, SafeTensors, CivitAI |
| GPU and compute activity | PyTorch, TensorFlow, CUDA, `nvidia-smi` |
| AI tooling | PentestGPT, AutoGPT, CrewAI, AI service credentials in command lines |
| AI API activity | Known AI vendor API references |
| Suspicious context | Script-host parent processes, SYSTEM integrity, user-writable directories, command-line AI API access |
| Shadow AI indicators | ChatGPT, Claude Desktop, Copilot CLI, Stable Diffusion, Whisper |

Each match includes a rule ID, description, severity, category, and tags. Severity represents investigation priority. Analysts still determine what the activity means in their environment.

## Requirements

- Python 3.10 or newer
- PyYAML 6.x

## Installation

Clone the repository and create a virtual environment:

```bash
git clone https://github.com/jennshaggy/aismon.git
cd aismon
python -m venv .venv
```

Activate the environment on macOS or Linux:

```bash
source .venv/bin/activate
```

Activate it on Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

Install the runtime dependency:

```bash
python -m pip install -r requirements.txt
```

## Usage

Parse Event ID 1 records and return JSON:

```bash
python parser.py samples/event1.xml
```

Run the detection rules:

```bash
python parser.py samples/event_ollama.xml --detect
```

Return only events with detections:

```bash
python parser.py samples/event_exfil_ai.xml --detect-only
```

Filter parsed events:

```bash
python parser.py events.xml --image powershell
python parser.py events.xml --user "DOMAIN\username"
python parser.py events.xml --integrity-level System
```

Filters can be combined. The image filter is case-insensitive and accepts a partial path or process name. User and integrity-level filters require exact values.

## Example detection

The supplied `event_exfil_ai.xml` fixture describes `curl.exe` accessing an AI API from SYSTEM context after being launched by `wscript.exe`. Its command line also contains a sample API key.

```json
{
  "rule_id": "AI-023",
  "name": "AI API Key in Command Line",
  "description": "AI service credential appears in process command-line arguments",
  "severity": "critical",
  "category": "ai_tooling",
  "tags": [
    "credential-exposure",
    "api-key"
  ]
}
```

The credential is available to the detection engine but is replaced with `[REDACTED]` before JSON is printed.

## Input format

`aismon` accepts XML containing one or more Windows Event records. It supports the namespace used by Windows Event Viewer XML exports.

The parser extracts these Event ID 1 fields when present:

- `EventID`
- `Computer`
- `UtcTime`
- `Image`
- `CommandLine`
- `User`
- `IntegrityLevel`
- `ParentImage`
- `ParentCommandLine`
- `Hashes`

The current version does not read binary `.evtx` files and does not collect live events from an endpoint.

## Detection rules

Rules are stored in `detections/` as YAML. Multiple match fields use AND logic. Values inside one match field use OR logic.

Supported match fields:

- `image_name`: exact executable basename, case-insensitive
- `image_contains`: partial process-path match, case-insensitive
- `commandline_contains`: partial command-line match, case-insensitive
- `commandline_words`: boundary-aware command term match, case-insensitive
- `parent_image_contains`: partial parent-process path match, case-insensitive
- `integrity_level`: exact integrity-level match

Rule files are schema-checked when loaded. Unsupported match fields, invalid values, duplicate rule IDs, and individual rule files larger than 1 MiB are rejected.

## Security behavior

- XML DTD and entity declarations are rejected.
- XML is processed incrementally instead of loading the complete document into memory.
- Common AI API keys and bearer tokens are redacted from command-line fields before output.
- Detection runs before redaction so credential-exposure rules still work.
- YAML is parsed with `safe_load` and validated before use.

## Tests

Install the development dependencies and run the complete suite:

```bash
python -m pip install -r requirements-dev.txt
python -m pytest
```

The current suite contains 70 tests covering XML parsing, Windows namespaces, filtering, credential redaction, rule validation, matching behavior, false-positive cases, and sample-file integration.

GitHub Actions runs the suite on Python 3.10, 3.12, and 3.14 for every pull request and every push to `main`.

## Current limitations

- Event ID 1 provides process context, not network payloads or proof of data transfer.
- Rules identify activity for review. They do not know an organization's approved software or users.
- Detection is based on process paths and command-line text. Renamed tools or missing command-line logging can evade matching.
- The included benign cases are targeted regression tests, not a measured enterprise false-positive rate.
- Output is JSON. CSV, JSONL, live collection, `.evtx` parsing, and SIEM integration are not implemented.

## License

MIT License. See [`LICENSE`](LICENSE).
