import os
import pytest
from detector import load_rules, detect, detect_summary, _check_rule, RuleValidationError

DETECTIONS_DIR = os.path.join(os.path.dirname(__file__), "..", "detections")


# --- Rule loading tests ---


class TestLoadRules:
    def test_loads_all_rule_files(self):
        rules = load_rules()
        assert len(rules) >= 35

    def test_every_rule_has_required_fields(self):
        rules = load_rules()
        for rule in rules:
            assert "id" in rule, f"Rule missing id: {rule}"
            assert "name" in rule, f"Rule {rule['id']} missing name"
            assert "severity" in rule, f"Rule {rule['id']} missing severity"
            assert "category" in rule, f"Rule {rule['id']} missing category"
            assert "match" in rule, f"Rule {rule['id']} missing match"

    def test_rule_ids_are_unique(self):
        rules = load_rules()
        ids = [r["id"] for r in rules]
        assert len(ids) == len(set(ids)), f"Duplicate rule IDs: {[x for x in ids if ids.count(x) > 1]}"

    def test_severity_values_valid(self):
        rules = load_rules()
        valid = {"low", "medium", "high", "critical"}
        for rule in rules:
            assert rule["severity"] in valid, f"Rule {rule['id']} has invalid severity: {rule['severity']}"

    def test_detection_output_has_documented_fields(self):
        event = {"EventID": 1, "Image": "ollama.exe", "CommandLine": "ollama run llama3"}
        detection = detect([event])[0]["detections"][0]
        assert set(detection) == {
            "rule_id",
            "name",
            "description",
            "severity",
            "category",
            "tags",
        }

    def test_loads_from_custom_dir(self, tmp_path):
        rule_file = tmp_path / "test.yml"
        rule_file.write_text("""
rules:
  - id: TEST-001
    name: Test Rule
    description: A test
    severity: low
    category: test
    match:
      image_contains:
        - test.exe
""")
        rules = load_rules(str(tmp_path))
        assert len(rules) == 1
        assert rules[0]["id"] == "TEST-001"

    def test_rejects_unsupported_match_field(self, tmp_path):
        (tmp_path / "bad.yml").write_text("""
rules:
  - id: TEST-001
    name: Bad field
    description: A malformed rule
    severity: low
    category: test
    match:
      imaginary_field:
        - value
""")
        with pytest.raises(RuleValidationError, match="unsupported match fields"):
            load_rules(str(tmp_path))

    def test_rejects_non_list_match_patterns(self, tmp_path):
        (tmp_path / "bad.yml").write_text("""
rules:
  - id: TEST-001
    name: Bad patterns
    description: A malformed rule
    severity: low
    category: test
    match:
      image_contains: ollama
""")
        with pytest.raises(RuleValidationError, match="must be a non-empty list"):
            load_rules(str(tmp_path))

    def test_rejects_duplicate_ids_at_runtime(self, tmp_path):
        rule = """
  - id: TEST-001
    name: Duplicate
    description: A duplicate rule
    severity: low
    category: test
    match:
      image_contains:
        - ollama
"""
        (tmp_path / "one.yml").write_text("rules:\n" + rule)
        (tmp_path / "two.yml").write_text("rules:\n" + rule)
        with pytest.raises(RuleValidationError, match="Duplicate rule IDs"):
            load_rules(str(tmp_path))


# --- Detection matching tests ---


class TestDetectionMatching:
    def _make_event(self, **kwargs):
        base = {"EventID": 1, "Computer": "HOST"}
        base.update(kwargs)
        return base

    # Local inference tools
    def test_detects_ollama(self):
        event = self._make_event(
            Image=r"C:\Users\user\AppData\Local\Programs\ollama\ollama.exe",
            CommandLine="ollama run llama2",
        )
        results = detect([event])
        rule_ids = [d["rule_id"] for d in results[0].get("detections", [])]
        assert "AI-001" in rule_ids
        assert "AI-011" not in rule_ids

    def test_detects_ollama_model_pull(self):
        event = self._make_event(
            Image=r"C:\\Users\\user\\AppData\\Local\\Programs\\ollama\\ollama.exe",
            CommandLine="ollama pull llama2",
        )
        results = detect([event])
        rule_ids = [d["rule_id"] for d in results[0].get("detections", [])]
        assert "AI-001" in rule_ids
        assert "AI-011" in rule_ids

    def test_detects_llama_cpp(self):
        event = self._make_event(
            Image=r"C:\tools\llama-server.exe",
            CommandLine="llama-server -m model.gguf",
        )
        results = detect([event])
        rule_ids = [d["rule_id"] for d in results[0].get("detections", [])]
        assert "AI-002" in rule_ids
        assert "AI-012" in rule_ids  # .gguf in commandline

    def test_detects_koboldcpp(self):
        event = self._make_event(Image=r"C:\tools\koboldcpp.exe", CommandLine="koboldcpp --model x")
        results = detect([event])
        rule_ids = [d["rule_id"] for d in results[0].get("detections", [])]
        assert "AI-003" in rule_ids

    def test_detects_vllm(self):
        event = self._make_event(
            Image="python.exe",
            CommandLine="python -m vllm.entrypoints.openai.api_server",
        )
        results = detect([event])
        rule_ids = [d["rule_id"] for d in results[0].get("detections", [])]
        assert "AI-005" in rule_ids

    def test_detects_lm_studio(self):
        event = self._make_event(Image=r"C:\Program Files\LM Studio\lmstudio.exe", CommandLine="lmstudio")
        results = detect([event])
        rule_ids = [d["rule_id"] for d in results[0].get("detections", [])]
        assert "AI-007" in rule_ids

    # Model download
    def test_detects_huggingface_download(self):
        event = self._make_event(
            Image="python.exe",
            CommandLine="python download.py --model huggingface.co/meta-llama/Llama-2-70b",
        )
        results = detect([event])
        rule_ids = [d["rule_id"] for d in results[0].get("detections", [])]
        assert "AI-010" in rule_ids

    def test_detects_safetensors(self):
        event = self._make_event(Image="python.exe", CommandLine="python load.py model.safetensors")
        results = detect([event])
        rule_ids = [d["rule_id"] for d in results[0].get("detections", [])]
        assert "AI-013" in rule_ids

    # GPU/compute
    def test_detects_nvidia_smi(self):
        event = self._make_event(
            Image=r"C:\Windows\System32\nvidia-smi.exe",
            CommandLine="nvidia-smi --query-gpu=memory.used",
        )
        results = detect([event])
        rule_ids = [d["rule_id"] for d in results[0].get("detections", [])]
        assert "AI-018" in rule_ids
        assert "AI-019" in rule_ids

    # AI attack tooling
    def test_detects_autogpt(self):
        event = self._make_event(
            Image="python.exe",
            CommandLine="python -m autogpt --continuous",
        )
        results = detect([event])
        rule_ids = [d["rule_id"] for d in results[0].get("detections", [])]
        assert "AI-021" in rule_ids

    def test_detects_api_key_exposure(self):
        event = self._make_event(
            Image="python.exe",
            CommandLine="python run.py OPENAI_API_KEY=sk-proj-abc123",
        )
        results = detect([event])
        rule_ids = [d["rule_id"] for d in results[0].get("detections", [])]
        assert "AI-023" in rule_ids

    def test_detects_ai_api_call(self):
        event = self._make_event(
            Image="python.exe",
            CommandLine="python chat.py --endpoint https://api.anthropic.com/v1/messages",
        )
        results = detect([event])
        rule_ids = [d["rule_id"] for d in results[0].get("detections", [])]
        assert "AI-025" in rule_ids

    # Exfiltration patterns
    def test_detects_curl_to_ai_api(self):
        event = self._make_event(
            Image=r"C:\Windows\System32\curl.exe",
            CommandLine="curl -X POST https://api.openai.com/v1/completions -d @data.json",
        )
        results = detect([event])
        rule_ids = [d["rule_id"] for d in results[0].get("detections", [])]
        assert "AI-029" in rule_ids

    def test_detects_ai_tool_from_wscript(self):
        event = self._make_event(
            Image="python.exe",
            CommandLine="python -c \"import openai; openai.ChatCompletion.create(...)\"",
            ParentImage=r"C:\Windows\System32\wscript.exe",
        )
        results = detect([event])
        rule_ids = [d["rule_id"] for d in results[0].get("detections", [])]
        assert "AI-026" in rule_ids

    def test_detects_system_integrity_ai(self):
        event = self._make_event(
            Image=r"C:\tools\ollama.exe",
            CommandLine="ollama run mistral",
            IntegrityLevel="System",
        )
        results = detect([event])
        rule_ids = [d["rule_id"] for d in results[0].get("detections", [])]
        assert "AI-028" in rule_ids

    def test_detects_python_langchain(self):
        event = self._make_event(
            Image=r"C:\Python311\python.exe",
            CommandLine="python agent.py langchain",
        )
        results = detect([event])
        rule_ids = [d["rule_id"] for d in results[0].get("detections", [])]
        assert "AI-030" in rule_ids

    # Shadow AI
    def test_detects_stable_diffusion(self):
        event = self._make_event(
            Image="python.exe",
            CommandLine="python launch.py --listen stable-diffusion",
        )
        results = detect([event])
        rule_ids = [d["rule_id"] for d in results[0].get("detections", [])]
        assert "AI-034" in rule_ids

    def test_detects_whisper(self):
        event = self._make_event(
            Image="python.exe",
            CommandLine="python -m whisper audio.wav --model large",
        )
        results = detect([event])
        rule_ids = [d["rule_id"] for d in results[0].get("detections", [])]
        assert "AI-035" in rule_ids


# --- No false positives ---


class TestNoFalsePositives:
    def _make_event(self, **kwargs):
        base = {"EventID": 1, "Computer": "HOST"}
        base.update(kwargs)
        return base

    def test_normal_cmd(self):
        event = self._make_event(
            Image=r"C:\Windows\System32\cmd.exe",
            CommandLine="cmd.exe /c dir",
            User=r"HOST\user",
            IntegrityLevel="Medium",
        )
        results = detect([event])
        assert "detections" not in results[0]

    def test_normal_powershell(self):
        event = self._make_event(
            Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            CommandLine="powershell.exe Get-Process",
            User=r"HOST\user",
            IntegrityLevel="Medium",
        )
        results = detect([event])
        assert "detections" not in results[0]

    def test_normal_python(self):
        event = self._make_event(
            Image=r"C:\Python311\python.exe",
            CommandLine="python manage.py runserver",
        )
        results = detect([event])
        assert "detections" not in results[0]

    def test_normal_curl(self):
        event = self._make_event(
            Image=r"C:\Windows\System32\curl.exe",
            CommandLine="curl https://example.com/api/status",
        )
        results = detect([event])
        assert "detections" not in results[0]

    def test_normal_notepad(self):
        event = self._make_event(
            Image=r"C:\Windows\System32\notepad.exe",
            CommandLine="notepad.exe readme.txt",
        )
        results = detect([event])
        assert "detections" not in results[0]

    def test_similar_claude_process_name(self):
        event = self._make_event(
            Image=r"C:\Tools\claudette.exe",
            CommandLine="claudette.exe --serve",
        )
        results = detect([event])
        assert "detections" not in results[0]

    def test_chatgpt_text_in_unrelated_process_path(self):
        event = self._make_event(
            Image=r"C:\Tools\chatgpt-notes.exe",
            CommandLine="chatgpt-notes.exe",
        )
        results = detect([event])
        assert "detections" not in results[0]

    def test_api_key_variable_name_without_value(self):
        event = self._make_event(
            Image=r"C:\Windows\System32\cmd.exe",
            CommandLine="echo OPENAI_API_KEY is not configured",
        )
        results = detect([event])
        assert "detections" not in results[0]

    def test_unrelated_aider_substring(self):
        event = self._make_event(
            Image=r"C:\Games\raider.exe",
            CommandLine="raider.exe --launch",
        )
        results = detect([event])
        assert "detections" not in results[0]


# --- detect_summary tests ---


class TestDetectSummary:
    def test_returns_only_flagged_events(self):
        events = [
            {"EventID": 1, "Computer": "HOST", "Image": "notepad.exe", "CommandLine": "notepad"},
            {"EventID": 1, "Computer": "HOST", "Image": "ollama.exe", "CommandLine": "ollama run llama2"},
        ]
        flagged = detect_summary(events)
        assert len(flagged) == 1
        assert "ollama" in flagged[0]["Image"]
        assert "detections" in flagged[0]

    def test_empty_when_no_detections(self):
        events = [
            {"EventID": 1, "Computer": "HOST", "Image": "notepad.exe", "CommandLine": "notepad"},
        ]
        assert detect_summary(events) == []


# --- Integration with sample files ---


class TestSampleFileDetections:
    def test_event1_no_detections(self):
        from parser import parse_events
        events = parse_events(os.path.join(DETECTIONS_DIR, "..", "samples", "event1.xml"))
        results = detect(events)
        assert "detections" not in results[0]

    def test_event2_no_detections(self):
        from parser import parse_events
        events = parse_events(os.path.join(DETECTIONS_DIR, "..", "samples", "event2.xml"))
        results = detect(events)
        assert "detections" not in results[0]

    def test_event3_no_ai_detections(self):
        """event3 is suspicious (encoded PS) but not AI-related."""
        from parser import parse_events
        events = parse_events(os.path.join(DETECTIONS_DIR, "..", "samples", "event3.xml"))
        results = detect(events)
        assert "detections" not in results[0]

    def test_event_ollama_detected(self):
        from parser import parse_events
        events = parse_events(os.path.join(DETECTIONS_DIR, "..", "samples", "event_ollama.xml"))
        results = detect(events)
        assert "detections" in results[0]
        rule_ids = [d["rule_id"] for d in results[0]["detections"]]
        assert "AI-001" in rule_ids
        assert "AI-011" not in rule_ids

    def test_event_exfil_ai_multi_detections(self):
        from parser import parse_events
        events = parse_events(os.path.join(DETECTIONS_DIR, "..", "samples", "event_exfil_ai.xml"))
        results = detect(events)
        detections = results[0]["detections"]
        assert len(detections) >= 3
        severities = {d["severity"] for d in detections}
        assert "critical" in severities

    def test_event_autogpt_detected(self):
        from parser import parse_events
        events = parse_events(os.path.join(DETECTIONS_DIR, "..", "samples", "event_autogpt.xml"))
        results = detect(events)
        detections = results[0]["detections"]
        rule_ids = [d["rule_id"] for d in detections]
        assert "AI-021" in rule_ids  # AutoGPT
        assert "AI-023" in rule_ids  # API key exposure
