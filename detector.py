"""Detection engine for AI/LLM threat indicators in Sysmon events."""

import os
import ntpath
import re
import yaml

DETECTIONS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "detections")
MAX_RULE_FILE_BYTES = 1024 * 1024
REQUIRED_RULE_FIELDS = {"id", "name", "description", "severity", "category", "match"}
VALID_SEVERITIES = {"low", "medium", "high", "critical"}
SUPPORTED_MATCH_FIELDS = {
    "image_contains",
    "image_name",
    "commandline_contains",
    "commandline_words",
    "parent_image_contains",
    "integrity_level",
}


class RuleValidationError(ValueError):
    """Raised when a detection rule file does not match the supported schema."""


def _validate_rule(rule, filename, index):
    location = f"{filename}: rule {index}"
    if not isinstance(rule, dict):
        raise RuleValidationError(f"{location} must be a mapping")

    missing = REQUIRED_RULE_FIELDS - rule.keys()
    if missing:
        raise RuleValidationError(f"{location} missing fields: {', '.join(sorted(missing))}")

    for field in ("id", "name", "description", "category"):
        if not isinstance(rule[field], str) or not rule[field].strip():
            raise RuleValidationError(f"{location} field '{field}' must be a non-empty string")

    if rule["severity"] not in VALID_SEVERITIES:
        raise RuleValidationError(f"{location} has invalid severity '{rule['severity']}'")

    match = rule["match"]
    if not isinstance(match, dict) or not match:
        raise RuleValidationError(f"{location} field 'match' must be a non-empty mapping")

    unsupported = set(match) - SUPPORTED_MATCH_FIELDS
    if unsupported:
        raise RuleValidationError(
            f"{location} has unsupported match fields: {', '.join(sorted(unsupported))}"
        )

    for field, patterns in match.items():
        if not isinstance(patterns, list) or not patterns:
            raise RuleValidationError(f"{location} match field '{field}' must be a non-empty list")
        if not all(isinstance(pattern, str) and pattern for pattern in patterns):
            raise RuleValidationError(f"{location} match field '{field}' contains an invalid value")


def load_rules(rules_dir=None):
    """Load all YAML detection rule files from the detections directory."""
    rules_dir = rules_dir or DETECTIONS_DIR
    rules = []
    for filename in sorted(os.listdir(rules_dir)):
        if not filename.endswith((".yml", ".yaml")):
            continue
        filepath = os.path.join(rules_dir, filename)
        if os.path.getsize(filepath) > MAX_RULE_FILE_BYTES:
            raise RuleValidationError(f"{filename} exceeds the 1 MiB rule-file limit")
        with open(filepath, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
            raise RuleValidationError(f"{filename} must contain a 'rules' list")
        for index, rule in enumerate(data["rules"], start=1):
            _validate_rule(rule, filename, index)
            rule = dict(rule)
            rule["source_file"] = filename
            rules.append(rule)

    ids = [rule["id"] for rule in rules]
    duplicate_ids = sorted({rule_id for rule_id in ids if ids.count(rule_id) > 1})
    if duplicate_ids:
        raise RuleValidationError(f"Duplicate rule IDs: {', '.join(duplicate_ids)}")
    return rules


def _matches_any(value, patterns):
    """Check if value contains any of the patterns (case-insensitive)."""
    if not value:
        return False
    value_lower = value.lower()
    return any(p.lower() in value_lower for p in patterns)


def _matches_image_name(value, patterns):
    """Compare a Windows process image basename against exact names."""
    if not value:
        return False
    image_name = ntpath.basename(value).lower()
    return any(image_name == pattern.lower() for pattern in patterns)


def _matches_words(value, patterns):
    """Match command-line terms without matching inside longer names."""
    if not value:
        return False
    return any(
        re.search(
            rf"(?<![A-Za-z0-9_.-]){re.escape(pattern)}(?![A-Za-z0-9_.-])",
            value,
            re.IGNORECASE,
        )
        for pattern in patterns
    )


def _check_rule(event, rule):
    """Check if a single event matches a rule's conditions. Returns True if all conditions match."""
    match = rule.get("match", {})
    if not match:
        return False

    conditions_met = []

    # image_contains: substring match against Image field
    if "image_contains" in match:
        conditions_met.append(_matches_any(event.get("Image"), match["image_contains"]))

    # image_name: exact, case-insensitive match against the executable basename
    if "image_name" in match:
        conditions_met.append(_matches_image_name(event.get("Image"), match["image_name"]))

    # commandline_contains: substring match against CommandLine field
    if "commandline_contains" in match:
        conditions_met.append(_matches_any(event.get("CommandLine"), match["commandline_contains"]))

    # commandline_words: match complete command terms, not substrings of longer names
    if "commandline_words" in match:
        conditions_met.append(_matches_words(event.get("CommandLine"), match["commandline_words"]))

    # parent_image_contains: substring match against ParentImage field
    if "parent_image_contains" in match:
        conditions_met.append(_matches_any(event.get("ParentImage"), match["parent_image_contains"]))

    # integrity_level: exact match against IntegrityLevel
    if "integrity_level" in match:
        event_level = event.get("IntegrityLevel", "")
        conditions_met.append(event_level in match["integrity_level"])

    # All conditions must be satisfied (AND logic)
    return len(conditions_met) > 0 and all(conditions_met)


def detect(events, rules=None):
    """Run detection rules against parsed Sysmon events.

    Returns a new list of event dicts. Events that trigger rules get a
    'detections' key added with a list of matched rule details.
    """
    if rules is None:
        rules = load_rules()

    results = []
    for event in events:
        matched = []
        for rule in rules:
            if _check_rule(event, rule):
                detection = {
                    "rule_id": rule["id"],
                    "name": rule["name"],
                    "description": rule["description"],
                    "severity": rule["severity"],
                    "category": rule["category"],
                    "tags": rule.get("tags", []),
                }
                matched.append(detection)

        event_copy = dict(event)
        if matched:
            event_copy["detections"] = matched
        results.append(event_copy)

    return results


def detect_summary(events, rules=None):
    """Run detection and return only events that have detections."""
    results = detect(events, rules)
    return [e for e in results if "detections" in e]
