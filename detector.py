"""Detection engine for AI/LLM threat indicators in Sysmon events."""

import os
import yaml

DETECTIONS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "detections")


def load_rules(rules_dir=None):
    """Load all YAML detection rule files from the detections directory."""
    rules_dir = rules_dir or DETECTIONS_DIR
    rules = []
    for filename in sorted(os.listdir(rules_dir)):
        if not filename.endswith((".yml", ".yaml")):
            continue
        filepath = os.path.join(rules_dir, filename)
        with open(filepath) as f:
            data = yaml.safe_load(f)
        if data and "rules" in data:
            for rule in data["rules"]:
                rule["source_file"] = filename
                rules.append(rule)
    return rules


def _matches_any(value, patterns):
    """Check if value contains any of the patterns (case-insensitive)."""
    if not value:
        return False
    value_lower = value.lower()
    return any(p.lower() in value_lower for p in patterns)


def _check_rule(event, rule):
    """Check if a single event matches a rule's conditions. Returns True if all conditions match."""
    match = rule.get("match", {})
    if not match:
        return False

    conditions_met = []

    # image_contains: substring match against Image field
    if "image_contains" in match:
        conditions_met.append(_matches_any(event.get("Image"), match["image_contains"]))

    # commandline_contains: substring match against CommandLine field
    if "commandline_contains" in match:
        conditions_met.append(_matches_any(event.get("CommandLine"), match["commandline_contains"]))

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
                matched.append({
                    "rule_id": rule["id"],
                    "name": rule["name"],
                    "description": rule["description"],
                    "severity": rule["severity"],
                    "category": rule["category"],
                    "mitre": rule.get("mitre", {}),
                    "tags": rule.get("tags", []),
                })

        event_copy = dict(event)
        if matched:
            event_copy["detections"] = matched
        results.append(event_copy)

    return results


def detect_summary(events, rules=None):
    """Run detection and return only events that have detections."""
    results = detect(events, rules)
    return [e for e in results if "detections" in e]
