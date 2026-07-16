#!/usr/bin/env python3
"""Parse Sysmon XML logs and extract key fields from Event ID 1 (Process Creation) events."""

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET

EVENTDATA_FIELDS = [
    "UtcTime",
    "Image",
    "CommandLine",
    "User",
    "IntegrityLevel",
    "ParentImage",
    "ParentCommandLine",
    "Hashes",
]

FORBIDDEN_XML_MARKERS = (b"<!DOCTYPE", b"<!ENTITY")
SECRET_PATTERNS = (
    re.compile(r"(?i)(Authorization:\s*Bearer\s+)[A-Za-z0-9._-]+"),
    re.compile(
        r"(?i)((?:OPENAI|ANTHROPIC|GOOGLE|MISTRAL|COHERE)_API_KEY\s*[=:]\s*)"
        r"(?:[^\s\"']+|\"[^\"]+\"|'[^']+')"
    ),
    re.compile(r"(?i)(sk-(?:proj-|ant-api\d*-)?)[A-Za-z0-9_-]{8,}"),
)


def _local_name(tag):
    """Return an XML tag without its optional namespace."""
    return tag.rsplit("}", 1)[-1]


def _child(element, name):
    """Find a direct child by local name, regardless of XML namespace."""
    return next((item for item in element if _local_name(item.tag) == name), None)


def _reject_dtd_and_entities(xml_path):
    """Reject XML constructs that are unnecessary for Windows Event exports."""
    overlap = b""
    with open(xml_path, "rb") as xml_file:
        while chunk := xml_file.read(65536):
            candidate = overlap + chunk
            if any(marker in candidate for marker in FORBIDDEN_XML_MARKERS):
                raise ET.ParseError("DTD and entity declarations are not allowed")
            overlap = candidate[-16:]


def redact_secrets(record):
    """Return a copy of an event with common API credentials masked."""
    redacted = dict(record)
    for field in ("CommandLine", "ParentCommandLine"):
        value = redacted.get(field)
        if not value:
            continue
        for pattern in SECRET_PATTERNS:
            value = pattern.sub(r"\1[REDACTED]", value)
        redacted[field] = value
    return redacted


def parse_events(xml_path):
    _reject_dtd_and_entities(xml_path)

    results = []
    for _, event in ET.iterparse(xml_path, events=("end",)):
        if _local_name(event.tag) != "Event":
            continue

        system = _child(event, "System")
        if system is None:
            event.clear()
            continue

        event_id_el = _child(system, "EventID")
        if event_id_el is None or event_id_el.text != "1":
            event.clear()
            continue

        record = {"EventID": 1}

        computer_el = _child(system, "Computer")
        if computer_el is not None:
            record["Computer"] = computer_el.text

        event_data = _child(event, "EventData")
        if event_data is not None:
            for data in event_data:
                if _local_name(data.tag) != "Data":
                    continue
                name = data.get("Name")
                if name in EVENTDATA_FIELDS:
                    record[name] = data.text

        results.append(record)
        event.clear()

    return results


def filter_events(events, image=None, user=None, integrity_level=None):
    filtered = events
    if image:
        image_lower = image.lower()
        filtered = [e for e in filtered if image_lower in e.get("Image", "").lower()]
    if user:
        filtered = [e for e in filtered if e.get("User") == user]
    if integrity_level:
        filtered = [e for e in filtered if e.get("IntegrityLevel") == integrity_level]
    return filtered


def main():
    parser = argparse.ArgumentParser(
        description="aismon: detect AI-related activity in Sysmon Event ID 1 XML"
    )
    parser.add_argument("xml_file", help="Path to Sysmon XML file")
    parser.add_argument("--image", help="Filter by Image (substring, case-insensitive)")
    parser.add_argument("--user", help="Filter by User (exact match)")
    parser.add_argument(
        "--integrity-level",
        choices=["High", "Medium", "Low", "System"],
        help="Filter by IntegrityLevel",
    )
    parser.add_argument(
        "--detect",
        action="store_true",
        help="Run AI/LLM threat detection rules against events",
    )
    parser.add_argument(
        "--detect-only",
        action="store_true",
        help="Only output events that trigger detection rules",
    )
    args = parser.parse_args()

    try:
        events = parse_events(args.xml_file)
    except ET.ParseError as e:
        print(f"Error parsing XML: {e}", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError:
        print(f"File not found: {args.xml_file}", file=sys.stderr)
        sys.exit(1)

    events = filter_events(events, image=args.image, user=args.user,
                            integrity_level=args.integrity_level)

    if args.detect or args.detect_only:
        from detector import detect, detect_summary
        if args.detect_only:
            events = detect_summary(events)
        else:
            events = detect(events)

    events = [redact_secrets(event) for event in events]

    if len(events) == 1:
        print(json.dumps(events[0], indent=2))
    else:
        print(json.dumps(events, indent=2))


if __name__ == "__main__":
    main()
