#!/usr/bin/env python3
"""Parse Sysmon XML logs and extract key fields from Event ID 1 (Process Creation) events."""

import argparse
import json
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


def parse_events(xml_path):
    tree = ET.parse(xml_path)
    root = tree.getroot()

    results = []
    for event in root.iter("Event"):
        system = event.find("System")
        if system is None:
            continue

        event_id_el = system.find("EventID")
        if event_id_el is None or event_id_el.text != "1":
            continue

        record = {"EventID": 1}

        computer_el = system.find("Computer")
        if computer_el is not None:
            record["Computer"] = computer_el.text

        event_data = event.find("EventData")
        if event_data is not None:
            for data in event_data.findall("Data"):
                name = data.get("Name")
                if name in EVENTDATA_FIELDS:
                    record[name] = data.text

        results.append(record)

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
    parser = argparse.ArgumentParser(description="Parse Sysmon Event ID 1 from XML")
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

    if len(events) == 1:
        print(json.dumps(events[0], indent=2))
    else:
        print(json.dumps(events, indent=2))


if __name__ == "__main__":
    main()
