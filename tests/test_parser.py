import os
import pytest
from parser import parse_events, filter_events

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "..", "samples")


def sample_path(name):
    return os.path.join(SAMPLES_DIR, name)


# --- parse_events tests ---


class TestParseEvents:
    def test_extracts_all_fields_from_event1(self):
        events = parse_events(sample_path("event1.xml"))
        assert len(events) == 1
        e = events[0]
        assert e["EventID"] == 1
        assert e["Computer"] == "DESKTOP-ABC1234"
        assert e["UtcTime"] == "2024-01-15 10:30:45.123"
        assert e["Image"] == r"C:\Windows\System32\whoami.exe"
        assert e["CommandLine"] == "whoami /priv"
        assert e["User"] == r"DESKTOP-ABC1234\analyst"
        assert e["IntegrityLevel"] == "Medium"
        assert e["ParentImage"] == r"C:\Windows\System32\cmd.exe"
        assert e["ParentCommandLine"] == r"cmd.exe /c whoami /priv"
        assert "SHA256=" in e["Hashes"]

    def test_extracts_event2_powershell(self):
        events = parse_events(sample_path("event2.xml"))
        assert len(events) == 1
        e = events[0]
        assert "powershell.exe" in e["Image"]
        assert e["Computer"] == "WORKSTATION-07"
        assert e["User"] == r"WORKSTATION-07\jdoe"
        assert e["IntegrityLevel"] == "Medium"
        assert "cmd.exe" in e["ParentImage"]

    def test_extracts_event3_suspicious(self):
        events = parse_events(sample_path("event3.xml"))
        assert len(events) == 1
        e = events[0]
        assert "-Enc" in e["CommandLine"]
        assert e["IntegrityLevel"] == "High"
        assert e["User"] == r"CORP\Administrator"
        assert "wscript.exe" in e["ParentImage"]

    def test_skips_non_event_id_1(self, tmp_path):
        xml = tmp_path / "event5.xml"
        xml.write_text("""<Events>
  <Event>
    <System>
      <EventID>5</EventID>
      <Computer>HOST</Computer>
    </System>
    <EventData>
      <Data Name="Image">C:\\foo.exe</Data>
    </EventData>
  </Event>
</Events>""")
        events = parse_events(str(xml))
        assert events == []

    def test_mixed_event_ids(self, tmp_path):
        xml = tmp_path / "mixed.xml"
        xml.write_text("""<Events>
  <Event>
    <System><EventID>3</EventID><Computer>HOST</Computer></System>
    <EventData><Data Name="Image">net.exe</Data></EventData>
  </Event>
  <Event>
    <System><EventID>1</EventID><Computer>HOST</Computer></System>
    <EventData>
      <Data Name="Image">calc.exe</Data>
      <Data Name="CommandLine">calc</Data>
      <Data Name="User">HOST\\user</Data>
      <Data Name="IntegrityLevel">Medium</Data>
      <Data Name="UtcTime">2024-01-01 00:00:00.000</Data>
      <Data Name="ParentImage">explorer.exe</Data>
      <Data Name="ParentCommandLine">explorer.exe</Data>
      <Data Name="Hashes">SHA256=AAA</Data>
    </EventData>
  </Event>
  <Event>
    <System><EventID>5</EventID><Computer>HOST</Computer></System>
    <EventData><Data Name="Image">svc.exe</Data></EventData>
  </Event>
</Events>""")
        events = parse_events(str(xml))
        assert len(events) == 1
        assert events[0]["Image"] == "calc.exe"

    def test_empty_events(self, tmp_path):
        xml = tmp_path / "empty.xml"
        xml.write_text("<Events></Events>")
        assert parse_events(str(xml)) == []

    def test_ignores_extra_data_fields(self, tmp_path):
        xml = tmp_path / "extra.xml"
        xml.write_text("""<Events>
  <Event>
    <System><EventID>1</EventID><Computer>HOST</Computer></System>
    <EventData>
      <Data Name="Image">test.exe</Data>
      <Data Name="User">HOST\\u</Data>
      <Data Name="RuleName">-</Data>
      <Data Name="ProcessGuid">{guid}</Data>
      <Data Name="LogonId">0x123</Data>
    </EventData>
  </Event>
</Events>""")
        events = parse_events(str(xml))
        e = events[0]
        assert "RuleName" not in e
        assert "ProcessGuid" not in e
        assert "LogonId" not in e

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            parse_events("/nonexistent/path.xml")

    def test_invalid_xml(self, tmp_path):
        xml = tmp_path / "bad.xml"
        xml.write_text("<<not xml at all>>")
        with pytest.raises(Exception):
            parse_events(str(xml))


# --- filter_events tests ---


SAMPLE_EVENTS = [
    {
        "EventID": 1,
        "Image": r"C:\Windows\System32\whoami.exe",
        "User": r"HOST\admin",
        "IntegrityLevel": "High",
    },
    {
        "EventID": 1,
        "Image": r"C:\Windows\System32\powershell.exe",
        "User": r"HOST\user1",
        "IntegrityLevel": "Medium",
    },
    {
        "EventID": 1,
        "Image": r"C:\Windows\System32\cmd.exe",
        "User": r"HOST\admin",
        "IntegrityLevel": "Medium",
    },
    {
        "EventID": 1,
        "Image": r"C:\Windows\System32\svchost.exe",
        "User": "SYSTEM",
        "IntegrityLevel": "System",
    },
]


class TestFilterEvents:
    def test_no_filters_returns_all(self):
        result = filter_events(SAMPLE_EVENTS)
        assert result == SAMPLE_EVENTS

    def test_image_substring_match(self):
        result = filter_events(SAMPLE_EVENTS, image="whoami")
        assert len(result) == 1
        assert "whoami" in result[0]["Image"].lower()

    def test_image_case_insensitive(self):
        result = filter_events(SAMPLE_EVENTS, image="POWERSHELL")
        assert len(result) == 1
        assert "powershell" in result[0]["Image"].lower()

    def test_image_no_match(self):
        result = filter_events(SAMPLE_EVENTS, image="notepad")
        assert result == []

    def test_user_exact_match(self):
        result = filter_events(SAMPLE_EVENTS, user=r"HOST\admin")
        assert len(result) == 2
        assert all(e["User"] == r"HOST\admin" for e in result)

    def test_user_no_partial_match(self):
        result = filter_events(SAMPLE_EVENTS, user="admin")
        assert result == []

    def test_integrity_level_filter(self):
        result = filter_events(SAMPLE_EVENTS, integrity_level="Medium")
        assert len(result) == 2
        assert all(e["IntegrityLevel"] == "Medium" for e in result)

    def test_integrity_level_system(self):
        result = filter_events(SAMPLE_EVENTS, integrity_level="System")
        assert len(result) == 1
        assert result[0]["User"] == "SYSTEM"

    def test_combined_image_and_user(self):
        result = filter_events(SAMPLE_EVENTS, image="cmd", user=r"HOST\admin")
        assert len(result) == 1
        assert "cmd" in result[0]["Image"].lower()

    def test_combined_all_three_filters(self):
        result = filter_events(
            SAMPLE_EVENTS, image="powershell", user=r"HOST\user1", integrity_level="Medium"
        )
        assert len(result) == 1
        assert "powershell" in result[0]["Image"].lower()

    def test_combined_filters_no_match(self):
        result = filter_events(SAMPLE_EVENTS, image="whoami", integrity_level="Low")
        assert result == []

    def test_empty_input(self):
        assert filter_events([], image="test") == []
