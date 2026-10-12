"""Regenerate distributable, original synthetic fixtures; never run event commands."""
import json
import sys
from pathlib import Path
from xml.etree.ElementTree import Element, SubElement, indent, tostring

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from endpoint_lab.scenarios import get_case, tuned_policy  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
TARGETS = [ROOT / "samples", ROOT / "src" / "endpoint_lab" / "data"]
NAMESPACE = "http://schemas.microsoft.com/win/2004/08/events/event"
FIELDS = {"process_guid": "ProcessGuid", "pid": "ProcessId", "image": "Image",
          "parent_process_guid": "ParentProcessGuid", "parent_image": "ParentImage",
          "command_line": "CommandLine", "user": "User", "target_filename": "TargetFilename",
          "destination_ip": "DestinationIp", "destination_port": "DestinationPort", "initiated": "Initiated"}


def make_xml(events):
    root = Element("Events")
    for entry in events:
        event = SubElement(root, "Event", xmlns=NAMESPACE)
        system = SubElement(event, "System")
        SubElement(system, "Provider", Name="Microsoft-Windows-Sysmon")
        SubElement(system, "EventID").text = str(entry["event_id"])
        SubElement(system, "TimeCreated", SystemTime=entry["timestamp"])
        SubElement(system, "EventRecordID").text = str(entry["record_id"])
        SubElement(system, "Computer").text = entry["host"]
        data = SubElement(event, "EventData")
        SubElement(data, "Data", Name="UtcTime").text = entry["timestamp"]
        for key, name in FIELDS.items():
            if key in entry:
                value = entry[key]
                SubElement(data, "Data", Name=name).text = str(value).lower() if isinstance(value, bool) else str(value)
    indent(root)
    return tostring(root, encoding="utf-8", xml_declaration=True)


def main():
    events = get_case("incident-chain")["events"]
    for target in TARGETS:
        target.mkdir(parents=True, exist_ok=True)
        (target / "incident-chain.json").write_text(json.dumps(events, indent=2) + "\n", encoding="utf-8")
        (target / "incident-chain.xml").write_bytes(make_xml(events) + b"\n")
        (target / "tuned-policy.json").write_text(json.dumps(tuned_policy(), indent=2) + "\n", encoding="utf-8")
    print("Original synthetic samples generated.")


if __name__ == "__main__":
    main()
