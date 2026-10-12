"""Bounded Sysmon XML reader using Expat; DTD and entity declarations are forbidden."""
from xml.parsers import expat

from .limits import InputError, Limits
from .model import SUPPORTED_IDS, normalize

NAMESPACE = "http://schemas.microsoft.com/win/2004/08/events/event"
FIELDS = {"processguid": "process_guid", "processid": "pid", "image": "image",
          "parentprocessguid": "parent_process_guid", "parentimage": "parent_image",
          "commandline": "command_line", "user": "user", "targetfilename": "target_filename",
          "destinationip": "destination_ip", "destinationport": "destination_port"}


def _integer(value: str) -> int:
    value = value.strip()
    if not value.isascii() or not value.isdecimal() or len(value) > 19:
        raise InputError("Invalid integer in Sysmon XML.")
    return int(value)


def parse_xml(data: bytes, limits: Limits) -> tuple[list, dict]:
    events, stack, text, raw, names = [], [], [], {}, set()
    stats = dict(source_events=0, unsupported_events=0, foreign_provider_events=0)
    parser = expat.ParserCreate(namespace_separator="}")
    parser.buffer_text = True
    node_count, text_size, capture, active = 0, 0, "", False

    def forbidden(*args):
        raise InputError("DTD, custom entities and external XML references are forbidden.")

    def start(tag, attrs):
        nonlocal node_count, text_size, capture, active, raw, names
        namespace, _, local = tag.rpartition("}")
        local = local or tag
        if namespace not in {"", NAMESPACE}:
            raise InputError("Unsupported XML namespace.")
        if capture:
            raise InputError("Nested markup in Sysmon scalar fields is forbidden.")
        stack.append(local)
        node_count += 1
        if len(stack) > limits.xml_depth or node_count > limits.xml_nodes:
            raise InputError("XML structural limit exceeded.")
        if len(attrs) > 32 or any(len(k) > 128 or len(v) > limits.field_chars for k, v in attrs.items()):
            raise InputError("XML attribute limit exceeded.")
        if len(stack) == 1 and local not in {"Events", "Event"}:
            raise InputError("Expected an Events or Event XML root.")
        if local == "Event":
            if active or stack not in [["Event"], ["Events", "Event"]]:
                raise InputError("Invalid nested Event element.")
            active, raw, names = True, {}, set()
            stats["source_events"] += 1
            if stats["source_events"] > limits.events:
                raise InputError("Event count exceeds 10000.")
        if not active:
            return
        if local in {"System", "EventData"} and stack[-2] != "Event":
            raise InputError("Invalid Sysmon element hierarchy.")
        if stack[-2:] == ["System", "Provider"]:
            if "provider" in raw:
                raise InputError("Duplicate Sysmon Provider.")
            raw["provider"] = attrs.get("Name", "")
        if stack[-2:] == ["System", "TimeCreated"]:
            if "system_time" in raw:
                raise InputError("Duplicate Sysmon TimeCreated.")
            raw["system_time"] = attrs.get("SystemTime", "")
        if stack[-2:] == ["System", local] and local in {"EventID", "EventRecordID", "Computer"}:
            capture = local
        elif stack[-2:] == ["EventData", "Data"]:
            name = attrs.get("Name", "").casefold()
            if not name or name in names:
                raise InputError("Missing or duplicate Sysmon data field.")
            names.add(name)
            capture = "data:" + name
        else:
            capture = ""
        text.clear()
        text_size = 0

    def characters(value):
        nonlocal text_size
        if capture:
            text_size += len(value)
            if text_size > limits.field_chars:
                raise InputError("XML text field exceeds limits.")
            text.append(value)

    def end(tag):
        nonlocal capture, active
        local = tag.rsplit("}", 1)[-1]
        if capture:
            if capture in raw:
                raise InputError("Duplicate Sysmon system field.")
            raw[capture] = "".join(text)
        capture = ""
        text.clear()
        if local == "Event":
            active = False
            event_id = _integer(raw.get("EventID", ""))
            if raw.get("provider") != "Microsoft-Windows-Sysmon":
                stats["foreign_provider_events"] += 1
            elif event_id not in SUPPORTED_IDS:
                stats["unsupported_events"] += 1
            else:
                record = {target: raw.get("data:" + source, "") for source, target in FIELDS.items()}
                for name in ("pid", "destination_port"):
                    record[name] = _integer(record[name]) if record[name] else 0
                initiated = raw.get("data:initiated", "").casefold()
                if initiated not in {"", "true", "false"}:
                    raise InputError("Invalid Initiated value in Sysmon XML.")
                record.update(event_id=event_id, timestamp=raw.get("data:utctime") or raw.get("system_time", ""),
                              host=raw.get("Computer", ""), record_id=_integer(raw.get("EventRecordID", "0")),
                              initiated=None if not initiated else initiated == "true")
                events.append(normalize(record, limits))
        stack.pop()

    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = characters
    parser.StartDoctypeDeclHandler = forbidden
    parser.EntityDeclHandler = forbidden
    parser.ExternalEntityRefHandler = forbidden
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    try:
        for offset in range(0, len(data), 65536):
            parser.Parse(data[offset:offset + 65536], False)
        parser.Parse(b"", True)
    except expat.ExpatError:
        raise InputError("Malformed XML; no partial report was produced.") from None
    return events, stats
