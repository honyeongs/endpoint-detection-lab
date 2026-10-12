import json

from .limits import DEFAULT, InputError, Limits
from .model import normalize
from .xml_reader import parse_xml


def strict_json(data: bytes):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise InputError("Duplicate JSON key.")
            result[key] = value
        return result

    def constant(value):
        raise InputError("Non-finite JSON numbers are forbidden.")

    try:
        return json.loads(data.decode("utf-8-sig"), object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        if isinstance(exc, InputError):
            raise
        raise InputError("Invalid or excessively nested UTF-8 JSON.") from None


def parse_events(data: bytes, *, format="auto", limits: Limits = DEFAULT) -> tuple[list, dict]:
    if not isinstance(data, bytes) or len(data) > limits.file_bytes:
        raise InputError("Expected at most 8 MiB of log bytes.")
    if format == "auto":
        prefix = data.lstrip(b"\xef\xbb\xbf \r\n\t")
        format = "xml" if prefix.startswith(b"<") or data.startswith((b"\xff\xfe", b"\xfe\xff")) else "json"
    if format == "xml":
        events, stats = parse_xml(data, limits)
    elif format == "json":
        source = strict_json(data)
        if not isinstance(source, list) or len(source) > limits.events:
            raise InputError("JSON must be an array with at most 10000 events.")
        events = [normalize(item, limits) for item in source]
        stats = dict(source_events=len(source), unsupported_events=0, foreign_provider_events=0)
    else:
        raise InputError("Format must be auto, xml or json.")
    unique = {event.key: event for event in events}
    stats.update(format=format, duplicate_events=len(events) - len(unique), accepted_events=len(unique),
                 timestamp_policy="UTC; timezone-free Sysmon UtcTime is interpreted as UTC")
    ordered = sorted(unique.values(), key=lambda e: (e.time, e.record_id, e.key))
    return ordered, stats
