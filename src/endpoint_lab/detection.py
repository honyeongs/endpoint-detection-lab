import bisect
import heapq
import ipaddress
import ntpath
import re
from collections import Counter

from .catalog import BY_ID
from .model import executable, windows_path, writable_path
from .policy import suppression

OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
SHELLS = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe"}
INTERPRETERS = SHELLS - {"cmd.exe"}
ENCODED = re.compile(r"(?i)(?:^|\s)[\"']?-(?:enc|encodedcommand)(?=\s|:|[\"']|$)")


def _is_executable_path(path):
    return writable_path(path) and ntpath.splitext(path)[1].casefold() in {".exe", ".com", ".scr"}


def evaluate(events, starts, exclusions, max_alerts):
    alerts, retained, total, suppressed = [], [], 0, 0
    event_counts, process_counts = Counter(), Counter()
    by_rule = {rule_id: dict(alerts=0, suppressed=0) for rule_id in BY_ID}
    files = {}
    for event in events:
        if event.event_id == 11:
            files.setdefault((event.host, windows_path(event.target_filename)), []).append(event)
    file_times = {key: [e.time for e in values] for key, values in files.items()}
    ends = {event.process_key: event.time for event in events if event.event_id == 5}

    def retain(heap, entry, sequence):
        item = (2 if entry["severity"] == "high" else 1, -sequence, entry)
        if len(heap) < max_alerts:
            heapq.heappush(heap, item)
        elif max_alerts:
            heapq.heappushpop(heap, item)

    def emit(rule_id, target, context, related, reason, evidence):
        nonlocal total, suppressed
        entry = dict(id=rule_id + ":" + target.key, rule_id=rule_id, severity=BY_ID[rule_id]["severity"],
            name=BY_ID[rule_id]["name"], event_key=target.key, process_key=target.process_key,
            timestamp=target.timestamp, host=target.host, image=target.image,
            reason=reason, evidence=evidence, related_events=[event.key for event in related])
        excluded = suppression(rule_id, context, exclusions)
        if excluded:
            suppressed += 1
            by_rule[rule_id]["suppressed"] += 1
            retain(retained, dict(entry, suppression=excluded), suppressed)
        else:
            total += 1
            by_rule[rule_id]["alerts"] += 1
            event_counts[target.key] += 1
            process_counts[target.process_key] += 1
            retain(alerts, entry, total)

    for event in events:
        if event.event_id == 1:
            image = executable(event.image)
            if _is_executable_path(event.image):
                emit("EDL-001", event, event, [event], "Executable starts in a temp/public-user path.",
                     dict(image=event.image))
            parent = starts.get(event.host + "|" + event.parent_process_guid)
            if parent and parent.time > event.time:
                parent = None
            parent_image = parent.image if parent else event.parent_image
            if image in SHELLS and executable(parent_image) in OFFICE:
                emit("EDL-002", event, event, [parent, event] if parent else [event],
                     "Document application is the shell's parent.",
                     dict(image=event.image, parent_image=parent_image,
                          parent_source="correlated_guid" if parent else "declared_metadata"))
            if image in {"powershell.exe", "pwsh.exe"} and ENCODED.search(event.command_line):
                emit("EDL-003", event, event, [event], "Encoded command option appears in process metadata.",
                     dict(command_line=event.command_line))
            key = (event.host, windows_path(event.image))
            if _is_executable_path(event.image) and key in files:
                index = bisect.bisect_right(file_times[key], event.time) - 1
                if index >= 0:
                    created = files[key][index]
                    elapsed = (event.time - created.time).total_seconds()
                    if elapsed <= 300:
                        emit("EDL-005", event, event, [created, event],
                             "Same host/path has a FileCreate within the preceding 300 seconds.",
                             dict(target_filename=created.target_filename, writer_image=created.image,
                                  elapsed_seconds=elapsed, content_identity="not_verified"))
        elif event.event_id == 3 and event.destination_ip and event.initiated is True:
            start = starts.get(event.process_key)
            if not start or windows_path(start.image) != windows_path(event.image):
                continue
            elapsed = (event.time - start.time).total_seconds()
            if event.process_key in ends and event.time > ends[event.process_key]:
                continue
            address = ipaddress.ip_address(event.destination_ip)
            if executable(start.image) in INTERPRETERS and 0 <= elapsed <= 120 and address.is_global and not address.is_multicast and not address.is_reserved:
                emit("EDL-004", event, start, [start, event],
                     "Interpreter has an outbound public unicast connection within 120 seconds.",
                     dict(destination_ip=str(address), destination_port=event.destination_port,
                          elapsed_seconds=elapsed, command_line=start.command_line))
    ordered = lambda heap: sorted((item[2] for item in heap), key=lambda a: (a["timestamp"], a["id"]))
    return dict(alerts=ordered(alerts), alert_count=total, alerts_truncated=total > len(alerts),
                suppressed=ordered(retained), suppressed_count=suppressed, suppressed_truncated=suppressed > len(retained),
                by_rule=by_rule, _event_counts=event_counts, _process_counts=process_counts)
