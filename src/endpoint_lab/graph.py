from .limits import InputError
from .model import windows_path


def build_processes(events):
    starts, nodes = {}, {}
    for event in events:
        key = event.process_key
        node = nodes.setdefault(key, dict(key=key, host=event.host, process_guid=event.process_guid,
            image=event.image, pid=event.pid, parent_key=None, start=None, end=None, creation_missing=True))
        if event.event_id == 1:
            if key in starts:
                raise InputError("Conflicting ProcessCreate records for the same host and ProcessGuid.")
            starts[key] = event
            node.update(image=event.image, pid=event.pid, start=event.timestamp, creation_missing=False)
        elif event.event_id == 5:
            node["end"] = event.timestamp
    issues = []
    for key, start in starts.items():
        if not start.parent_process_guid:
            continue
        parent_key = start.host + "|" + start.parent_process_guid
        parent = starts.get(parent_key)
        if parent_key == key or (parent and parent.time > start.time):
            issues.append("Invalid parent chronology or self-parent; edge omitted.")
            continue
        if parent_key not in nodes:
            nodes[parent_key] = dict(key=parent_key, host=start.host, process_guid=start.parent_process_guid,
                image=start.parent_image, pid=0, parent_key=None, start=None, end=None, creation_missing=True)
        nodes[key]["parent_key"] = parent_key
    # Each node has at most one parent. Iterative coloring detects cycles in linear time.
    finished = set()
    for key in nodes:
        route, positions, current = [], {}, key
        while current in nodes and current not in finished:
            if current in positions:
                nodes[route[-1]]["parent_key"] = None
                issues.append("Cyclic parent metadata; one edge omitted.")
                break
            positions[current] = len(route)
            route.append(current)
            current = nodes[current]["parent_key"]
        finished.update(route)
    for event in events:
        start = starts.get(event.process_key)
        if start and event.event_id != 1 and windows_path(start.image) != windows_path(event.image):
            issues.append("Image differs across events sharing a ProcessGuid.")
    return starts, nodes, dict(count=len(issues), messages=sorted(set(issues))[:20])
