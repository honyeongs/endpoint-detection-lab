from collections import Counter

from .catalog import RULES
from .detection import evaluate
from .graph import build_processes
from .limits import DEFAULT, InputError, Limits
from .parsing import parse_events
from .policy import validate_policy


def analyze_events(events, *, policy=None, limits: Limits = DEFAULT, stats=None, replay_count=None):
    source_total = len(events)
    if replay_count is not None:
        if isinstance(replay_count, bool) or not isinstance(replay_count, int) or not 0 <= replay_count <= source_total:
            raise InputError("Replay count must be between zero and the source event count.")
        events = events[:replay_count]
    exclusions = validate_policy(policy if policy is not None else {"exclusions": []})
    starts, nodes, issues = build_processes(events)
    detection = evaluate(events, starts, exclusions, limits.alerts)
    counts = Counter(event.event_id for event in events)
    coverage = [dict(rule_id=rule["id"], required_event_ids=rule["required"],
                     missing_event_ids=[event_id for event_id in rule["required"] if not counts[event_id]]) for rule in RULES]
    event_alerts = detection.pop("_event_counts")
    process_alerts = detection.pop("_process_counts")
    for key, node in nodes.items():
        node["alert_count"] = process_alerts[key]
    stats = stats or dict(source_events=source_total, accepted_events=source_total, duplicate_events=0,
                          unsupported_events=0, foreign_provider_events=0, format="normalized")
    quality = "empty" if not events else "partial" if stats.get("unsupported_events") or stats.get("foreign_provider_events") or issues["count"] else "analyzed"
    return dict(schema_version="1.0", lab_only=True, verdict="indicators_only", quality=quality,
        input=stats, replay=dict(total=source_total, analyzed=len(events)),
        summary=dict(events=len(events), processes=len(nodes), hosts=len({event.host for event in events}),
                     alerts=detection["alert_count"], suppressed=detection["suppressed_count"]),
        event_type_counts={str(key): value for key, value in sorted(counts.items())},
        coverage=coverage, graph_issues=issues,
        events=[dict(event.public(), alert_count=event_alerts[event.key]) for event in events],
        processes=list(nodes.values()), **detection)


def analyze_bytes(data: bytes, *, format="auto", policy=None, limits: Limits = DEFAULT, replay_count=None):
    events, stats = parse_events(data, format=format, limits=limits)
    return analyze_events(events, policy=policy, limits=limits, stats=stats, replay_count=replay_count)
