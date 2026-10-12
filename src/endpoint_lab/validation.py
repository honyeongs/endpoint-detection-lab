import json

from .analysis import analyze_bytes
from .catalog import RULES
from .scenarios import build_cases, tuned_policy


def validate_suite(policy=None):
    totals = dict(tp=0, fp=0, fn=0, tn=0)
    per_rule = {rule["id"]: dict(rule_id=rule["id"], tp=0, fp=0, fn=0, tn=0) for rule in RULES}
    cases = []
    for case in build_cases():
        report = analyze_bytes(json.dumps(case["events"]).encode(), policy=policy)
        records = {event["key"]: event["record_id"] for event in report["events"]}
        expected = {(entry["rule_id"], entry["record_id"]) for entry in case["expected"]}
        actual = {(alert["rule_id"], records[alert["event_key"]]) for alert in report["alerts"]}
        tp, fp, fn = expected & actual, actual - expected, expected - actual
        for rule in RULES:
            rule_id = rule["id"]
            row = per_rule[rule_id]
            counts = dict(tp=sum(item[0] == rule_id for item in tp), fp=sum(item[0] == rule_id for item in fp),
                          fn=sum(item[0] == rule_id for item in fn),
                          tn=int(not any(item[0] == rule_id for item in expected | actual)))
            for name, value in counts.items():
                row[name] += value
                totals[name] += value
        cases.append(dict(id=case["id"], name=case["name"], passed=not fp and not fn,
                          tp=len(tp), fp=len(fp), fn=len(fn), expected=sorted(expected), actual=sorted(actual)))
    precision = totals["tp"] / (totals["tp"] + totals["fp"]) if totals["tp"] + totals["fp"] else None
    recall = totals["tp"] / (totals["tp"] + totals["fn"]) if totals["tp"] + totals["fn"] else None
    return dict(synthetic_only=True, case_count=len(cases), passed_cases=sum(case["passed"] for case in cases),
                totals=totals, precision=precision, recall=recall, per_rule=list(per_rule.values()), cases=cases,
                metric_unit="TP/FP/FN: unique (rule_id, target_event_record_id) per case; TN: absent rule per case",
                limitation="Functional regression on hand-authored synthetic metadata, not measured field detection performance.")


def compare_policies():
    return dict(baseline=validate_suite(), tuned=validate_suite(tuned_policy()),
                tuning_notice="Exact exclusions target a synthetic approved admin case; matching an exclusion is not a safety verdict.")
