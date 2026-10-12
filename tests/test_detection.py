import json
import unittest

from endpoint_lab.analysis import analyze_bytes
from endpoint_lab.limits import InputError, Limits
from endpoint_lab.policy import ADMIN_COMMAND
from endpoint_lab.scenarios import POWERSHELL, build_cases, connection, get_case, process, tuned_policy
from endpoint_lab.validation import compare_policies


def analyze(events, **kwargs):
    return analyze_bytes(json.dumps(events).encode(), **kwargs)


class DetectionTests(unittest.TestCase):
    def test_five_original_rules(self):
        report = analyze(get_case("incident-chain")["events"])
        self.assertEqual({entry["rule_id"] for entry in report["alerts"]}, {f"EDL-00{i}" for i in range(1, 6)})
        self.assertEqual(report["alert_count"], 5)
        self.assertEqual(report["verdict"], "indicators_only")

    def test_all_tuned_ground_truth_cases(self):
        result = compare_policies()
        self.assertEqual(result["tuned"]["case_count"], 18)
        self.assertEqual(result["tuned"]["passed_cases"], 18)
        self.assertEqual(result["baseline"]["totals"]["fp"], 2)
        self.assertEqual(result["tuned"]["totals"]["tp"], 16)
        self.assertEqual(result["tuned"]["totals"]["fn"], 0)

    def test_no_sample_labels_used(self):
        for case in build_cases():
            self.assertTrue(all("expected" not in event for event in case["events"]))

    def test_order_does_not_change_results(self):
        events = get_case("incident-chain")["events"]
        self.assertEqual(analyze(events), analyze(list(reversed(events))))

    def test_guid_not_pid(self):
        self.assertEqual(analyze(get_case("pid-reuse")["events"])["alert_count"], 0)

    def test_cross_host_isolation(self):
        self.assertEqual(analyze(get_case("cross-host")["events"])["alert_count"], 0)

    def test_host_case_is_normalized(self):
        first = process(1, host="LAB-01", image=POWERSHELL)
        second = connection(first, 2, host="lab-01")
        self.assertEqual(analyze([first, second])["alert_count"], 1)

    def test_parent_fallback_is_explicit(self):
        report = analyze(get_case("parent-metadata")["events"])
        self.assertEqual(report["alerts"][0]["evidence"]["parent_source"], "declared_metadata")
        self.assertTrue(any(node["creation_missing"] for node in report["processes"]))

    def test_future_parent_not_linked(self):
        child = process(1, parent=2, second=0)
        parent = process(2, second=10)
        report = analyze([child, parent])
        self.assertGreater(report["graph_issues"]["count"], 0)
        self.assertIsNone(report["processes"][0]["parent_key"])

    def test_parent_cycle_broken(self):
        report = analyze([process(1, parent=2), process(2, parent=1)])
        self.assertGreater(report["graph_issues"]["count"], 0)
        self.assertTrue(any(node["parent_key"] is None for node in report["processes"]))

    def test_self_parent_broken(self):
        report = analyze([process(1, parent=1)])
        self.assertIsNone(report["processes"][0]["parent_key"])

    def test_conflicting_guid_rejected(self):
        with self.assertRaises(InputError):
            analyze([process(1), dict(process(1), record_id=2, image=POWERSHELL)])

    def test_image_mismatch_not_network_correlated(self):
        start = process(1, image=POWERSHELL)
        network = dict(connection(start, 2), image=r"C:\Other\other.exe")
        report = analyze([start, network])
        self.assertEqual(report["alert_count"], 0)
        self.assertGreater(report["graph_issues"]["count"], 0)

    def test_missing_creation_not_guessed(self):
        start = process(1, image=POWERSHELL)
        self.assertEqual(analyze([connection(start, 2)])["alert_count"], 0)

    def test_non_global_destinations_excluded(self):
        start = process(1, image=POWERSHELL)
        for address in ["127.0.0.1", "10.0.0.1", "192.0.2.1", "224.0.0.1", "::1", "fe80::1", "ff02::1"]:
            with self.subTest(address=address):
                self.assertEqual(analyze([start, connection(start, 2, address=address)])["alert_count"], 0)

    def test_future_connection_and_boundary(self):
        start = process(1, second=30, image=POWERSHELL)
        self.assertEqual(analyze([start, connection(start, 2, second=29)])["alert_count"], 0)
        self.assertEqual(analyze([start, connection(start, 2, second=150)])["alert_count"], 1)
        self.assertEqual(analyze([start, connection(start, 2, second=151)])["alert_count"], 0)

    def test_tuning_records_suppressed_alerts(self):
        events = get_case("normal-admin")["events"]
        report = analyze(events, policy=tuned_policy())
        self.assertEqual(report["alert_count"], 0)
        self.assertEqual(report["suppressed_count"], 2)
        self.assertTrue(all(entry["suppression"] for entry in report["suppressed"]))

    def test_tuning_does_not_suppress_other_command(self):
        event = process(1, host="lab-admin", image=POWERSHELL, command=ADMIN_COMMAND + " OTHER")
        self.assertEqual(analyze([event], policy=tuned_policy())["alert_count"], 1)

    def test_invalid_policy_rejected(self):
        for policy in [{}, {"exclusions": [{"rule_id": "EDL-003", "host": "lab-admin"}]},
                       {"exclusions": [{"rule_id": "EDL-003", "regex": ".*"}]},
                       {"exclusions": [{"rule_id": "unknown", "image": "x"}]}]:
            with self.subTest(policy=policy), self.assertRaises(InputError):
                analyze([], policy=policy)

    def test_replay_prefix(self):
        events = get_case("incident-chain")["events"]
        self.assertEqual(analyze(events, replay_count=0)["summary"]["events"], 0)
        self.assertEqual(analyze(events, replay_count=3)["alert_count"], 0)
        self.assertEqual(analyze(events, replay_count=4)["alert_count"], 2)
        with self.assertRaises(InputError):
            analyze(events, replay_count=9)

    def test_alert_limit_preserves_total(self):
        report = analyze(get_case("incident-chain")["events"], limits=Limits(alerts=1))
        self.assertEqual(len(report["alerts"]), 1)
        self.assertEqual(report["alert_count"], 5)
        self.assertTrue(report["alerts_truncated"])
        self.assertEqual(report["alerts"][0]["severity"], "high")
        self.assertEqual(sum(node["alert_count"] for node in report["processes"]), 5)

    def test_network_after_termination_not_correlated(self):
        start = process(1, image=POWERSHELL)
        ended = dict(start, event_id=5, record_id=2, timestamp="2026-01-01T00:00:05Z")
        self.assertEqual(analyze([start, ended, connection(start, 3, second=10)])["alert_count"], 0)

    def test_missing_telemetry_not_safe_verdict(self):
        report = analyze([process(1)])
        self.assertTrue(next(rule for rule in report["coverage"] if rule["rule_id"] == "EDL-004")["missing_event_ids"])
        self.assertEqual(report["verdict"], "indicators_only")

    def test_termination_in_tree(self):
        report = analyze(get_case("incident-chain")["events"])
        self.assertTrue(any(node["end"] for node in report["processes"]))
