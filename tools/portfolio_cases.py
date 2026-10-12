"""Explicit scope and provenance for ten independent feature scenarios."""
PROJECT = {
    "cases": [
        [
            "Sysmon XML and normalized JSON parity",
            "tests.test_parsing.ParsingTests.test_json_xml_equivalence"
        ],
        [
            "All five original indicators in an incident chain",
            "tests.test_detection.DetectionTests.test_five_original_rules"
        ],
        [
            "Synthetic truth validation and tuning comparison",
            "tests.test_detection.DetectionTests.test_all_tuned_ground_truth_cases"
        ],
        [
            "PID reuse does not link different GUIDs",
            "tests.test_detection.DetectionTests.test_guid_not_pid"
        ],
        [
            "Host isolation in process correlation",
            "tests.test_detection.DetectionTests.test_cross_host_isolation"
        ],
        [
            "Connection time direction and inclusive boundary",
            "tests.test_detection.DetectionTests.test_future_connection_and_boundary"
        ],
        [
            "Exact exclusions retain suppressed evidence",
            "tests.test_detection.DetectionTests.test_tuning_records_suppressed_alerts"
        ],
        [
            "DTD and internal/external entities rejected",
            "tests.test_parsing.ParsingTests.test_dtd_and_entity_rejected"
        ],
        [
            "Replay prefix changes analyzed events",
            "tests.test_detection.DetectionTests.test_replay_prefix"
        ],
        [
            "CLI output never overwrites the input",
            "tests.test_cli.CliTests.test_no_overwrite"
        ]
    ],
    "checks": [
        [
            "endpoint-browser",
            [
                "tests/browser/smoke.mjs"
            ]
        ]
    ],
    "limitations": [
        "All telemetry in this run is original synthetic Sysmon-shaped XML/JSON, not logs collected from a real endpoint.",
        "Synthetic TP/FP/FN measures functional regression only, not independent field detection accuracy.",
        "No Sysmon installation, malware execution, event collection agent or automatic blocking is performed.",
        "Windows symbolic-link cases may be skipped when the account lacks the required privilege."
    ]
}

