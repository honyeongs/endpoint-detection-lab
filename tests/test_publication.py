import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from tools.check_publication import ROOT, check_assets, check_runtime, check_samples, check_tracked_files


class PublicationTests(unittest.TestCase):
    def test_vendored_asset_inventory(self):
        check_assets()

    def test_only_original_synthetic_samples(self):
        check_samples()

    def test_no_unreviewed_runtime_dependencies(self):
        check_runtime()

    def test_current_publication_set_is_reviewed(self):
        check_tracked_files()

    def check_fixture(self, filename, data):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            target = root / filename
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(json.dumps(data), encoding='utf-8')
            with patch('tools.check_publication.subprocess.run', return_value=Mock(stdout=(filename + '\0').encode())):
                check_tracked_files(root)

    def test_worker_manifest_rejects_unreviewed_fields_and_types(self):
        for manifest in ({'project_id': 'appgprj_test', 'static': {'directory': 'dist'}},
                         {'project_id': 'appgprj_test', 'token': 'inert'}, {'project_id': None}):
            with self.subTest(manifest=manifest), self.assertRaises(ValueError):
                self.check_fixture('website/.openai/hosting.json', manifest)
        self.check_fixture('website/.openai/hosting.json', {'project_id': 'appgprj_test'})

    def test_new_report_requires_privacy_schema_not_just_an_approved_name(self):
        report = json.loads((ROOT / 'docs/testing/2026-10-22-security-fixes.json').read_text(encoding='utf-8'))
        self.check_fixture('docs/testing/2026-10-22-security-fixes-final.json', report)
        report['raw_log'] = 'INERT_PRIVATE_CANARY'
        with self.assertRaises(ValueError):
            self.check_fixture('docs/testing/2026-10-22-security-fixes-final.json', report)

    def test_other_json_files_are_still_blocked(self):
        with self.assertRaises(ValueError):
            self.check_fixture('docs/testing/unreviewed.json', {})

    def test_private_file_types_are_still_blocked(self):
        for name in ('.env', 'private.evtx', 'private.pem'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.check_fixture(name, {})
