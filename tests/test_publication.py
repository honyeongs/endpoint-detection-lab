import unittest

from tools.check_publication import check_assets, check_runtime, check_samples


class PublicationTests(unittest.TestCase):
    def test_vendored_asset_inventory(self):
        check_assets()

    def test_only_original_synthetic_samples(self):
        check_samples()

    def test_no_unreviewed_runtime_dependencies(self):
        check_runtime()
