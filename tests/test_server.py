import http.client
import json
import threading
import unittest

from endpoint_lab.server import create_server
from endpoint_lab.scenarios import get_case
from tools.generate_samples import make_xml


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = create_server(0)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = cls.server.server_port
        cls.origin = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def request(self, path="/", method="GET", body=None, headers=None):
        client = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            client.request(method, path, body=body, headers=headers or {})
            response = client.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            client.close()

    def post(self, body=b"[]", **headers):
        values = {"Origin": self.origin, "Content-Type": "application/octet-stream"}
        values.update(headers)
        return self.request("/api/analyze", "POST", body, values)

    def test_health(self):
        status, _, body = self.request("/api/health")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["max_file_bytes"], 8 * 1024 * 1024)

    def test_static_files_and_headers(self):
        for path in ["/", "/app.js", "/render.js", "/style.css", "/assets/shield-check.svg"]:
            status, headers, body = self.request(path)
            self.assertEqual(status, 200)
            self.assertTrue(body)
            self.assertEqual(headers["Cache-Control"], "no-store")
            self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
            self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
            self.assertNotIn("Access-Control-Allow-Origin", headers)

    def test_catalog_and_scenarios(self):
        _, _, raw = self.request("/api/catalog")
        self.assertEqual(len(json.loads(raw)["rules"]), 5)
        self.assertEqual(len(json.loads(raw)["scenarios"]), 18)
        self.assertEqual(self.request("/api/scenarios/incident-chain")[0], 200)
        self.assertEqual(self.request("/api/scenarios/unknown")[0], 404)

    def test_analyze_json_and_xml(self):
        events = get_case("incident-chain")["events"]
        for body in [json.dumps(events).encode(), make_xml(events)]:
            status, _, result = self.post(body)
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(result)["alert_count"], 5)

    def test_validation(self):
        status, _, body = self.request("/api/validation")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["tuned"]["passed_cases"], 18)

    def test_tuning_and_replay(self):
        events = get_case("normal-admin")["events"]
        status, _, body = self.post(json.dumps(events).encode(), **{"X-Lab-Policy": "tuned"})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["suppressed_count"], 2)
        status, _, body = self.post(json.dumps(events).encode(), **{"X-Replay-Count": "0"})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["summary"]["events"], 0)

    def test_host_and_origin(self):
        self.assertEqual(self.request(headers={"Host": "attacker.invalid"})[0], 403)
        self.assertEqual(self.post(Origin="https://attacker.invalid")[0], 403)
        self.assertEqual(self.request("/api/analyze", "POST", b"[]")[0], 403)

    def test_traversal_and_unknown_api(self):
        for path in ["/../pyproject.toml", "/%2e%2e/run.py", "/assets/../server.py", "/api/scenarios/../secret", "/api/analyze?path=secret"]:
            self.assertEqual(self.request(path)[0], 404)

    def test_bad_length_encoding_and_type(self):
        for headers in [{"Content-Length": "-1"}, {"Content-Length": "9" * 5000},
                        {"Content-Length": str(8 * 1024 * 1024 + 1)}, {"Transfer-Encoding": "chunked"},
                        {"Content-Type": "application/json"}]:
            with self.subTest(headers=headers):
                self.assertEqual(self.post(**headers)[0], 400)

    def test_bad_policy_and_replay_header(self):
        for headers in [{"X-Lab-Policy": "unknown"}, {"X-Replay-Count": "-1"}, {"X-Replay-Count": "1"}]:
            self.assertEqual(self.post(**headers)[0], 400)

    def test_invalid_xml_is_not_partial_success(self):
        self.assertEqual(self.post(b'<!DOCTYPE Events [<!ENTITY x "x">]><Events/>')[0], 400)

    def test_port_validation(self):
        with self.assertRaises(ValueError):
            create_server(-1)
