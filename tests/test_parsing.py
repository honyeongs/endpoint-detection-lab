import json
import unittest
from pathlib import Path

from endpoint_lab.limits import InputError, Limits
from endpoint_lab.model import normalize, windows_path
from endpoint_lab.parsing import parse_events
from endpoint_lab.scenarios import process
from tools.generate_samples import make_xml


class ParsingTests(unittest.TestCase):
    def test_json_xml_equivalence(self):
        path = Path(__file__).parents[1] / "samples"
        json_events, _ = parse_events((path / "incident-chain.json").read_bytes())
        xml_events, _ = parse_events((path / "incident-chain.xml").read_bytes())
        self.assertEqual(json_events, xml_events)

    def test_utf16_xml(self):
        data = make_xml([process(1)]).decode().replace("encoding='utf-8'", "encoding='utf-16'").encode("utf-16")
        self.assertEqual(len(parse_events(data)[0]), 1)

    def test_single_event_xml(self):
        from xml.etree.ElementTree import fromstring, tostring
        source = fromstring(make_xml([process(1)]))
        self.assertEqual(len(parse_events(tostring(source[0]))[0]), 1)

    def test_dtd_and_entity_rejected(self):
        for data in [b'<!DOCTYPE Events [<!ENTITY x "boom">]><Events>&x;</Events>',
                     b'<!DOCTYPE Events SYSTEM "file:///etc/passwd"><Events/>',
                     b'<!DOCTYPE Events [<!ENTITY % a SYSTEM "https://example.invalid/x">%a;]><Events/>']:
            with self.subTest(data=data), self.assertRaises(InputError):
                parse_events(data)

    def test_utf16_dtd_rejected(self):
        with self.assertRaises(InputError):
            parse_events('<!DOCTYPE Events [<!ENTITY x "boom">]><Events>&x;</Events>'.encode("utf-16"))

    def test_xml_depth_and_nodes(self):
        for limits in [Limits(xml_depth=2), Limits(xml_nodes=2)]:
            with self.assertRaises(InputError):
                parse_events(make_xml([process(1)]), limits=limits)

    def test_xml_field_limits(self):
        with self.assertRaises(InputError):
            parse_events(make_xml([process(1, command="x" * 5000)]))

    def test_xml_duplicate_data(self):
        data = make_xml([process(1)]).replace(b'</EventData>', b'<Data Name="Image">other</Data></EventData>')
        with self.assertRaises(InputError):
            parse_events(data)

    def test_xml_duplicate_system_field(self):
        data = make_xml([process(1)]).replace(b'</System>', b'<EventID>1</EventID></System>')
        with self.assertRaises(InputError):
            parse_events(data)

    def test_xml_nested_scalar(self):
        data = make_xml([process(1)]).replace(b'<EventID>1</EventID>', b'<EventID><fake>1</fake></EventID>')
        with self.assertRaises(InputError):
            parse_events(data)

    def test_unsupported_and_foreign_counted(self):
        source = make_xml([process(1)])
        unsupported = source.replace(b'<EventID>1</EventID>', b'<EventID>22</EventID>')
        foreign = source.replace(b'Microsoft-Windows-Sysmon', b'Other-Provider')
        self.assertEqual(parse_events(unsupported)[1]["unsupported_events"], 1)
        self.assertEqual(parse_events(foreign)[1]["foreign_provider_events"], 1)

    def test_malformed_xml(self):
        for data in [b'<Events><Event', b'<wrong/>', b'<Events><Event><Event/></Event></Events>']:
            with self.subTest(data=data), self.assertRaises(InputError):
                parse_events(data)

    def test_unknown_namespace(self):
        data = make_xml([process(1)]).replace(b'http://schemas.microsoft.com/win/2004/08/events/event', b'https://example.invalid')
        with self.assertRaises(InputError):
            parse_events(data)

    def test_duplicate_json_key(self):
        with self.assertRaises(InputError):
            parse_events(b'[{"event_id":1,"event_id":3}]')

    def test_nan_and_nested_json(self):
        for data in [b'[NaN]', b'[' * 2000 + b']' * 2000, b'null', b'{}', b'\xff']:
            with self.subTest(size=len(data)), self.assertRaises(InputError):
                parse_events(data)

    def test_json_unknown_labels_rejected(self):
        raw = dict(process(1), expected_malicious=True)
        with self.assertRaises(InputError):
            normalize(raw)

    def test_invalid_fields(self):
        for values in [dict(event_id=True), dict(pid=-1), dict(destination_port=65536), dict(host=""),
                       dict(image=""), dict(process_guid="bad"), dict(parent_process_guid="bad"),
                       dict(timestamp="2026-01-01"), dict(initiated="true"), dict(destination_ip="example.invalid")]:
            with self.subTest(values=values), self.assertRaises(InputError):
                normalize(dict(process(1), **values))

    def test_utc_normalization(self):
        event = normalize(dict(process(1), timestamp="2026-01-01T09:00:00+09:00"))
        self.assertEqual(event.timestamp, "2026-01-01T00:00:00.000000Z")
        self.assertEqual(normalize(dict(process(1), timestamp="2026-01-01 00:00:00")).timestamp, event.timestamp)

    def test_order_and_deduplication(self):
        a, b = process(1), process(2, second=1)
        events, stats = parse_events(json.dumps([b, a, a]).encode())
        self.assertEqual([event.record_id for event in events], [1, 2])
        self.assertEqual(stats["duplicate_events"], 1)

    def test_input_and_count_limits(self):
        for data, limits in [(b'12345', Limits(file_bytes=4)), (json.dumps([process(1), process(2)]).encode(), Limits(events=1))]:
            with self.assertRaises(InputError):
                parse_events(data, limits=limits)

    def test_path_normalization_no_disk_access(self):
        self.assertEqual(windows_path(r"C:/Users/Lab/Temp/../a.exe"), r"c:\users\lab\a.exe")

    def test_empty_json(self):
        self.assertEqual(parse_events(b'[]')[0], [])
