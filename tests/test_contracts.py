import json
import math
import tempfile
import unittest
from pathlib import Path

from contracts import (
    MAX_JSONL_LINE_CHARS,
    assert_public_safe,
    load_jsonl,
    stable_fingerprint,
    validate_event,
    validate_worksite,
)


class ContractTests(unittest.TestCase):
    def test_fingerprint_is_stable_across_key_order(self):
        self.assertEqual(stable_fingerprint({"a": 1, "b": 2}), stable_fingerprint({"b": 2, "a": 1}))

    def test_public_guard_rejects_direct_pii(self):
        with self.assertRaises(ValueError):
            assert_public_safe({"contact": {"phone": "123"}})

    def event(self):
        return {
            "id": "e1",
            "title": "Flood report",
            "description": "Water rising",
            "kind": "flood",
            "severity": 0.7,
            "confidence": 0.6,
            "source": {"name": "demo", "source_id": "s1", "url": "https://example.org/report/1"},
            "geometry": {"type": "Point", "coordinates": [-3.7, 40.4]},
            "tags": ["flood"],
        }

    def test_event_contract_accepts_bounded_http_source(self):
        validate_event(self.event())

    def test_event_contract_rejects_unsafe_source_scheme(self):
        event = self.event()
        event["source"]["url"] = "javascript:alert(1)"
        with self.assertRaises(ValueError):
            validate_event(event)

    def test_event_contract_rejects_embedded_url_credentials(self):
        event = self.event()
        event["source"]["url"] = "https://user:pass@example.org/report"
        with self.assertRaises(ValueError):
            validate_event(event)

    def test_event_contract_rejects_non_finite_or_out_of_range_scores(self):
        for value in (-0.1, 1.1, math.nan, math.inf):
            event = self.event()
            event["confidence"] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                validate_event(event)

    def test_event_contract_rejects_non_finite_coordinates(self):
        event = self.event()
        event["geometry"]["coordinates"] = [math.inf, 40.4]
        with self.assertRaises(ValueError):
            validate_event(event)

    def test_event_contract_rejects_unbounded_text(self):
        event = self.event()
        event["title"] = "x" * 501
        with self.assertRaises(ValueError):
            validate_event(event)

    def base_worksite(self, source_type="synthetic"):
        return {
            "id": "w1",
            "title": "Cleanup",
            "work_type": "debris_removal",
            "state": "ready",
            "priority": "high",
            "area": "Synthetic",
            "geometry": {"type": "Point", "coordinates": [-3.7, 40.4]},
            "source": {"type": source_type, "name": "demo", "source_id": "s1"},
        }

    def test_worksite_requires_explicit_request_family_source(self):
        base = self.base_worksite()
        validate_worksite(base)
        bad = {**base, "source": {"type": "hazard_inference", "name": "demo", "source_id": "s1"}}
        with self.assertRaises(ValueError):
            validate_worksite(bad)

    def test_real_public_worksite_requires_approximate_location(self):
        real = self.base_worksite("partner_import")
        real["geometry"] = {"type": "Point", "coordinates": [-3.70379, 40.41678]}
        with self.assertRaises(ValueError):
            validate_worksite(real)
        real["location_precision"] = "approximate"
        with self.assertRaises(ValueError):
            validate_worksite(real)
        real["geometry"] = {"type": "Point", "coordinates": [-3.70, 40.42]}
        validate_worksite(real)

    def test_synthetic_worksite_may_keep_exact_demo_location(self):
        demo = self.base_worksite("synthetic")
        demo["geometry"] = {"type": "Point", "coordinates": [-3.70379, 40.41678]}
        validate_worksite(demo)

    def test_jsonl_loader_rejects_oversized_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            path.write_text("x" * (MAX_JSONL_LINE_CHARS + 1), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_jsonl(path)

    def test_jsonl_loader_accepts_normal_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            path.write_text(json.dumps(self.event()) + "\n", encoding="utf-8")
            self.assertEqual(len(load_jsonl(path)), 1)


if __name__ == "__main__":
    unittest.main()
