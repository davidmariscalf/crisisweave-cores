import unittest

from contracts import assert_public_safe, stable_fingerprint, validate_event, validate_worksite


class ContractTests(unittest.TestCase):
    def test_fingerprint_is_stable_across_key_order(self):
        self.assertEqual(stable_fingerprint({"a":1,"b":2}), stable_fingerprint({"b":2,"a":1}))

    def test_public_guard_rejects_direct_pii(self):
        with self.assertRaises(ValueError):
            assert_public_safe({"contact":{"phone":"123"}})

    def test_event_contract_accepts_point(self):
        validate_event({"id":"e1","source":{"name":"demo","source_id":"s1"},"geometry":{"type":"Point","coordinates":[-3.7,40.4]}})

    def test_worksite_requires_explicit_request_family_source(self):
        base={"id":"w1","title":"Cleanup","work_type":"debris_removal","state":"ready","priority":"high","area":"Synthetic","geometry":{"type":"Point","coordinates":[-3.7,40.4]},"source":{"type":"synthetic","name":"demo","source_id":"s1"}}
        validate_worksite(base)
        bad={**base,"source":{"type":"hazard_inference","name":"demo","source_id":"s1"}}
        with self.assertRaises(ValueError): validate_worksite(bad)


if __name__=="__main__": unittest.main()
