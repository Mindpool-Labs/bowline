import json
import pathlib
import unittest

from integrations.litellm.bowline_callback import serialize_callback_event


class BowlineCallbackContractTest(unittest.TestCase):
    def test_synthetic_callback_matches_the_shipped_content_free_fixture(self):
        callback = {
            "request_id": "req-1",
            "started_at_ms": 1783785600123,
            "model": "shared-model",
            "deployment": "east",
            "status_code": 200,
            "latency_ms": 25,
            "usage": {"prompt_tokens": 10, "completion_tokens": 5},
            "messages": [{"content": "SENSITIVE_SENTINEL"}],
            "metadata": {
                "bowline": {"route": "/v1/responses", "app": "support"},
                "authorization": "SENSITIVE_SENTINEL",
            },
        }

        line = serialize_callback_event(callback)
        fixture = pathlib.Path(__file__).with_name("fixture.jsonl").read_text().strip()

        self.assertEqual(line, fixture)
        self.assertNotIn("SENSITIVE_SENTINEL", line)
        self.assertNotIn("messages", line)
        self.assertNotIn("authorization", line)
        self.assertIsInstance(json.loads(line), dict)


if __name__ == "__main__":
    unittest.main()
