"""Bowline-defined, content-free LiteLLM callback output contract."""

import json


def serialize_callback_event(callback):
    """Serialize only the reviewed scalar evidence contract as one JSON line."""
    event = {
        "request_id": callback["request_id"],
        "started_at_ms": callback["started_at_ms"],
        "route": callback["metadata"]["bowline"]["route"],
        "model": callback.get("model"),
        "deployment": callback.get("deployment"),
        "status_code": callback["status_code"],
        "latency_ms": callback["latency_ms"],
        "usage": {
            "prompt_tokens": callback.get("usage", {}).get("prompt_tokens"),
            "completion_tokens": callback.get("usage", {}).get("completion_tokens"),
        },
        "metadata": {
            "app": callback.get("metadata", {}).get("bowline", {}).get("app"),
        },
    }
    return json.dumps(event, sort_keys=True, separators=(",", ":"))
