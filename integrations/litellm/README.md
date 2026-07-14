# LiteLLM callback output contract

`bowline_callback.py` is a Bowline-defined, content-free serializer for an operator-configured
LiteLLM callback. It is not a parser for arbitrary LiteLLM logs. The serializer emits only the
scalar fields named by `profile.yaml`; prompts, messages, headers, credentials, request bodies, and
response bodies are omitted.

Run the synthetic contract test from the Bowline repository root:

```sh
python3 -m unittest integrations/litellm/test_bowline_callback.py -v
```

The LiteLLM serializer is tested only against Bowline synthetic callback objects. This is an exact
serializer-output contract, not a live LiteLLM integration test or compatibility claim for native,
internal, or version-specific LiteLLM logs.

The pointer denylist cannot detect a secret or content value deliberately aliased under an
innocuous field name. The operator remains responsible for wiring the callback and keeping such
metadata fields free of secrets or content.
