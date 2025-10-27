from djinn.core.cli_handlers.filter_reward_deltas import _parse_json_response


def test_parse_json_response_handles_markdown_fence():
    content = """```json
{
  "filtered": [{"id": "sample-1"}],
  "notes": "OK"
}
```"""
    result = _parse_json_response(content)
    assert result["filtered"] == [{"id": "sample-1"}]
    assert result["notes"] == "OK"


def test_parse_json_response_ignores_trailing_text():
    content = """{
  "filtered": [],
  "notes": "All good"
}
Additional commentary that should not break parsing."""
    result = _parse_json_response(content)
    assert result["filtered"] == []
    assert result["notes"] == "All good"


def test_parse_json_response_fallback_on_invalid_json():
    content = """```json
{
  "filtered": [],
  "notes": "Missing closing quote
"""
    result = _parse_json_response(content)
    assert result["filtered"] == []
    assert result["notes"].startswith("Model response was not valid JSON:")
    assert "```json" in result["notes"]


def test_parse_json_response_defaults_filtered_list():
    content = """{
  "notes": "Only notes provided."
}"""
    result = _parse_json_response(content)
    assert result["filtered"] == []
    assert result["notes"] == "Only notes provided."
