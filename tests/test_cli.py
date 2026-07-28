import argparse
import json

from specsentinel.cli import run
from specsentinel.config import Settings


def _write_schema(tmp_path, schema):
    path = tmp_path / "openapi.json"
    path.write_text(json.dumps(schema), encoding="utf-8")
    return path


def test_cli_generate_prints_json(tmp_path, openapi_schema, capsys):
    path = _write_schema(tmp_path, openapi_schema)
    args = argparse.Namespace(command="generate", schema=str(path), base_url=None, targets=["pytest"], policy=None)
    assert run(args, Settings()) == 0
    output = json.loads(capsys.readouterr().out)
    assert output["operation_count"] == 1


def test_cli_diff_returns_nonzero_for_high_risk(tmp_path, openapi_schema, capsys):
    previous = _write_schema(tmp_path, openapi_schema)
    current_schema = json.loads(json.dumps(openapi_schema))
    current_schema["security"] = []
    current = tmp_path / "current.json"
    current.write_text(json.dumps(current_schema), encoding="utf-8")
    args = argparse.Namespace(command="diff", previous=str(previous), current=str(current))
    assert run(args, Settings()) == 2
    assert json.loads(capsys.readouterr().out)["risk_score"] == 35


def test_cli_bundle_refuses_overwrite(tmp_path, openapi_schema):
    schema = _write_schema(tmp_path, openapi_schema)
    output = tmp_path / "bundle.zip"
    args = argparse.Namespace(command="bundle", schema=str(schema), output=str(output), base_url=None, policy=None)
    config = Settings(bundle_signing_key="secret")
    assert run(args, config) == 0
    try:
        run(args, config)
    except ValueError as exc:
        assert "overwrite" in str(exc)
    else:
        raise AssertionError("existing output must not be overwritten")
