import hashlib
import hmac
import io
import json
import zipfile

import pytest
from fastapi import HTTPException

from specsentinel.bundle import build_signed_bundle, chunks
from specsentinel.models import Artifact


def test_bundle_is_deterministic_and_signature_verifies():
    artifacts = [Artifact(filename="tests/a.txt", media_type="text/plain", content="hello")]
    first = build_signed_bundle(artifacts, "abc", "secret", "key-1", 10_000)
    second = build_signed_bundle(artifacts, "abc", "secret", "key-1", 10_000)
    assert first == second
    with zipfile.ZipFile(io.BytesIO(first)) as archive:
        manifest = archive.read("manifest.json")
        signature = archive.read("manifest.sig").decode()
        assert hmac.compare_digest(signature, hmac.new(b"secret", manifest, hashlib.sha256).hexdigest())
        assert json.loads(manifest)["files"][0]["sha256"] == hashlib.sha256(b"hello").hexdigest()


def test_bundle_requires_key_and_enforces_output_limit():
    artifact = [Artifact(filename="a", media_type="text/plain", content="x" * 100)]
    with pytest.raises(HTTPException) as missing:
        build_signed_bundle(artifact, "abc", "", "default", 10_000)
    assert missing.value.status_code == 503
    with pytest.raises(HTTPException) as large:
        build_signed_bundle(artifact, "abc", "secret", "default", 10)
    assert large.value.status_code == 413


def test_chunks_reassembles_bytes():
    data = b"abcdefgh"
    assert b"".join(chunks(data, 3)) == data

