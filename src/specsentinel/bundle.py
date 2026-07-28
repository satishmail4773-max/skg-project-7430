import hashlib
import hmac
import io
import json
import zipfile
from collections.abc import Iterator

from fastapi import HTTPException

from .models import Artifact


def build_signed_bundle(artifacts: list[Artifact], fingerprint: str, signing_key: str, key_id: str, max_bytes: int) -> bytes:
    if not signing_key:
        raise HTTPException(503, "bundle signing is not configured")
    files = sorted(artifacts, key=lambda item: item.filename)
    manifest = {
        "algorithm": "HMAC-SHA256",
        "key_id": key_id,
        "schema_fingerprint": fingerprint,
        "files": [{"path": item.filename, "sha256": hashlib.sha256(item.content.encode()).hexdigest()} for item in files],
    }
    manifest_bytes = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    signature = hmac.new(signing_key.encode(), manifest_bytes, hashlib.sha256).hexdigest().encode()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for item in files:
            _write_deterministic(archive, item.filename, item.content.encode())
        _write_deterministic(archive, "manifest.json", manifest_bytes)
        _write_deterministic(archive, "manifest.sig", signature)
    data = buffer.getvalue()
    if len(data) > max_bytes:
        raise HTTPException(413, "generated bundle exceeds configured limit")
    return data


def _write_deterministic(archive: zipfile.ZipFile, name: str, content: bytes) -> None:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o100644 << 16
    info.create_system = 3
    archive.writestr(info, content, compresslevel=6)


def chunks(data: bytes, size: int = 64 * 1024) -> Iterator[bytes]:
    for offset in range(0, len(data), size):
        yield data[offset : offset + size]
