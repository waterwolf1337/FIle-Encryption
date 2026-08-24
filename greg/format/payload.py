from __future__ import annotations

import json
import struct
from dataclasses import dataclass, field
from pathlib import PurePath
from typing import Any

METADATA_LENGTH = struct.Struct(">I")
MAX_METADATA_LENGTH = 1_048_576


@dataclass(frozen=True, slots=True)
class GregPayload:
    filename: str
    data: bytes
    metadata: dict[str, Any] = field(default_factory=dict)

    def serialize(self) -> bytes:
        validate_filename(self.filename)
        metadata = {
            "filename": self.filename,
            "extension": PurePath(self.filename).suffix,
            "metadata": self.metadata,
        }
        encoded = json.dumps(
            metadata, ensure_ascii=False, separators=(",", ":"), sort_keys=True
        ).encode("utf-8")
        if len(encoded) > MAX_METADATA_LENGTH:
            raise ValueError("payload metadata is too large")
        return METADATA_LENGTH.pack(len(encoded)) + encoded + self.data

    @classmethod
    def deserialize(cls, raw: bytes) -> "GregPayload":
        if len(raw) < METADATA_LENGTH.size:
            raise ValueError("truncated encrypted payload")
        (metadata_length,) = METADATA_LENGTH.unpack_from(raw)
        if metadata_length > MAX_METADATA_LENGTH:
            raise ValueError("encrypted payload metadata is too large")
        boundary = METADATA_LENGTH.size + metadata_length
        if boundary > len(raw):
            raise ValueError("truncated encrypted payload metadata")
        try:
            parsed = json.loads(raw[METADATA_LENGTH.size:boundary].decode("utf-8"))
            if not isinstance(parsed, dict):
                raise TypeError("metadata root is not an object")
            filename = parsed["filename"]
            extension = parsed["extension"]
            metadata = parsed.get("metadata", {})
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as error:
            raise ValueError("invalid encrypted payload metadata") from error
        if not isinstance(filename, str) or not isinstance(extension, str):
            raise ValueError("invalid encrypted filename metadata")
        validate_filename(filename)
        if extension != PurePath(filename).suffix:
            raise ValueError("inconsistent encrypted extension metadata")
        if not isinstance(metadata, dict):
            raise ValueError("invalid optional metadata")
        return cls(filename=filename, data=raw[boundary:], metadata=metadata)


def validate_filename(filename: str) -> None:
    if (
        not filename
        or filename in {".", ".."}
        or "\x00" in filename
        or "/" in filename
        or "\\" in filename
        or PurePath(filename).name != filename
    ):
        raise ValueError("unsafe original filename")
