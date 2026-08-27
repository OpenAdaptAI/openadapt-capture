#!/usr/bin/env python3
"""Read the closed output of one structural qualification fixture producer."""

from __future__ import annotations

import argparse
import uuid
from pathlib import Path

OUTPUT_FIELDS = frozenset(
    {"structural_fixture_path", "structural_fixture_instance_uuid"}
)


class FixtureOutputError(ValueError):
    """The fixture producer output is incomplete or ambiguous."""


def read_fixture_output(path: Path) -> dict[str, str]:
    """Return the two exact producer outputs from a bounded UTF-8 file."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise FixtureOutputError(f"fixture output is unreadable: {exc}") from exc
    if len(raw) > 64 * 1024:
        raise FixtureOutputError("fixture output exceeds 64 KiB")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FixtureOutputError("fixture output is not UTF-8") from exc
    values: dict[str, str] = {}
    for line in text.splitlines():
        if not line or "=" not in line:
            raise FixtureOutputError("fixture output has an invalid line")
        key, value = line.split("=", 1)
        if key not in OUTPUT_FIELDS or key in values or not value:
            raise FixtureOutputError("fixture output has an unknown or repeated field")
        values[key] = value
    if set(values) != OUTPUT_FIELDS:
        raise FixtureOutputError("fixture output does not contain the exact field set")
    fixture_path = Path(values["structural_fixture_path"])
    if not fixture_path.is_absolute():
        raise FixtureOutputError("structural fixture path is not absolute")
    instance_uuid = values["structural_fixture_instance_uuid"]
    try:
        parsed = uuid.UUID(instance_uuid)
    except ValueError as exc:
        raise FixtureOutputError("fixture instance UUID is invalid") from exc
    if str(parsed) != instance_uuid:
        raise FixtureOutputError("fixture instance UUID is not canonical")
    return values


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path)
    parser.add_argument("--field", choices=sorted(OUTPUT_FIELDS), required=True)
    args = parser.parse_args()
    try:
        value = read_fixture_output(args.path)
    except FixtureOutputError as exc:
        parser.error(str(exc))
    print(value[args.field])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
