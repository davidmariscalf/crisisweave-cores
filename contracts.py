from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

EVENT_CONTRACT_VERSION = 1
WORKSITE_CONTRACT_VERSION = 1
FORBIDDEN_PUBLIC_KEYS = {
    "survivor_name", "full_name", "phone", "phone_number", "email", "email_address",
    "street_address", "exact_address", "date_of_birth", "dob", "government_id", "ssn"
}
EXPLICIT_WORKSITE_SOURCES = {"request", "assessment", "partner_import", "synthetic"}
PUBLIC_LOCATION_PRECISIONS = {"approximate", "area_only"}
MAX_JSONL_BYTES = 64 * 1024 * 1024
MAX_JSONL_RECORDS = 100_000
MAX_JSONL_LINE_CHARS = 2 * 1024 * 1024
MAX_URL_CHARS = 2048


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def stable_fingerprint(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _bounded_text(value: Any, field: str, *, required: bool = False, max_chars: int = 500) -> str:
    text = str(value or "").strip()
    if required and not text:
        raise ValueError(f"{field} is required")
    if len(text) > max_chars:
        raise ValueError(f"{field} exceeds {max_chars} characters")
    return text


def _unit_interval(value: Any, field: str) -> None:
    if value is None:
        return
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise ValueError(f"{field} must be numeric") from None
    if not math.isfinite(number) or not 0.0 <= number <= 1.0:
        raise ValueError(f"{field} must be finite and between 0 and 1")


def validate_point_geometry(geometry: Any, *, required: bool = False) -> None:
    if geometry is None and not required:
        return
    if not isinstance(geometry, dict) or geometry.get("type") != "Point":
        raise ValueError("geometry must be a GeoJSON Point")
    coords = geometry.get("coordinates")
    if not isinstance(coords, list) or len(coords) != 2:
        raise ValueError("Point coordinates must be [longitude, latitude]")
    try:
        lon, lat = float(coords[0]), float(coords[1])
    except (TypeError, ValueError):
        raise ValueError("Point coordinates must be numeric") from None
    if not math.isfinite(lon) or not math.isfinite(lat):
        raise ValueError("Point coordinates must be finite")
    if not (-180 <= lon <= 180 and -90 <= lat <= 90):
        raise ValueError("Point coordinates outside valid bounds")


def _walk_keys(value: Any, prefix: str = ""):
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else str(key)
            yield str(key).casefold(), path
            yield from _walk_keys(child, path)
    elif isinstance(value, list):
        for i, child in enumerate(value):
            yield from _walk_keys(child, f"{prefix}[{i}]")


def assert_public_safe(value: Any) -> None:
    found = [path for key, path in _walk_keys(value) if key in FORBIDDEN_PUBLIC_KEYS]
    if found:
        raise ValueError("direct PII fields are not allowed in the public contract: " + ", ".join(found))


def validate_source(source: Any) -> None:
    if not isinstance(source, dict):
        raise ValueError("source must be an object")
    _bounded_text(source.get("name"), "source.name", required=True, max_chars=300)
    _bounded_text(source.get("source_id"), "source.source_id", required=True, max_chars=512)
    source_type = source.get("type")
    if source_type is not None:
        _bounded_text(source_type, "source.type", max_chars=64)
    raw_url = source.get("url")
    if raw_url not in (None, ""):
        url = _bounded_text(raw_url, "source.url", max_chars=MAX_URL_CHARS)
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("source.url must be an absolute http(s) URL")
        if parsed.username or parsed.password:
            raise ValueError("source.url must not contain embedded credentials")


def _is_two_decimal_point(geometry: dict[str, Any]) -> bool:
    lon, lat = geometry["coordinates"]
    return abs(float(lon) - round(float(lon), 2)) < 1e-9 and abs(float(lat) - round(float(lat), 2)) < 1e-9


def validate_public_worksite_location(worksite: dict[str, Any]) -> None:
    source = worksite.get("source") or {}
    if source.get("type") == "synthetic":
        return
    precision = worksite.get("location_precision")
    if precision not in PUBLIC_LOCATION_PRECISIONS:
        raise ValueError("non-synthetic public worksites must declare approximate or area_only location_precision")
    if precision == "approximate" and not _is_two_decimal_point(worksite["geometry"]):
        raise ValueError("approximate public worksite coordinates must be rounded to at most two decimal places")


def validate_event(event: dict[str, Any]) -> None:
    if not isinstance(event, dict):
        raise ValueError("event must be an object")
    _bounded_text(event.get("id"), "event.id", required=True, max_chars=256)
    _bounded_text(event.get("kind"), "event.kind", max_chars=64)
    _bounded_text(event.get("title"), "event.title", max_chars=500)
    _bounded_text(event.get("description"), "event.description", max_chars=20_000)
    _bounded_text(event.get("area"), "event.area", max_chars=1000)
    _bounded_text(event.get("observed_at"), "event.observed_at", max_chars=128)
    _bounded_text(event.get("expires_at"), "event.expires_at", max_chars=128)
    _unit_interval(event.get("severity"), "event.severity")
    _unit_interval(event.get("confidence"), "event.confidence")

    source = event.get("source")
    if isinstance(source, str):
        source = {"name": source, "source_id": event.get("id")}
    validate_source(source)
    validate_point_geometry(event.get("geometry"), required=False)

    tags = event.get("tags")
    if tags is not None:
        if not isinstance(tags, list) or len(tags) > 64:
            raise ValueError("event.tags must be a list with at most 64 entries")
        for index, tag in enumerate(tags):
            _bounded_text(tag, f"event.tags[{index}]", required=True, max_chars=64)

    evidence = event.get("evidence")
    if evidence is not None and (not isinstance(evidence, list) or len(evidence) > 100):
        raise ValueError("event.evidence must be a list with at most 100 entries")

    assert_public_safe(event)


def validate_worksite(worksite: dict[str, Any]) -> None:
    if not isinstance(worksite, dict):
        raise ValueError("worksite must be an object")
    for key, limit in (
        ("id", 256), ("title", 500), ("work_type", 64), ("state", 64),
        ("priority", 64), ("area", 1000),
    ):
        _bounded_text(worksite.get(key), f"worksite.{key}", required=True, max_chars=limit)
    _bounded_text(worksite.get("description"), "worksite.description", max_chars=20_000)
    _bounded_text(worksite.get("coordinator_instructions"), "worksite.coordinator_instructions", max_chars=20_000)

    source = worksite.get("source")
    validate_source(source)
    if source.get("type") not in EXPLICIT_WORKSITE_SOURCES:
        raise ValueError("worksite source must represent an explicit request, assessment, partner import or synthetic demo")
    validate_point_geometry(worksite.get("geometry"), required=True)
    assert_public_safe(worksite)
    validate_public_worksite_location(worksite)


def load_jsonl(path: str | Path) -> list[dict[str, Any]]:
    path = Path(path)
    size = path.stat().st_size
    if size > MAX_JSONL_BYTES:
        raise ValueError(f"JSONL file exceeds {MAX_JSONL_BYTES} bytes")
    rows = []
    with path.open(encoding="utf-8") as handle:
        for n, line in enumerate(handle, 1):
            if len(line) > MAX_JSONL_LINE_CHARS:
                raise ValueError(f"line {n} exceeds {MAX_JSONL_LINE_CHARS} characters")
            if not line.strip():
                continue
            if len(rows) >= MAX_JSONL_RECORDS:
                raise ValueError(f"JSONL file exceeds {MAX_JSONL_RECORDS} records")
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"line {n} must contain a JSON object")
            rows.append(value)
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description="Check CrisisWeave public JSONL contracts")
    sub = parser.add_subparsers(dest="cmd", required=True)
    check = sub.add_parser("check")
    check.add_argument("--kind", choices=("event", "worksite"), required=True)
    check.add_argument("path")
    args = parser.parse_args()
    rows = load_jsonl(args.path)
    validator = validate_event if args.kind == "event" else validate_worksite
    for index, row in enumerate(rows, 1):
        try:
            validator(row)
        except Exception as exc:
            raise SystemExit(f"{args.path}:{index}: {exc}") from exc
    print(json.dumps({"ok": True, "kind": args.kind, "records": len(rows)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
