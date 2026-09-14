from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

EVENT_CONTRACT_VERSION = 1
WORKSITE_CONTRACT_VERSION = 1
FORBIDDEN_PUBLIC_KEYS = {
    "survivor_name", "full_name", "phone", "phone_number", "email", "email_address",
    "street_address", "exact_address", "date_of_birth", "dob", "government_id", "ssn"
}
EXPLICIT_WORKSITE_SOURCES = {"request", "assessment", "partner_import", "synthetic"}
PUBLIC_LOCATION_PRECISIONS = {"approximate", "area_only"}


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def stable_fingerprint(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


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
    if not (-180 <= lon <= 180 and -90 <= lat <= 90):
        raise ValueError("Point coordinates outside valid bounds")


def _walk_keys(value: Any, prefix: str = ""):
    if isinstance(value, dict):
        for key, child in value.items():
            path = f"{prefix}.{key}" if prefix else key
            yield key.casefold(), path
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
    if not str(source.get("name") or "").strip():
        raise ValueError("source.name is required")
    if not str(source.get("source_id") or "").strip():
        raise ValueError("source.source_id is required")


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
    if not str(event.get("id") or "").strip():
        raise ValueError("event.id is required")
    source = event.get("source")
    if isinstance(source, str):
        source = {"name": source, "source_id": event.get("id")}
    validate_source(source)
    validate_point_geometry(event.get("geometry"), required=False)
    assert_public_safe(event)


def validate_worksite(worksite: dict[str, Any]) -> None:
    for key in ("id", "title", "work_type", "state", "priority", "area"):
        if not str(worksite.get(key) or "").strip():
            raise ValueError(f"worksite.{key} is required")
    source = worksite.get("source")
    validate_source(source)
    if source.get("type") not in EXPLICIT_WORKSITE_SOURCES:
        raise ValueError("worksite source must represent an explicit request, assessment, partner import or synthetic demo")
    validate_point_geometry(worksite.get("geometry"), required=True)
    assert_public_safe(worksite)
    validate_public_worksite_location(worksite)


def load_jsonl(path: str | Path) -> list[dict[str, Any]]:
    rows = []
    with Path(path).open(encoding="utf-8") as handle:
        for n, line in enumerate(handle, 1):
            if not line.strip():
                continue
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