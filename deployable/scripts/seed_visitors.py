import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import Any

import boto3


def load_visitors(path: Path) -> list[dict[str, Any]]:
    visitors = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(visitors, list):
        raise ValueError("Visitor file must contain a JSON array.")
    for visitor in visitors:
        if not isinstance(visitor, dict):
            raise ValueError("Each visitor entry must be a JSON object.")
        if not all(isinstance(visitor.get(key), str) and visitor[key].strip() for key in ("visitor_id", "name")):
            raise ValueError("Each visitor needs non-empty string visitor_id and name fields.")
        for key in ("valid_from", "valid_until"):
            value = visitor.get(key)
            if value is not None:
                if not isinstance(value, str):
                    raise ValueError(f"{key} must be an ISO-8601 timestamp string.")
                datetime.fromisoformat(value.replace("Z", "+00:00"))
        if visitor.get("status", "ACTIVE") not in {"ACTIVE", "INACTIVE"}:
            raise ValueError("status must be ACTIVE or INACTIVE.")
    return visitors


def main() -> None:
    parser = argparse.ArgumentParser(description="Add or update DeskPass site visitor records.")
    parser.add_argument("--table", required=True, help="VisitorsTable name from the SAM stack outputs.")
    parser.add_argument("--site-id", required=True, help="The deployed stack's SiteId parameter.")
    parser.add_argument("--file", required=True, type=Path, help="Local JSON file; do not commit real visitor data.")
    args = parser.parse_args()

    table = boto3.resource("dynamodb").Table(args.table)
    visitors = load_visitors(args.file)
    for visitor in visitors:
        item = {
            "site_id": args.site_id,
            "visitor_id": visitor["visitor_id"].strip(),
            "name": visitor["name"].strip(),
            "status": visitor.get("status", "ACTIVE"),
        }
        for key in ("valid_from", "valid_until"):
            if visitor.get(key):
                item[key] = visitor[key]
        if visitor.get("company"):
            item["company"] = visitor["company"]
        table.put_item(Item=item)
    print(f"Loaded {len(visitors)} visitor record(s).")


if __name__ == "__main__":
    main()
