from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.config import get_settings
from app.ledger.merkle import (
    snapshot_merkle_proof_json,
    snapshot_merkle_root_json,
    snapshot_merkle_schema_json,
)
from app.ledger.snapshot import ledger_snapshot
from scripts.export_ledger_snapshot import read_only_session_scope


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Export read-only Merkle artifacts for an MRWK ledger snapshot."
    )
    parser.add_argument("--database-url", help="Database URL. Defaults to MERGEWORK_DATABASE_URL.")
    parser.add_argument("--source-host", help="Public source host/origin for snapshot metadata.")
    parser.add_argument(
        "--source-mode",
        default="database",
        help="Source mode label for snapshot metadata. Defaults to database.",
    )
    parser.add_argument(
        "--account",
        help="Snapshot account id to prove. Without this, the script prints the root object.",
    )
    parser.add_argument(
        "--schema",
        action="store_true",
        help="Print the Merkle root/proof JSON Schema instead of a live artifact.",
    )
    args = parser.parse_args(argv)
    if args.schema:
        sys.stdout.write(snapshot_merkle_schema_json())
        return 0

    settings = get_settings()
    database_url = args.database_url or settings.database_url
    source_host = args.source_host if args.source_host is not None else settings.public_base_url
    with read_only_session_scope(database_url) as session:
        snapshot = ledger_snapshot(
            session,
            source_mode=args.source_mode,
            source_host=source_host,
        )
    if args.account:
        sys.stdout.write(snapshot_merkle_proof_json(snapshot, args.account))
    else:
        sys.stdout.write(snapshot_merkle_root_json(snapshot))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
