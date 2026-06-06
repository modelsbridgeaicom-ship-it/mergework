from __future__ import annotations

import copy
import json
from datetime import UTC, datetime

import pytest

from app.db import create_schema, session_scope
from app.ledger.merkle import (
    SNAPSHOT_MERKLE_PROOF_SCHEMA,
    SNAPSHOT_MERKLE_ROOT_SCHEMA,
    SnapshotMerkleError,
    snapshot_merkle_proof,
    snapshot_merkle_proof_json,
    snapshot_merkle_root,
    snapshot_merkle_root_json,
    snapshot_merkle_schema_json,
    verify_snapshot_merkle_proof,
)
from app.ledger.service import GENESIS_SUPPLY_MICRO, TREASURY_ACCOUNT, create_bounty, ensure_genesis
from app.ledger.snapshot import ledger_snapshot
from scripts.export_snapshot_merkle import main as export_snapshot_merkle_main


def test_snapshot_merkle_root_handles_empty_tree(sqlite_url: str) -> None:
    create_schema(sqlite_url)

    with session_scope(sqlite_url) as session:
        snapshot = ledger_snapshot(session, generated_at=datetime(2026, 6, 7, tzinfo=UTC))

    root = snapshot_merkle_root(snapshot)

    assert root["schema"] == SNAPSHOT_MERKLE_ROOT_SCHEMA
    assert root["ledger_anchor"] == {"latest_sequence": 0, "latest_entry_hash": None}
    assert root["tree_size"] == 0
    assert len(root["account_tree_hash"]) == 64
    assert len(root["root_hash"]) == 64
    assert snapshot_merkle_root(snapshot) == root
    with pytest.raises(SnapshotMerkleError, match="account is not present"):
        snapshot_merkle_proof(snapshot, TREASURY_ACCOUNT)


def test_snapshot_merkle_single_account_proof_verifies(sqlite_url: str) -> None:
    create_schema(sqlite_url)

    with session_scope(sqlite_url) as session:
        ensure_genesis(session)
        snapshot = ledger_snapshot(session, generated_at=datetime(2026, 6, 7, tzinfo=UTC))

    proof = snapshot_merkle_proof(snapshot, TREASURY_ACCOUNT)

    assert proof["schema"] == SNAPSHOT_MERKLE_PROOF_SCHEMA
    assert proof["leaf_index"] == 0
    assert proof["siblings"] == []
    assert proof["leaf"] == {
        "schema": "mergework.ledger_snapshot_account_leaf.v1",
        "schema_version": 1,
        "snapshot_schema": "mergework.ledger_snapshot.v1",
        "snapshot_schema_version": 1,
        "account": TREASURY_ACCOUNT,
        "balance_microunits": GENESIS_SUPPLY_MICRO,
    }
    assert verify_snapshot_merkle_proof(proof)
    assert verify_snapshot_merkle_proof(proof, proof["root"])


def test_snapshot_merkle_root_ignores_generated_and_source_metadata(sqlite_url: str) -> None:
    create_schema(sqlite_url)

    with session_scope(sqlite_url) as session:
        ensure_genesis(session)
        create_bounty(
            session,
            repo="ramimbo/mergework",
            issue_number=1027,
            issue_url="https://github.com/ramimbo/mergework/issues/1027",
            title="Snapshot Merkle proofs",
            reward_mrwk="450",
            max_awards=1,
            acceptance="Read-only snapshot Merkle proof tooling.",
        )
        first = ledger_snapshot(
            session,
            generated_at=datetime(2026, 6, 7, 1, 0, tzinfo=UTC),
            source_mode="database",
            source_host="https://mrwk.example",
        )
        second = ledger_snapshot(
            session,
            generated_at=datetime(2026, 6, 7, 2, 0, tzinfo=UTC),
            source_mode="fixture",
            source_host="https://other.example",
        )

    first_root = snapshot_merkle_root(first)
    second_root = snapshot_merkle_root(second)

    assert first["generated_at"] != second["generated_at"]
    assert first["source"] != second["source"]
    assert first_root == second_root


def test_snapshot_merkle_multi_account_proof_verifies(sqlite_url: str) -> None:
    create_schema(sqlite_url)

    with session_scope(sqlite_url) as session:
        ensure_genesis(session)
        create_bounty(
            session,
            repo="ramimbo/mergework",
            issue_number=1027,
            issue_url="https://github.com/ramimbo/mergework/issues/1027",
            title="Snapshot Merkle proofs",
            reward_mrwk="450",
            max_awards=1,
            acceptance="Read-only snapshot Merkle proof tooling.",
        )
        create_bounty(
            session,
            repo="ramimbo/mergework",
            issue_number=1028,
            issue_url="https://github.com/ramimbo/mergework/issues/1028",
            title="Snapshot Merkle proof fixtures",
            reward_mrwk="10",
            max_awards=1,
            acceptance="Read-only snapshot Merkle proof fixture.",
        )
        snapshot = ledger_snapshot(session, generated_at=datetime(2026, 6, 7, tzinfo=UTC))

    proof = snapshot_merkle_proof(snapshot, "reserve:bounty:1")

    assert proof["leaf"] == {
        "schema": "mergework.ledger_snapshot_account_leaf.v1",
        "schema_version": 1,
        "snapshot_schema": "mergework.ledger_snapshot.v1",
        "snapshot_schema_version": 1,
        "account": "reserve:bounty:1",
        "balance_microunits": 450_000_000,
    }
    assert len(proof["siblings"]) == 2
    assert verify_snapshot_merkle_proof(proof)
    assert json.loads(snapshot_merkle_proof_json(snapshot, "reserve:bounty:1")) == proof
    assert json.loads(snapshot_merkle_root_json(snapshot)) == proof["root"]


def test_snapshot_merkle_verification_rejects_tampering(sqlite_url: str) -> None:
    create_schema(sqlite_url)

    with session_scope(sqlite_url) as session:
        ensure_genesis(session)
        create_bounty(
            session,
            repo="ramimbo/mergework",
            issue_number=1027,
            issue_url="https://github.com/ramimbo/mergework/issues/1027",
            title="Snapshot Merkle proofs",
            reward_mrwk="450",
            max_awards=1,
            acceptance="Read-only snapshot Merkle proof tooling.",
        )
        snapshot = ledger_snapshot(session, generated_at=datetime(2026, 6, 7, tzinfo=UTC))

    proof = snapshot_merkle_proof(snapshot, TREASURY_ACCOUNT)

    tampered_account = copy.deepcopy(proof)
    tampered_account["leaf"]["account"] = "github:mallory"
    assert not verify_snapshot_merkle_proof(tampered_account)

    tampered_balance = copy.deepcopy(proof)
    tampered_balance["leaf"]["balance_microunits"] -= 1
    assert not verify_snapshot_merkle_proof(tampered_balance)

    tampered_leaf_index = copy.deepcopy(proof)
    tampered_leaf_index["leaf_index"] = 0
    assert not verify_snapshot_merkle_proof(tampered_leaf_index)

    tampered_sibling_hash = copy.deepcopy(proof)
    tampered_sibling_hash["siblings"][0]["hash"] = "0" * 64
    assert not verify_snapshot_merkle_proof(tampered_sibling_hash)

    tampered_direction = copy.deepcopy(proof)
    tampered_direction["siblings"][0]["direction"] = (
        "right" if proof["siblings"][0]["direction"] == "left" else "left"
    )
    assert not verify_snapshot_merkle_proof(tampered_direction)

    tampered_tree_size = copy.deepcopy(proof)
    tampered_tree_size["root"]["tree_size"] += 1
    assert not verify_snapshot_merkle_proof(tampered_tree_size)

    tampered_root_hash = copy.deepcopy(proof)
    tampered_root_hash["root"]["root_hash"] = "0" * 64
    assert not verify_snapshot_merkle_proof(tampered_root_hash)

    tampered_anchor = copy.deepcopy(proof)
    tampered_anchor["root"]["ledger_anchor"]["latest_sequence"] += 1
    assert not verify_snapshot_merkle_proof(tampered_anchor)

    extra_proof_field = copy.deepcopy(proof)
    extra_proof_field["unexpected"] = True
    assert not verify_snapshot_merkle_proof(extra_proof_field)

    extra_root_field = copy.deepcopy(proof)
    extra_root_field["root"]["unexpected"] = True
    assert not verify_snapshot_merkle_proof(extra_root_field)

    extra_leaf_field = copy.deepcopy(proof)
    extra_leaf_field["leaf"]["unexpected"] = True
    assert not verify_snapshot_merkle_proof(extra_leaf_field)

    extra_sibling_field = copy.deepcopy(proof)
    extra_sibling_field["siblings"][0]["unexpected"] = True
    assert not verify_snapshot_merkle_proof(extra_sibling_field)


def test_snapshot_merkle_script_outputs_root_proof_and_schema(sqlite_url: str, capsys) -> None:
    create_schema(sqlite_url)

    with session_scope(sqlite_url) as session:
        ensure_genesis(session)

    assert export_snapshot_merkle_main(["--schema"]) == 0
    schema = json.loads(capsys.readouterr().out)
    assert schema["$id"] == "mergework.ledger_snapshot_merkle.v1"

    assert export_snapshot_merkle_main(["--database-url", sqlite_url]) == 0
    root = json.loads(capsys.readouterr().out)
    assert root["schema"] == SNAPSHOT_MERKLE_ROOT_SCHEMA
    assert root["tree_size"] == 1

    assert (
        export_snapshot_merkle_main(["--database-url", sqlite_url, "--account", TREASURY_ACCOUNT])
        == 0
    )
    proof = json.loads(capsys.readouterr().out)
    assert proof["schema"] == SNAPSHOT_MERKLE_PROOF_SCHEMA
    assert verify_snapshot_merkle_proof(proof, root)


def test_snapshot_merkle_schema_is_deterministic_json() -> None:
    assert snapshot_merkle_schema_json() == snapshot_merkle_schema_json()
