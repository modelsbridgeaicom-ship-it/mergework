from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Literal, cast

from app.ledger.service import canonical_json
from app.ledger.snapshot import LEDGER_SNAPSHOT_SCHEMA, LEDGER_SNAPSHOT_SCHEMA_VERSION

SNAPSHOT_MERKLE_ROOT_SCHEMA = "mergework.ledger_snapshot_merkle_root.v1"
SNAPSHOT_MERKLE_PROOF_SCHEMA = "mergework.ledger_snapshot_account_proof.v1"
SNAPSHOT_MERKLE_LEAF_SCHEMA = "mergework.ledger_snapshot_account_leaf.v1"
SNAPSHOT_MERKLE_NODE_SCHEMA = "mergework.ledger_snapshot_merkle_node.v1"
SNAPSHOT_MERKLE_EMPTY_SCHEMA = "mergework.ledger_snapshot_merkle_empty.v1"
SNAPSHOT_MERKLE_ROOT_HASH_SCHEMA = "mergework.ledger_snapshot_merkle_root_hash.v1"
SNAPSHOT_MERKLE_SCHEMA_VERSION = 1
SNAPSHOT_MERKLE_HASH_ALGORITHM = "sha256"


class SnapshotMerkleError(ValueError):
    pass


@dataclass(frozen=True)
class SnapshotAccountBalance:
    account: str
    balance_microunits: int


@dataclass(frozen=True)
class ProofSibling:
    direction: Literal["left", "right"]
    digest: str


SNAPSHOT_MERKLE_JSON_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "mergework.ledger_snapshot_merkle.v1",
    "oneOf": [
        {"$ref": "#/$defs/root"},
        {"$ref": "#/$defs/proof"},
    ],
    "$defs": {
        "anchor": {
            "type": "object",
            "required": ["latest_sequence", "latest_entry_hash"],
            "properties": {
                "latest_sequence": {"type": "integer", "minimum": 0},
                "latest_entry_hash": {
                    "anyOf": [
                        {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                        {"type": "null"},
                    ]
                },
            },
            "additionalProperties": False,
        },
        "leaf": {
            "type": "object",
            "required": [
                "schema",
                "schema_version",
                "snapshot_schema",
                "snapshot_schema_version",
                "account",
                "balance_microunits",
            ],
            "properties": {
                "schema": {"const": SNAPSHOT_MERKLE_LEAF_SCHEMA},
                "schema_version": {"const": SNAPSHOT_MERKLE_SCHEMA_VERSION},
                "snapshot_schema": {"const": LEDGER_SNAPSHOT_SCHEMA},
                "snapshot_schema_version": {"const": LEDGER_SNAPSHOT_SCHEMA_VERSION},
                "account": {"type": "string"},
                "balance_microunits": {"type": "integer"},
            },
            "additionalProperties": False,
        },
        "root": {
            "type": "object",
            "required": [
                "schema",
                "schema_version",
                "snapshot_schema",
                "snapshot_schema_version",
                "hash_algorithm",
                "leaf_schema",
                "node_schema",
                "ledger_anchor",
                "tree_size",
                "account_tree_hash",
                "root_hash",
            ],
            "properties": {
                "schema": {"const": SNAPSHOT_MERKLE_ROOT_SCHEMA},
                "schema_version": {"const": SNAPSHOT_MERKLE_SCHEMA_VERSION},
                "snapshot_schema": {"const": LEDGER_SNAPSHOT_SCHEMA},
                "snapshot_schema_version": {"const": LEDGER_SNAPSHOT_SCHEMA_VERSION},
                "hash_algorithm": {"const": SNAPSHOT_MERKLE_HASH_ALGORITHM},
                "leaf_schema": {"const": SNAPSHOT_MERKLE_LEAF_SCHEMA},
                "node_schema": {"const": SNAPSHOT_MERKLE_NODE_SCHEMA},
                "ledger_anchor": {"$ref": "#/$defs/anchor"},
                "tree_size": {"type": "integer", "minimum": 0},
                "account_tree_hash": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                "root_hash": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            },
            "additionalProperties": False,
        },
        "sibling": {
            "type": "object",
            "required": ["direction", "hash"],
            "properties": {
                "direction": {"enum": ["left", "right"]},
                "hash": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            },
            "additionalProperties": False,
        },
        "proof": {
            "type": "object",
            "required": ["schema", "schema_version", "root", "leaf", "leaf_index", "siblings"],
            "properties": {
                "schema": {"const": SNAPSHOT_MERKLE_PROOF_SCHEMA},
                "schema_version": {"const": SNAPSHOT_MERKLE_SCHEMA_VERSION},
                "root": {"$ref": "#/$defs/root"},
                "leaf": {"$ref": "#/$defs/leaf"},
                "leaf_index": {"type": "integer", "minimum": 0},
                "siblings": {
                    "type": "array",
                    "items": {"$ref": "#/$defs/sibling"},
                },
            },
            "additionalProperties": False,
        },
    },
}


def snapshot_merkle_root(snapshot: dict[str, Any]) -> dict[str, Any]:
    accounts = _snapshot_accounts(snapshot)
    account_tree_hash = _account_tree_hash(accounts)
    root = {
        "schema": SNAPSHOT_MERKLE_ROOT_SCHEMA,
        "schema_version": SNAPSHOT_MERKLE_SCHEMA_VERSION,
        "snapshot_schema": LEDGER_SNAPSHOT_SCHEMA,
        "snapshot_schema_version": LEDGER_SNAPSHOT_SCHEMA_VERSION,
        "hash_algorithm": SNAPSHOT_MERKLE_HASH_ALGORITHM,
        "leaf_schema": SNAPSHOT_MERKLE_LEAF_SCHEMA,
        "node_schema": SNAPSHOT_MERKLE_NODE_SCHEMA,
        "ledger_anchor": _snapshot_ledger_anchor(snapshot),
        "tree_size": len(accounts),
        "account_tree_hash": account_tree_hash,
    }
    root["root_hash"] = _root_binding_hash(root)
    return root


def snapshot_merkle_proof(snapshot: dict[str, Any], account: str) -> dict[str, Any]:
    if not isinstance(account, str) or not account:
        raise SnapshotMerkleError("account must be a non-empty string")
    accounts = _snapshot_accounts(snapshot)
    index_by_account = {row.account: index for index, row in enumerate(accounts)}
    if account not in index_by_account:
        raise SnapshotMerkleError("account is not present in snapshot")
    leaf_index = index_by_account[account]
    leaf_hashes = [_account_leaf_hash(row) for row in accounts]
    levels = _hash_levels(leaf_hashes)
    siblings: list[dict[str, str]] = []
    node_index = leaf_index
    for level in levels[:-1]:
        if node_index % 2 == 0:
            sibling_index = node_index + 1 if node_index + 1 < len(level) else node_index
            siblings.append({"direction": "right", "hash": level[sibling_index]})
        else:
            sibling_index = node_index - 1
            siblings.append({"direction": "left", "hash": level[sibling_index]})
        node_index //= 2
    return {
        "schema": SNAPSHOT_MERKLE_PROOF_SCHEMA,
        "schema_version": SNAPSHOT_MERKLE_SCHEMA_VERSION,
        "root": snapshot_merkle_root(snapshot),
        "leaf": _account_leaf_object(accounts[leaf_index]),
        "leaf_index": leaf_index,
        "siblings": siblings,
    }


def verify_snapshot_merkle_proof(
    proof: dict[str, Any],
    root: dict[str, Any] | None = None,
) -> bool:
    try:
        _require_keys(
            proof, {"schema", "schema_version", "root", "leaf", "leaf_index", "siblings"}, "proof"
        )
        proof_root = _normalize_root(_require_dict(proof.get("root"), "root"))
        expected_root = proof_root if root is None else _normalize_root(root)
        if proof_root != expected_root:
            return False
        if proof.get("schema") != SNAPSHOT_MERKLE_PROOF_SCHEMA:
            return False
        if proof.get("schema_version") != SNAPSHOT_MERKLE_SCHEMA_VERSION:
            return False
        leaf = _normalize_leaf(_require_dict(proof.get("leaf"), "leaf"))
        leaf_index = _require_int(proof.get("leaf_index"), "leaf_index", minimum=0)
        siblings = _normalize_siblings(proof.get("siblings"))
        if expected_root["tree_size"] <= 0:
            return False
        if leaf_index >= expected_root["tree_size"]:
            return False
        if len(siblings) != _expected_proof_length(expected_root["tree_size"]):
            return False
        if expected_root["root_hash"] != _root_binding_hash(expected_root):
            return False

        computed = _account_leaf_hash(leaf)
        level_size = expected_root["tree_size"]
        node_index = leaf_index
        for sibling in siblings:
            if level_size <= 1:
                return False
            if sibling.direction == "right":
                if node_index % 2 != 0:
                    return False
                if node_index + 1 >= level_size and sibling.digest != computed:
                    return False
                computed = _internal_node_hash(computed, sibling.digest)
            else:
                if node_index % 2 != 1:
                    return False
                computed = _internal_node_hash(sibling.digest, computed)
            node_index //= 2
            level_size = (level_size + 1) // 2
        return (
            node_index == 0 and level_size == 1 and computed == expected_root["account_tree_hash"]
        )
    except SnapshotMerkleError:
        return False


def snapshot_merkle_root_json(snapshot: dict[str, Any]) -> str:
    return canonical_json(snapshot_merkle_root(snapshot)) + "\n"


def snapshot_merkle_proof_json(snapshot: dict[str, Any], account: str) -> str:
    return canonical_json(snapshot_merkle_proof(snapshot, account)) + "\n"


def snapshot_merkle_schema_json() -> str:
    return (
        json.dumps(
            SNAPSHOT_MERKLE_JSON_SCHEMA,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        + "\n"
    )


def _snapshot_accounts(snapshot: dict[str, Any]) -> list[SnapshotAccountBalance]:
    if snapshot.get("schema") != LEDGER_SNAPSHOT_SCHEMA:
        raise SnapshotMerkleError("snapshot schema is not supported")
    if snapshot.get("schema_version") != LEDGER_SNAPSHOT_SCHEMA_VERSION:
        raise SnapshotMerkleError("snapshot schema version is not supported")
    accounts_value = snapshot.get("accounts")
    if not isinstance(accounts_value, list):
        raise SnapshotMerkleError("snapshot accounts must be a list")
    accounts: list[SnapshotAccountBalance] = []
    seen: set[str] = set()
    for index, row_value in enumerate(accounts_value):
        row = _require_dict(row_value, f"accounts[{index}]")
        account = _require_str(row.get("account"), f"accounts[{index}].account")
        balance = _require_int(
            row.get("balance_microunits"),
            f"accounts[{index}].balance_microunits",
        )
        if account in seen:
            raise SnapshotMerkleError("snapshot accounts must be unique")
        seen.add(account)
        accounts.append(SnapshotAccountBalance(account=account, balance_microunits=balance))
    return sorted(accounts, key=lambda row: row.account)


def _snapshot_ledger_anchor(snapshot: dict[str, Any]) -> dict[str, Any]:
    anchor = _require_dict(snapshot.get("ledger_anchor"), "ledger_anchor")
    _require_keys(anchor, {"latest_sequence", "latest_entry_hash"}, "ledger_anchor")
    return {
        "latest_sequence": _require_int(
            anchor.get("latest_sequence"),
            "ledger_anchor.latest_sequence",
            minimum=0,
        ),
        "latest_entry_hash": _require_hex_hash(
            anchor.get("latest_entry_hash"),
            "ledger_anchor.latest_entry_hash",
            nullable=True,
        ),
    }


def _account_tree_hash(accounts: list[SnapshotAccountBalance]) -> str:
    if not accounts:
        return _empty_tree_hash()
    return _hash_levels([_account_leaf_hash(account) for account in accounts])[-1][0]


def _hash_levels(leaf_hashes: list[str]) -> list[list[str]]:
    if not leaf_hashes:
        return [[_empty_tree_hash()]]
    levels = [leaf_hashes]
    current = leaf_hashes
    while len(current) > 1:
        next_level: list[str] = []
        for index in range(0, len(current), 2):
            left = current[index]
            right = current[index + 1] if index + 1 < len(current) else left
            next_level.append(_internal_node_hash(left, right))
        levels.append(next_level)
        current = next_level
    return levels


def _account_leaf_object(account: SnapshotAccountBalance) -> dict[str, Any]:
    return {
        "schema": SNAPSHOT_MERKLE_LEAF_SCHEMA,
        "schema_version": SNAPSHOT_MERKLE_SCHEMA_VERSION,
        "snapshot_schema": LEDGER_SNAPSHOT_SCHEMA,
        "snapshot_schema_version": LEDGER_SNAPSHOT_SCHEMA_VERSION,
        "account": account.account,
        "balance_microunits": account.balance_microunits,
    }


def _account_leaf_hash(account: SnapshotAccountBalance) -> str:
    return _hash_payload(_account_leaf_object(account))


def _internal_node_hash(left_hash: str, right_hash: str) -> str:
    return _hash_payload(
        {
            "schema": SNAPSHOT_MERKLE_NODE_SCHEMA,
            "schema_version": SNAPSHOT_MERKLE_SCHEMA_VERSION,
            "hash_algorithm": SNAPSHOT_MERKLE_HASH_ALGORITHM,
            "left_hash": left_hash,
            "right_hash": right_hash,
        }
    )


def _empty_tree_hash() -> str:
    return _hash_payload(
        {
            "schema": SNAPSHOT_MERKLE_EMPTY_SCHEMA,
            "schema_version": SNAPSHOT_MERKLE_SCHEMA_VERSION,
            "hash_algorithm": SNAPSHOT_MERKLE_HASH_ALGORITHM,
            "snapshot_schema": LEDGER_SNAPSHOT_SCHEMA,
            "snapshot_schema_version": LEDGER_SNAPSHOT_SCHEMA_VERSION,
        }
    )


def _root_binding_hash(root: dict[str, Any]) -> str:
    return _hash_payload(
        {
            "schema": SNAPSHOT_MERKLE_ROOT_HASH_SCHEMA,
            "schema_version": SNAPSHOT_MERKLE_SCHEMA_VERSION,
            "snapshot_schema": root["snapshot_schema"],
            "snapshot_schema_version": root["snapshot_schema_version"],
            "hash_algorithm": root["hash_algorithm"],
            "leaf_schema": root["leaf_schema"],
            "node_schema": root["node_schema"],
            "ledger_anchor": root["ledger_anchor"],
            "tree_size": root["tree_size"],
            "account_tree_hash": root["account_tree_hash"],
        }
    )


def _hash_payload(payload: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def _normalize_root(root: dict[str, Any]) -> dict[str, Any]:
    _require_keys(
        root,
        {
            "schema",
            "schema_version",
            "snapshot_schema",
            "snapshot_schema_version",
            "hash_algorithm",
            "leaf_schema",
            "node_schema",
            "ledger_anchor",
            "tree_size",
            "account_tree_hash",
            "root_hash",
        },
        "root",
    )
    if root.get("schema") != SNAPSHOT_MERKLE_ROOT_SCHEMA:
        raise SnapshotMerkleError("root schema is not supported")
    if root.get("schema_version") != SNAPSHOT_MERKLE_SCHEMA_VERSION:
        raise SnapshotMerkleError("root schema version is not supported")
    if root.get("snapshot_schema") != LEDGER_SNAPSHOT_SCHEMA:
        raise SnapshotMerkleError("root snapshot schema is not supported")
    if root.get("snapshot_schema_version") != LEDGER_SNAPSHOT_SCHEMA_VERSION:
        raise SnapshotMerkleError("root snapshot schema version is not supported")
    if root.get("hash_algorithm") != SNAPSHOT_MERKLE_HASH_ALGORITHM:
        raise SnapshotMerkleError("root hash algorithm is not supported")
    if root.get("leaf_schema") != SNAPSHOT_MERKLE_LEAF_SCHEMA:
        raise SnapshotMerkleError("root leaf schema is not supported")
    if root.get("node_schema") != SNAPSHOT_MERKLE_NODE_SCHEMA:
        raise SnapshotMerkleError("root node schema is not supported")
    return {
        "schema": SNAPSHOT_MERKLE_ROOT_SCHEMA,
        "schema_version": SNAPSHOT_MERKLE_SCHEMA_VERSION,
        "snapshot_schema": LEDGER_SNAPSHOT_SCHEMA,
        "snapshot_schema_version": LEDGER_SNAPSHOT_SCHEMA_VERSION,
        "hash_algorithm": SNAPSHOT_MERKLE_HASH_ALGORITHM,
        "leaf_schema": SNAPSHOT_MERKLE_LEAF_SCHEMA,
        "node_schema": SNAPSHOT_MERKLE_NODE_SCHEMA,
        "ledger_anchor": {
            "latest_sequence": _require_int(
                _require_dict(root.get("ledger_anchor"), "ledger_anchor").get("latest_sequence"),
                "ledger_anchor.latest_sequence",
                minimum=0,
            ),
            "latest_entry_hash": _require_hex_hash(
                _require_dict(root.get("ledger_anchor"), "ledger_anchor").get("latest_entry_hash"),
                "ledger_anchor.latest_entry_hash",
                nullable=True,
            ),
        },
        "tree_size": _require_int(root.get("tree_size"), "tree_size", minimum=0),
        "account_tree_hash": _require_hex_hash(root.get("account_tree_hash"), "account_tree_hash"),
        "root_hash": _require_hex_hash(root.get("root_hash"), "root_hash"),
    }


def _normalize_leaf(leaf: dict[str, Any]) -> SnapshotAccountBalance:
    _require_keys(
        leaf,
        {
            "schema",
            "schema_version",
            "snapshot_schema",
            "snapshot_schema_version",
            "account",
            "balance_microunits",
        },
        "leaf",
    )
    if leaf.get("schema") != SNAPSHOT_MERKLE_LEAF_SCHEMA:
        raise SnapshotMerkleError("leaf schema is not supported")
    if leaf.get("schema_version") != SNAPSHOT_MERKLE_SCHEMA_VERSION:
        raise SnapshotMerkleError("leaf schema version is not supported")
    if leaf.get("snapshot_schema") != LEDGER_SNAPSHOT_SCHEMA:
        raise SnapshotMerkleError("leaf snapshot schema is not supported")
    if leaf.get("snapshot_schema_version") != LEDGER_SNAPSHOT_SCHEMA_VERSION:
        raise SnapshotMerkleError("leaf snapshot schema version is not supported")
    return SnapshotAccountBalance(
        account=_require_str(leaf.get("account"), "leaf.account"),
        balance_microunits=_require_int(leaf.get("balance_microunits"), "leaf.balance_microunits"),
    )


def _normalize_siblings(value: Any) -> list[ProofSibling]:
    if not isinstance(value, list):
        raise SnapshotMerkleError("siblings must be a list")
    siblings: list[ProofSibling] = []
    for index, item in enumerate(value):
        sibling = _require_dict(item, f"siblings[{index}]")
        _require_keys(sibling, {"direction", "hash"}, f"siblings[{index}]")
        direction = _require_str(sibling.get("direction"), f"siblings[{index}].direction")
        if direction not in {"left", "right"}:
            raise SnapshotMerkleError("sibling direction is not supported")
        siblings.append(
            ProofSibling(
                direction=cast(Literal["left", "right"], direction),
                digest=cast(str, _require_hex_hash(sibling.get("hash"), f"siblings[{index}].hash")),
            )
        )
    return siblings


def _expected_proof_length(tree_size: int) -> int:
    proof_length = 0
    level_size = tree_size
    while level_size > 1:
        proof_length += 1
        level_size = (level_size + 1) // 2
    return proof_length


def _require_dict(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SnapshotMerkleError(f"{field} must be an object")
    return cast(dict[str, Any], value)


def _require_keys(value: dict[str, Any], allowed: set[str], field: str) -> None:
    extra = sorted(set(value) - allowed)
    if extra:
        raise SnapshotMerkleError(f"{field} has unsupported fields")


def _require_str(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise SnapshotMerkleError(f"{field} must be a string")
    if not value:
        raise SnapshotMerkleError(f"{field} must not be empty")
    return value


def _require_int(value: Any, field: str, *, minimum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SnapshotMerkleError(f"{field} must be an integer")
    if minimum is not None and value < minimum:
        raise SnapshotMerkleError(f"{field} is below minimum")
    return value


def _require_hex_hash(value: Any, field: str, *, nullable: bool = False) -> str | None:
    if value is None and nullable:
        return None
    if not isinstance(value, str):
        raise SnapshotMerkleError(f"{field} must be a hex hash")
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise SnapshotMerkleError(f"{field} must be a lowercase sha256 hex hash")
    return value
