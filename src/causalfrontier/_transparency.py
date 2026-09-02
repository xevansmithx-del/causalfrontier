"""Minimal RFC 6962 Merkle-tree hashing and proof verification.

The proof verifiers accept already-hashed leaves and proof nodes.  They are
deliberately fail-closed: malformed inputs return ``False`` rather than being
coerced into hashes, indices, or sizes.
"""

from __future__ import annotations

import hashlib
from typing import Sequence

_HASH_BYTES = 32
_MAX_TREE_SIZE = (1 << 63) - 1
_MAX_PROOF_LENGTH = 63
_EMPTY_HASH = hashlib.sha256(b"").digest()


def empty_hash() -> bytes:
    """Return the RFC 6962 Merkle-tree hash of an empty tree."""

    return _EMPTY_HASH


def leaf_hash(data: bytes) -> bytes:
    """Return the RFC 6962 Merkle-tree hash of one leaf's raw bytes."""

    if type(data) is not bytes:
        raise TypeError("leaf data must be bytes")
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """Return the RFC 6962 hash of two 32-byte child hashes."""

    if type(left) is not bytes or type(right) is not bytes:
        raise TypeError("child hashes must be bytes")
    if len(left) != _HASH_BYTES or len(right) != _HASH_BYTES:
        raise ValueError("child hashes must be exactly 32 bytes")
    return hashlib.sha256(b"\x01" + left + right).digest()


def _is_hash(value: object) -> bool:
    return type(value) is bytes and len(value) == _HASH_BYTES


def _is_tree_size(value: object) -> bool:
    return type(value) is int and 0 <= value <= _MAX_TREE_SIZE


def _proof_nodes(proof: object) -> tuple[bytes, ...] | None:
    if type(proof) not in (list, tuple) or len(proof) > _MAX_PROOF_LENGTH:
        return None
    if any(not _is_hash(node) for node in proof):
        return None
    return tuple(proof)


def verify_inclusion_proof(
    leaf_hash_value: bytes,
    leaf_index: int,
    tree_size: int,
    proof: Sequence[bytes],
    expected_root: bytes,
) -> bool:
    """Verify an RFC 6962 audit path for an already-hashed leaf.

    ``leaf_index`` is zero based.  The proof must contain exactly the path
    required by ``tree_size``; truncated and trailing paths are rejected.
    """

    if not _is_hash(leaf_hash_value) or not _is_hash(expected_root):
        return False
    if not _is_tree_size(tree_size) or type(leaf_index) is not int:
        return False
    if tree_size == 0 or leaf_index < 0 or leaf_index >= tree_size:
        return False
    nodes = _proof_nodes(proof)
    if nodes is None:
        return False

    node_index = leaf_index
    last_node = tree_size - 1
    calculated = leaf_hash_value

    for sibling in nodes:
        if last_node == 0:
            return False
        if node_index == last_node or node_index & 1:
            calculated = node_hash(sibling, calculated)
            while node_index != 0 and not node_index & 1:
                node_index >>= 1
                last_node >>= 1
        else:
            calculated = node_hash(calculated, sibling)
        node_index >>= 1
        last_node >>= 1

    return node_index == 0 and last_node == 0 and calculated == expected_root


def verify_consistency_proof(
    old_size: int,
    new_size: int,
    old_root: bytes,
    new_root: bytes,
    proof: Sequence[bytes],
) -> bool:
    """Verify that one supplied RFC 6962 tree root extends another."""

    if not _is_tree_size(old_size) or not _is_tree_size(new_size):
        return False
    if old_size > new_size or not _is_hash(old_root) or not _is_hash(new_root):
        return False
    nodes = _proof_nodes(proof)
    if nodes is None:
        return False

    if old_size == 0:
        if nodes or old_root != _EMPTY_HASH:
            return False
        return new_size != 0 or new_root == _EMPTY_HASH
    if old_size == new_size:
        return not nodes and old_root == new_root

    old_node = old_size - 1
    new_node = new_size - 1
    while old_node & 1:
        old_node >>= 1
        new_node >>= 1

    proof_index = 0
    if old_node == 0:
        old_calculated = old_root
        new_calculated = old_root
    else:
        if not nodes:
            return False
        old_calculated = nodes[0]
        new_calculated = nodes[0]
        proof_index = 1

    for sibling in nodes[proof_index:]:
        if new_node == 0:
            return False
        if old_node == new_node or old_node & 1:
            old_calculated = node_hash(sibling, old_calculated)
            new_calculated = node_hash(sibling, new_calculated)
            while old_node != 0 and not old_node & 1:
                old_node >>= 1
                new_node >>= 1
        else:
            new_calculated = node_hash(new_calculated, sibling)
        old_node >>= 1
        new_node >>= 1

    return old_node == 0 and new_node == 0 and old_calculated == old_root and new_calculated == new_root


__all__ = [
    "empty_hash",
    "leaf_hash",
    "node_hash",
    "verify_consistency_proof",
    "verify_inclusion_proof",
]
