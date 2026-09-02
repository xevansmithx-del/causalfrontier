from __future__ import annotations

import hashlib

import pytest

from causalfrontier._transparency import (
    empty_hash,
    leaf_hash,
    node_hash,
    verify_consistency_proof,
    verify_inclusion_proof,
)


def _leaf(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(size: int) -> int:
    return 1 << ((size - 1).bit_length() - 1)


def _root_from_leaves(leaves: list[bytes]) -> bytes:
    if not leaves:
        return hashlib.sha256(b"").digest()
    if len(leaves) == 1:
        return _leaf(leaves[0])
    split = _split(len(leaves))
    return _node(_root_from_leaves(leaves[:split]), _root_from_leaves(leaves[split:]))


def _inclusion_proof(leaves: list[bytes], index: int) -> list[bytes]:
    if len(leaves) == 1:
        return []
    split = _split(len(leaves))
    if index < split:
        return [*_inclusion_proof(leaves[:split], index), _root_from_leaves(leaves[split:])]
    return [*_inclusion_proof(leaves[split:], index - split), _root_from_leaves(leaves[:split])]


def _consistency_subproof(leaves: list[bytes], old_size: int, complete: bool) -> list[bytes]:
    if old_size == len(leaves):
        return [] if complete else [_root_from_leaves(leaves)]
    split = _split(len(leaves))
    if old_size <= split:
        return [
            *_consistency_subproof(leaves[:split], old_size, complete),
            _root_from_leaves(leaves[split:]),
        ]
    return [
        *_consistency_subproof(leaves[split:], old_size - split, False),
        _root_from_leaves(leaves[:split]),
    ]


def _consistency_proof(leaves: list[bytes], old_size: int) -> list[bytes]:
    if old_size == 0 or old_size == len(leaves):
        return []
    return _consistency_subproof(leaves, old_size, True)


def _leaves(size: int) -> list[bytes]:
    return [("leaf-%02d" % index).encode("ascii") for index in range(size)]


def _flipped(value: bytes) -> bytes:
    return bytes([value[0] ^ 1]) + value[1:]


def test_rfc6962_hash_prefixes_and_empty_tree_vector():
    assert empty_hash().hex() == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert leaf_hash(b"").hex() == "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
    assert leaf_hash(b"payload") == _leaf(b"payload")
    assert node_hash(_leaf(b"left"), _leaf(b"right")) == _node(_leaf(b"left"), _leaf(b"right"))


def test_all_inclusion_paths_for_tree_sizes_zero_through_sixteen():
    assert not verify_inclusion_proof(_leaf(b"absent"), 0, 0, [], empty_hash())

    for size in range(1, 17):
        leaves = _leaves(size)
        root = _root_from_leaves(leaves)
        for index, data in enumerate(leaves):
            proof = _inclusion_proof(leaves, index)
            assert verify_inclusion_proof(_leaf(data), index, size, proof, root)


def test_all_consistency_paths_for_tree_sizes_zero_through_sixteen():
    for new_size in range(17):
        leaves = _leaves(new_size)
        new_root = _root_from_leaves(leaves)
        for old_size in range(new_size + 1):
            old_root = _root_from_leaves(leaves[:old_size])
            proof = _consistency_proof(leaves, old_size)
            assert verify_consistency_proof(old_size, new_size, old_root, new_root, proof)


def test_inclusion_paths_reject_corruption_truncation_and_trailing_nodes():
    leaves = _leaves(13)
    root = _root_from_leaves(leaves)
    proof = _inclusion_proof(leaves, 9)

    assert not verify_inclusion_proof(_flipped(_leaf(leaves[9])), 9, 13, proof, root)
    assert not verify_inclusion_proof(_leaf(leaves[9]), 9, 13, proof, _flipped(root))
    assert not verify_inclusion_proof(_leaf(leaves[9]), 8, 13, proof, root)
    assert not verify_inclusion_proof(_leaf(leaves[9]), 9, 13, proof[:-1], root)
    assert not verify_inclusion_proof(_leaf(leaves[9]), 9, 13, [*proof, _leaf(b"trailing")], root)
    for index in range(len(proof)):
        corrupt = proof.copy()
        corrupt[index] = _flipped(corrupt[index])
        assert not verify_inclusion_proof(_leaf(leaves[9]), 9, 13, corrupt, root)


def test_consistency_paths_reject_corruption_truncation_and_trailing_nodes():
    leaves = _leaves(15)
    old_size = 7
    old_root = _root_from_leaves(leaves[:old_size])
    new_root = _root_from_leaves(leaves)
    proof = _consistency_proof(leaves, old_size)

    assert not verify_consistency_proof(old_size, 15, _flipped(old_root), new_root, proof)
    assert not verify_consistency_proof(old_size, 15, old_root, _flipped(new_root), proof)
    assert not verify_consistency_proof(old_size, 15, old_root, new_root, proof[:-1])
    assert not verify_consistency_proof(old_size, 15, old_root, new_root, [*proof, _leaf(b"trailing")])
    for index in range(len(proof)):
        corrupt = proof.copy()
        corrupt[index] = _flipped(corrupt[index])
        assert not verify_consistency_proof(old_size, 15, old_root, new_root, corrupt)


@pytest.mark.parametrize("bad_hash", [b"", b"x" * 31, b"x" * 33, bytearray(32), "x" * 32, None])
def test_verifiers_reject_malformed_hashes_and_path_nodes(bad_hash):
    good = _leaf(b"leaf")
    assert not verify_inclusion_proof(bad_hash, 0, 1, [], good)
    assert not verify_inclusion_proof(good, 0, 1, [], bad_hash)
    assert not verify_inclusion_proof(good, 0, 2, [bad_hash], good)
    assert not verify_consistency_proof(1, 1, bad_hash, good, [])
    assert not verify_consistency_proof(1, 1, good, bad_hash, [])
    assert not verify_consistency_proof(1, 2, good, good, [bad_hash])


@pytest.mark.parametrize("bad_number", [-1, True, False, 1.0, "1", None, 1 << 63])
def test_verifiers_reject_malformed_sizes_and_indices(bad_number):
    root = _leaf(b"leaf")
    assert not verify_inclusion_proof(root, 0, bad_number, [], root)
    assert not verify_inclusion_proof(root, bad_number, 1, [], root)
    assert not verify_consistency_proof(bad_number, 1, root, root, [])
    assert not verify_consistency_proof(0, bad_number, empty_hash(), root, [])


@pytest.mark.parametrize("bad_proof", [b"", bytearray(), "", None, iter(())])
def test_verifiers_reject_non_list_or_tuple_paths(bad_proof):
    root = _leaf(b"leaf")
    assert not verify_inclusion_proof(root, 0, 1, bad_proof, root)
    assert not verify_consistency_proof(1, 1, root, root, bad_proof)


def test_verifiers_reject_impossible_boundaries_and_oversized_paths():
    root = _leaf(b"leaf")
    too_long = [root] * 64

    assert not verify_inclusion_proof(root, -1, 1, [], root)
    assert not verify_inclusion_proof(root, 1, 1, [], root)
    assert not verify_inclusion_proof(root, 0, 1, [root], root)
    assert not verify_inclusion_proof(root, 0, 1, too_long, root)
    assert not verify_consistency_proof(2, 1, root, root, [])
    assert not verify_consistency_proof(1, 1, root, root, [root])
    assert not verify_consistency_proof(1, 1, root, root, too_long)
    assert not verify_consistency_proof(0, 1, empty_hash(), root, [root])
    assert not verify_consistency_proof(0, 0, root, root, [])


def test_hash_primitives_reject_implicit_byte_coercion_and_bad_widths():
    with pytest.raises(TypeError, match="leaf data"):
        leaf_hash(bytearray(b"payload"))
    with pytest.raises(TypeError, match="child hashes"):
        node_hash(bytearray(32), b"x" * 32)
    with pytest.raises(ValueError, match="exactly 32 bytes"):
        node_hash(b"x" * 31, b"x" * 32)
