"""RFC 6962 tree topology with domain-separated BLAKE2b-256 hashes.

The empty-root convention is H(0x00) rather than the SHA-256 empty string used
by Certificate Transparency. Odd nodes are promoted.
"""
from __future__ import annotations

from hashlib import blake2b


def leaf_hash(data: bytes) -> bytes:
    return blake2b(b"\x00" + data, digest_size=32).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    if len(left) != 32 or len(right) != 32:
        raise ValueError("Merkle node children must be 256-bit digests")
    return blake2b(b"\x01" + left + right, digest_size=32).digest()


class MerkleTree:
    """Immutable snapshot of leaf bytes, preserving their order and multiplicity."""

    def __init__(self, leaves: list[bytes]):
        self.leaves = tuple(bytes(leaf) for leaf in leaves)
        level = [leaf_hash(leaf) for leaf in self.leaves]
        self._levels = [level]
        while len(level) > 1:
            level = [node_hash(level[i], level[i + 1]) if i + 1 < len(level)
                     else level[i] for i in range(0, len(level), 2)]
            self._levels.append(level)
        self.root_hex = (level[0] if level else leaf_hash(b"")).hex()

    def inclusion_proof(self, index: int) -> list[tuple[str, str]]:
        if not isinstance(index, int) or not 0 <= index < len(self.leaves):
            raise IndexError("Leaf index is outside this Merkle tree")
        proof = []
        for level in self._levels[:-1]:
            if index % 2:
                proof.append(("L", level[index - 1].hex()))
            elif index + 1 < len(level):
                proof.append(("R", level[index + 1].hex()))
            index //= 2
        return proof


def verify_inclusion_proof(leaf_bytes: bytes, root_hex: str,
                           proof: list[tuple[str, str]]) -> bool:
    """Verify a path; membership does not independently authenticate tree size."""
    try:
        root = bytes.fromhex(root_hex)
        if len(root) != 32:
            return False
        current = leaf_hash(leaf_bytes)
        for direction, sibling_hex in proof:
            sibling = bytes.fromhex(sibling_hex)
            if len(sibling) != 32 or direction not in ("L", "R"):
                return False
            current = node_hash(sibling, current) if direction == "L" else node_hash(current, sibling)
        return current == root
    except (ValueError, TypeError):
        return False
