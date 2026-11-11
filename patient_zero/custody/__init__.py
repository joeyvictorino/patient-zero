"""Integrity primitives: Merkle tree and Ed25519, both standard library only."""
from .merkle import MerkleTree, verify_inclusion_proof  # noqa: F401
from .signer import generate_keypair, sign, verify  # noqa: F401
