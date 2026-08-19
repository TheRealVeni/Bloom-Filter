"""
Multiple hash functions for Bloom filters.

Supports:
- SHA-256 based hashing
- Double hashing (Kirsch-Mitzenmacher)
- Arbitrary number of hash functions
- Stable deterministic output
"""

import hashlib
import struct
from typing import List


class HashFunction:
    """
    Generates k independent-looking hash values
    from a single input using double hashing.
    """

    def __init__(self, num_hashes: int, bit_size: int):
        """
        Args:
            num_hashes:
                Number of hash functions k.

            bit_size:
                Size of Bloom filter bit array.
        """
        if num_hashes <= 0:
            raise ValueError("num_hashes must be positive")

        if bit_size <= 0:
            raise ValueError("bit_size must be positive")

        self.num_hashes = num_hashes
        self.bit_size = bit_size


    def _base_hashes(self, item: bytes):
        """
        Generate two independent 64-bit hashes.

        h1 and h2 are combined:

            h(i) = h1 + i*h2 mod m

        This gives k hash functions.
        """

        digest1 = hashlib.sha256(
            b"hash-function-1:" + item
        ).digest()

        digest2 = hashlib.sha256(
            b"hash-function-2:" + item
        ).digest()


        h1 = struct.unpack(
            ">Q",
            digest1[:8]
        )[0]


        h2 = struct.unpack(
            ">Q",
            digest2[:8]
        )[0]


        return h1, h2


    def hashes(self, item) -> List[int]:
        """
        Generate k hash positions.

        Example:

        [
            123,
            9283,
            18272,
            ...
        ]
        """

        if isinstance(item, str):
            item = item.encode()

        elif isinstance(item, int):
            item = str(item).encode()

        elif not isinstance(item, bytes):
            raise TypeError(
                "item must be str, int, or bytes"
            )


        h1, h2 = self._base_hashes(item)


        positions = []


        for i in range(self.num_hashes):

            value = (
                h1 +
                i * h2
            ) % self.bit_size


            positions.append(value)


        return positions



    def hash_hex(self, item):
        """
        Returns raw SHA-256 hash.

        Useful for:
        - certificates
        - addon packages
        - malware signatures
        """

        if isinstance(item, str):
            item = item.encode()

        return hashlib.sha256(item).hexdigest()