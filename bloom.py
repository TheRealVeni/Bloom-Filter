from __future__ import annotations

import hashlib
import math
import struct
from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class BloomParams:
    capacity: int
    error_rate: float
    num_bits: int
    num_hashes: int


def optimal_params(capacity: int, error_rate: float) -> BloomParams:
    if capacity <= 0:
        raise ValueError("capacity must be > 0")
    if not (0 < error_rate < 1):
        raise ValueError("error_rate must be between 0 and 1")

    m = -capacity * math.log(error_rate) / (math.log(2) ** 2)
    k = (m / capacity) * math.log(2)

    num_bits = max(8, int(math.ceil(m)))
    num_hashes = max(1, int(round(k)))

    return BloomParams(
        capacity=capacity,
        error_rate=error_rate,
        num_bits=num_bits,
        num_hashes=num_hashes,
    )


class BloomFilter:
    """
    Standard Bloom filter using Kirsch-Mitzenmacher double hashing.
    """

    MAGIC = b"BLM1"

    def __init__(self, capacity: int, error_rate: float = 0.01):
        params = optimal_params(capacity, error_rate)

        self.capacity = params.capacity
        self.error_rate = params.error_rate
        self.num_bits = params.num_bits
        self.num_hashes = params.num_hashes

        self._bytes = bytearray((self.num_bits + 7) // 8)
        self.count = 0

    # ---------- hashing ----------

    @staticmethod
    def _to_bytes(item: bytes | str | int) -> bytes:
        if isinstance(item, bytes):
            return item
        if isinstance(item, str):
            return item.encode("utf-8")
        if isinstance(item, int):
            return item.to_bytes(8, "big", signed=False)
        raise TypeError(f"unsupported item type: {type(item)!r}")

    def _hashes(self, item: bytes | str | int):
        data = self._to_bytes(item)

        digest = hashlib.sha256(data).digest()
        h1 = int.from_bytes(digest[:16], "big")
        h2 = int.from_bytes(digest[16:], "big") or 0x9E3779B97F4A7C15

        for i in range(self.num_hashes):
            yield (h1 + i * h2) % self.num_bits

    # ---------- bit operations ----------

    def _set_bit(self, bit: int) -> None:
        self._bytes[bit >> 3] |= 1 << (bit & 7)

    def _get_bit(self, bit: int) -> bool:
        return bool(self._bytes[bit >> 3] & (1 << (bit & 7)))

    # ---------- public API ----------

    def add(self, item: bytes | str | int) -> None:
        for bit in self._hashes(item):
            self._set_bit(bit)
        self.count += 1

    def update(self, items: Iterable[bytes | str | int]) -> None:
        for item in items:
            self.add(item)

    def __contains__(self, item: bytes | str | int) -> bool:
        return all(self._get_bit(bit) for bit in self._hashes(item))

    def contains(self, item: bytes | str | int) -> bool:
        return item in self

    # ---------- persistence ----------

    def to_bytes(self) -> bytes:
        header = struct.pack(
            ">4sQdQQQ",
            self.MAGIC,
            self.capacity,
            self.error_rate,
            self.num_bits,
            self.num_hashes,
            self.count,
        )
        return header + bytes(self._bytes)

    @classmethod
    def from_bytes(cls, data: bytes) -> "BloomFilter":
        header_size = struct.calcsize(">4sQdQQQ")
        magic, capacity, error_rate, num_bits, num_hashes, count = struct.unpack(
            ">4sQdQQQ", data[:header_size]
        )

        if magic != cls.MAGIC:
            raise ValueError("invalid Bloom filter data")

        obj = cls.__new__(cls)
        obj.capacity = capacity
        obj.error_rate = error_rate
        obj.num_bits = num_bits
        obj.num_hashes = num_hashes
        obj.count = count
        obj._bytes = bytearray(data[header_size:])

        expected_len = (num_bits + 7) // 8
        if len(obj._bytes) != expected_len:
            raise ValueError("corrupted Bloom filter data")

        return obj

    def save(self, path: str) -> None:
        with open(path, "wb") as f:
            f.write(self.to_bytes())

    @classmethod
    def load(cls, path: str) -> "BloomFilter":
        with open(path, "rb") as f:
            return cls.from_bytes(f.read())

    # ---------- misc ----------

    def __len__(self) -> int:
        return self.count

    def __repr__(self) -> str:
        return (
            f"BloomFilter(capacity={self.capacity}, error_rate={self.error_rate}, "
            f"bits={self.num_bits}, hashes={self.num_hashes}, count={self.count})"
        )


if __name__ == "__main__":
    bf = BloomFilter(capacity=1000, error_rate=0.01)
    bf.add("cert:1234")
    bf.add("addon:deadbeef")

    print("cert:1234" in bf)      # True
    print("cert:9999" in bf)      # Usually False

    bf.save("test.bloom")
    bf2 = BloomFilter.load("test.bloom")
    print("addon:deadbeef" in bf2)  # True