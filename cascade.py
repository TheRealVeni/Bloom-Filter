from __future__ import annotations

import pickle
from dataclasses import dataclass
from typing import Iterable, List, Sequence, Set

from bloom import BloomFilter


@dataclass
class CascadeLevel:
    filter: BloomFilter
    stores_positive_set: bool
    size: int


class CascadingBloomFilter:
    """
    Cascading Bloom filter.

    Levels alternate between:
      - revoked set (positive set)
      - false positives of previous level
      - false positives of previous level
      - ...

    Membership lookup alternates the meaning of a positive result.
    """

    def __init__(self, levels: List[CascadeLevel], exact_tail: Set[bytes]):
        self.levels = levels
        self.exact_tail = exact_tail

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    @classmethod
    def build(
        cls,
        revoked: Iterable[bytes],
        universe: Iterable[bytes],
        error_rate: float = 0.01,
        max_levels: int = 4,
        tail_threshold: int = 1000,
    ) -> "CascadingBloomFilter":
        revoked_set = set(revoked)
        universe_set = set(universe)

        if not revoked_set.issubset(universe_set):
            raise ValueError("revoked must be a subset of universe")

        levels: List[CascadeLevel] = []

        current_positive = revoked_set
        current_negative = universe_set - revoked_set
        stores_positive = True

        for _ in range(max_levels):
            if not current_positive:
                break

            bf = BloomFilter(
                capacity=max(1, len(current_positive)),
                error_rate=error_rate,
            )
            bf.update(current_positive)

            levels.append(
                CascadeLevel(
                    filter=bf,
                    stores_positive_set=stores_positive,
                    size=len(current_positive),
                )
            )

            # Compute false positives against the current negative set.
            false_positives = {x for x in current_negative if x in bf}

            if len(false_positives) <= tail_threshold:
                return cls(levels, false_positives)

            # Next level stores the false positives.
            current_positive = false_positives
            current_negative = current_positive if stores_positive else revoked_set
            stores_positive = not stores_positive

        return cls(levels, current_positive)

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def contains(self, item: bytes) -> bool:
        """
        Return True if the item is in the original revoked set.
        No false negatives; false positives are possible only if the exact
        tail is omitted or corrupted.
        """

        expect_positive = True

        for level in self.levels:
            hit = item in level.filter

            if not hit:
                # If the level stored the positive set and we miss, item is absent.
                # If the level stored a false-positive set and we miss, item is present.
                return not expect_positive

            expect_positive = not expect_positive

        # Final exact tail resolves the remaining ambiguity.
        return (item in self.exact_tail) == expect_positive

    __contains__ = contains

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self, path: str) -> None:
        payload = {
            "levels": [
                {
                    "filter": level.filter.to_bytes(),
                    "stores_positive_set": level.stores_positive_set,
                    "size": level.size,
                }
                for level in self.levels
            ],
            "exact_tail": list(self.exact_tail),
        }

        with open(path, "wb") as f:
            pickle.dump(payload, f, protocol=pickle.HIGHEST_PROTOCOL)

    @classmethod
    def load(cls, path: str) -> "CascadingBloomFilter":
        with open(path, "rb") as f:
            payload = pickle.load(f)

        levels = [
            CascadeLevel(
                filter=BloomFilter.from_bytes(entry["filter"]),
                stores_positive_set=entry["stores_positive_set"],
                size=entry["size"],
            )
            for entry in payload["levels"]
        ]

        return cls(levels, set(payload["exact_tail"]))

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------

    def stats(self) -> dict:
        return {
            "levels": len(self.levels),
            "level_sizes": [lvl.size for lvl in self.levels],
            "tail_size": len(self.exact_tail),
            "total_bits": sum(lvl.filter.num_bits for lvl in self.levels),
        }

    def __repr__(self) -> str:
        s = self.stats()
        return (
            f"CascadingBloomFilter(levels={s['levels']}, "
            f"tail_size={s['tail_size']}, total_bits={s['total_bits']})"
        )


# ----------------------------------------------------------------------
# Example usage
# ----------------------------------------------------------------------

if __name__ == "__main__":
    # Universe of certificate hashes.
    universe = {f"cert:{i}".encode() for i in range(100_000)}

    # Revoked subset.
    revoked = {f"cert:{i}".encode() for i in range(0, 100_000, 137)}

    cbf = CascadingBloomFilter.build(
        revoked=revoked,
        universe=universe,
        error_rate=0.01,
        max_levels=4,
        tail_threshold=128,
    )

    print(cbf)
    print(cbf.stats())

    test_revoked = b"cert:137"
    test_good = b"cert:138"

    print(test_revoked in cbf)  # True
    print(test_good in cbf)     # False (deterministically resolved by tail)

    cbf.save("revocations.cbf")
    cbf2 = CascadingBloomFilter.load("revocations.cbf")

    assert (test_revoked in cbf2) is True
    assert (test_good in cbf2) is False
    print("Reload successful.")