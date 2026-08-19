"""
Persistent storage layer for Bloom filters.

Supports:
- serialization
- compression
- integrity checking
- atomic writes
"""

import os
import json
import gzip
import pickle
import hashlib
import tempfile
from datetime import datetime


STORAGE_VERSION = 1



class BloomStorageError(Exception):
    pass



class BloomStorage:


    @staticmethod
    def _checksum(data: bytes) -> str:
        """
        Calculate SHA-256 checksum.
        """

        return hashlib.sha256(data).hexdigest()



    @staticmethod
    def save(
        obj,
        path: str,
        metadata=None,
        compress=True
    ):
        """
        Save Bloom filter object.

        Args:

            obj:
                BloomFilter or Cascade object

            path:
                output file

            metadata:
                optional information

            compress:
                gzip compression
        """

        payload = {

            "version": STORAGE_VERSION,

            "created":
                datetime.utcnow()
                .isoformat(),

            "metadata":
                metadata or {},

            "object":
                obj
        }


        raw = pickle.dumps(
            payload,
            protocol=pickle.HIGHEST_PROTOCOL
        )


        checksum = BloomStorage._checksum(
            raw
        )


        container = {

            "checksum":
                checksum,

            "payload":
                raw
        }


        final_data = pickle.dumps(
            container,
            protocol=pickle.HIGHEST_PROTOCOL
        )


        if compress:
            final_data = gzip.compress(
                final_data
            )


        # Atomic write
        directory = os.path.dirname(
            path
        ) or "."


        with tempfile.NamedTemporaryFile(
            dir=directory,
            delete=False
        ) as tmp:

            tmp.write(final_data)
            temp_name = tmp.name


        os.replace(
            temp_name,
            path
        )



    @staticmethod
    def load(
        path: str,
        compressed=True
    ):
        """
        Load stored Bloom filter.
        """

        if not os.path.exists(path):
            raise BloomStorageError(
                "File does not exist"
            )


        with open(
            path,
            "rb"
        ) as f:

            data = f.read()



        if compressed:

            data = gzip.decompress(
                data
            )



        container = pickle.loads(
            data
        )


        raw = container["payload"]

        checksum = container["checksum"]



        if BloomStorage._checksum(raw) != checksum:

            raise BloomStorageError(
                "Integrity check failed"
            )



        payload = pickle.loads(
            raw
        )



        if payload["version"] != STORAGE_VERSION:

            raise BloomStorageError(
                "Unsupported storage version"
            )



        return (
            payload["object"],
            payload["metadata"]
        )