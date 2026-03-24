"""
File-based cache for sec-check registry metadata.
Reduces API calls across hook invocations.
"""

import hashlib
import json
import os
import random
import time
from typing import Optional


_CACHE_DIR = os.path.join(os.path.expanduser("~"), ".cache", "sec-check")
_DEFAULT_TTL = 3600  # 1 hour


class DiskCache:
    """Simple file-based JSON cache with TTL."""

    def __init__(self, cache_dir: str = _CACHE_DIR, ttl: int = _DEFAULT_TTL):
        self.cache_dir = cache_dir
        self.ttl = ttl
        try:
            os.makedirs(cache_dir, exist_ok=True)
        except OSError:
            pass  # Cache dir creation failure is non-fatal

    def _key_path(self, key: str) -> str:
        h = hashlib.sha256(key.encode()).hexdigest()[:16]
        return os.path.join(self.cache_dir, f"{h}.json")

    def get(self, key: str) -> Optional[dict]:
        """Get a cached value. Returns None if expired or missing."""
        path = self._key_path(key)
        try:
            with open(path, "r") as f:
                entry = json.load(f)
            if time.time() - entry.get("ts", 0) > self.ttl:
                try:
                    os.unlink(path)
                except OSError:
                    pass
                return None
            return entry.get("data")
        except (FileNotFoundError, json.JSONDecodeError, KeyError, OSError):
            return None

    def set(self, key: str, data: dict) -> None:
        """Cache a value."""
        path = self._key_path(key)
        try:
            with open(path, "w") as f:
                json.dump({"ts": time.time(), "data": data}, f)
        except OSError:
            pass  # Cache write failure is non-fatal

    def maybe_cleanup(self, probability: float = 0.05) -> None:
        """Run cleanup ~5% of the time to avoid I/O on every invocation."""
        if random.random() < probability:
            self.cleanup()

    def cleanup(self) -> None:
        """Remove expired cache entries."""
        try:
            for fname in os.listdir(self.cache_dir):
                if not fname.endswith(".json"):
                    continue
                path = os.path.join(self.cache_dir, fname)
                try:
                    with open(path) as f:
                        entry = json.load(f)
                    if time.time() - entry.get("ts", 0) > self.ttl:
                        os.unlink(path)
                except (json.JSONDecodeError, KeyError, OSError):
                    try:
                        os.unlink(path)  # Remove corrupt entries
                    except OSError:
                        pass
        except OSError:
            pass
