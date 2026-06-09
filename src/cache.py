import threading
import time


class TTLCache:
    """Thread-safe in-memory TTL cache."""

    def __init__(self):
        self._store = {}
        self._lock = threading.Lock()

    def get(self, namespace, key):
        cache_key = (namespace, key)
        with self._lock:
            entry = self._store.get(cache_key)
            if entry and time.time() < entry["expires_at"]:
                return entry["value"]
            if entry:
                del self._store[cache_key]
        return None

    def set(self, namespace, key, value, ttl_seconds):
        cache_key = (namespace, key)
        with self._lock:
            self._store[cache_key] = {
                "value": value,
                "expires_at": time.time() + ttl_seconds,
            }

    def clear(self, namespace=None):
        with self._lock:
            if namespace is None:
                self._store.clear()
                return
            keys = [key for key in self._store if key[0] == namespace]
            for key in keys:
                del self._store[key]


_runtime_cache = TTLCache()


def get_cache(namespace, key):
    return _runtime_cache.get(namespace, key)


def set_cache(namespace, key, value, ttl_seconds):
    _runtime_cache.set(namespace, key, value, ttl_seconds)


def clear_cache(namespace=None):
    _runtime_cache.clear(namespace)
