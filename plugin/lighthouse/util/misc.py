import collections

DEFAULT_CACHE_CAPACITY = 30
class CompositionCache(object):
    """
    A simple LRU cache to hold coverage compositions.
    """

    def __init__(self, capacity=DEFAULT_CACHE_CAPACITY):
        self._cache = collections.OrderedDict()
        self._capacity = capacity

    def __getitem__(self, key):
        """
        Get an entry from the cache.
        """
        result = self._cache.pop(key, None)

        # cache hit, raise priority of this item
        if result:
            self._cache[key] = result

        # return the cache entry (or None)
        return result

    def __setitem__(self, key, value):
        """
        Update the cache with the given entry.
        """
        result = self._cache.pop(key, None)

        # item is already in the cache, touch it.
        if result:
            self._cache[key] = result
            return

        # if the cache is full, evict the entry oldest entry
        if len(self._cache) > self._capacity:
            self._cache.popitem(False)

        # insert the new cache entry
        self._cache[key] = value
