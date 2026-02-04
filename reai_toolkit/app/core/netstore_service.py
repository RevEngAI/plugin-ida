# -*- coding: utf-8 -*-
"""
JsonKVStore for IDA (9.1/9.2 friendly)

- Persist JSON-serializable values alongside your analysis.
- Storage strategy:
    1) Plain JSON string in hash (readable)
    2) zlib-compressed JSON as hex in hash (if still under MAXSPECSIZE)
    3) zlib-compressed JSON in a blob (supvals 'S'), with a small marker in hash

- Hash writing is robust across SWIG overloads:
    hashset(key, str) -> hashset(key, bytes) -> hashset(key, bytes, len)

- Namespaces:
    - Keys are stored under "{ns}:{key}" in the hash (or just "key" for global).
    - Per-namespace index lives at "idx:{ns_or_g}" to list keys quickly.

Usage (in IDA console):
    store = JsonKVStore()
    store.put_global("a", {"x": 1, "y": [1, 2, 3]})
    assert store.get_global("a") == {"x": 1, "y": [1, 2, 3]}
"""

import json
import zlib
from typing import Any, Iterator, Optional

import ida_netnode
from libbs.decompilers.ida.compat import execute_read, execute_write

from revengai.models.function_mapping import FunctionMapping
import reai_toolkit.hooks.globals as menu_hook_globals


# ----- config -----
NAME = "$ REAI_DB"
BLOB_TAG = ord("S")  # store blobs under supvals 'S'
MAX = (
    ida_netnode.MAXSPECSIZE
)  # per-element cap for hash/sup values (typically ~1024 bytes)
_CACHE = {}  # cache for quick pulls within a session (not persistent)


# ----- low-level helpers -----


def _bind_or_create(node_name: str = NAME) -> ida_netnode.netnode:
    """Bind the named node if it exists, else create it."""
    n = ida_netnode.netnode(node_name, 0, False)
    if n == ida_netnode.BADNODE:
        n = ida_netnode.netnode(node_name, 0, True)
    return n


def _row_key(ns: Optional[str], key: str) -> str:
    """Compose the hash key with optional namespace."""
    return f"{ns}:{key}" if ns else key


def _idx_key(ns: Optional[str]) -> str:
    """Key of the per-namespace index (JSON list of keys)."""
    return f"idx:{(ns or 'g')}"


def _meta_next_key() -> str:
    """Key holding the next free blob start index."""
    return "meta:next_idx"


class SimpleNetStore:
    """
    Persist JSON-serializable values alongside an IDA analysis.

    Strategy:
        - Try plain JSON string in hash (readable).
        - Else compress with zlib; try hex in hash.
        - Else spill compressed bytes to a blob (supvals 'S'), and save a marker in hash:
            {"__blob__": true, "codec": "zlib", "start": <int>, "tag": "S"}

    Namespace support:
        - Values live under "{ns}:{key}" (or "key" for global).
        - Per-namespace index "idx:{ns_or_g}" stores a JSON list of keys for O(1) listing.
    """

    def __init__(self, node_name: str = NAME):
        self.n = _bind_or_create(node_name)

    # ---------- hash helpers (robust to SWIG overloads) ----------

    def _h_get_str(self, hkey: str) -> Optional[str]:
        """
        Read a string from the node's hash. Try hashstr() first; then hashstr_buf().
        Handle both `str` and `bytes` returns from SWIG.
        """
        # 1) Direct 'hashstr' (some builds return Python str, others length/-1)
        v = self.n.hashstr(hkey)
        if isinstance(v, str):
            return v
        # 2) Fallback: 'hashstr_buf' can yield str or bytes
        try:
            vb = self.n.hashstr_buf(hkey)
        except Exception:
            vb = None
        if isinstance(vb, str):
            return vb
        if isinstance(vb, (bytes, bytearray)):
            try:
                return bytes(vb).decode("utf-8")
            except Exception:
                return None
        return None

    def _h_set_str(self, hkey: str, s: str) -> bool:
        """
        Write a string to the node's hash.
        Tries (in order): hashset(key, str) -> hashset(key, bytes) -> hashset(key, bytes, len).
        """
        # 1) direct string
        try:
            if self.n.hashset(hkey, s):
                return True
        except TypeError:
            pass
        # 2) bytes
        b = s.encode("utf-8")
        try:
            if self.n.hashset(hkey, b):
                return True
        except TypeError:
            pass
        # 3) explicit length (matches netnode::hashset(const char*, const void*, size_t))
        try:
            return bool(self.n.hashset(hkey, b, len(b)))
        except TypeError:
            return False

    def _h_del(self, hkey: str) -> bool:
        return bool(self.n.hashdel(hkey))

    # ---------- blob index allocator ----------

    def _alloc_start(self) -> int:
        """
        Allocate a new blob start index (monotonic counter stored in hash).
        """
        k = _meta_next_key()
        s = self._h_get_str(k)
        nxt = int(s) if s and s.isdigit() else 1
        self._h_set_str(k, str(nxt + 1))
        return nxt

    # ---------- namespace index ----------

    def _idx_add(self, ns: Optional[str], key: str) -> None:
        ik = _idx_key(ns)
        raw = self._h_get_str(ik)
        keys = set(json.loads(raw) if raw else [])
        if key not in keys:
            keys.add(key)
            self._h_set_str(ik, json.dumps(sorted(keys)))

    def _idx_remove(self, ns: Optional[str], key: str) -> None:
        ik = _idx_key(ns)
        raw = self._h_get_str(ik)
        if not raw:
            return
        try:
            keys = set(json.loads(raw))
            if key in keys:
                keys.remove(key)
                if keys:
                    self._h_set_str(ik, json.dumps(sorted(keys)))
                else:
                    self._h_del(ik)
        except Exception:
            pass

    # ---------- public API ----------

    def put(self, key: str | int, value: Any, ns: Optional[str] = None) -> bool:
        """
        Store JSON-serializable 'value' at (ns, key).
        Tries: plain JSON -> zlib+hex -> blob(zlib).
        """
        k = str(key)
        hkey = _row_key(ns, k)

        # 1) plain JSON in hash (readable)
        js = json.dumps(value, separators=(",", ":"))
        if len(js.encode("utf-8")) < MAX:
            ok = self._h_set_str(hkey, js)
            if ok:
                self._idx_add(ns, k)
            return ok

        # 2) compressed JSON as hex string in hash
        comp = zlib.compress(js.encode("utf-8"), 9)
        hexs = comp.hex()
        if len(hexs.encode("utf-8")) < MAX:
            ok = self._h_set_str(
                hkey, json.dumps({"__cmp__": True, "codec": "zlib", "hex": hexs})
            )
            if ok:
                self._idx_add(ns, k)
            return ok

        # 3) spill to blob
        start = self._alloc_start()
        if not self.n.setblob(comp, start, BLOB_TAG):
            return False
        marker = {"__blob__": True, "codec": "zlib", "start": start, "tag": "S"}
        ok = self._h_set_str(hkey, json.dumps(marker))
        if ok:
            self._idx_add(ns, k)
        return ok

    def get(self, key: str | int, ns: Optional[str] = None, default: Any = None) -> Any:
        k = str(key)
        hkey = _row_key(ns, k)
        s = self._h_get_str(hkey)
        if s is None:
            return default

        # Parse JSON
        try:
            obj = json.loads(s)
        except Exception:
            return default

        # If it's a marker dict, handle it; otherwise return the plain value
        if (
            isinstance(obj, dict)
            and obj.get("__cmp__") is True
            and obj.get("codec") == "zlib"
            and "hex" in obj
        ):
            try:
                comp = bytes.fromhex(obj["hex"])
                raw = zlib.decompress(comp)
                return json.loads(raw.decode("utf-8"))
            except Exception:
                return default

        if (
            isinstance(obj, dict)
            and obj.get("__blob__") is True
            and obj.get("codec") == "zlib"
            and isinstance(obj.get("start"), int)
        ):
            b = self.n.getblob(obj["start"], BLOB_TAG)
            if not b:
                return default
            try:
                raw = zlib.decompress(b)
                return json.loads(raw.decode("utf-8"))
            except Exception:
                return default

        # Not a marker → return the parsed value
        return obj

    def delete(self, key: str | int, ns: Optional[str] = None) -> bool:
        """
        Remove key and any associated blob if present.
        """
        k = str(key)
        hkey = _row_key(ns, k)
        s = self._h_get_str(hkey)
        if not s:
            return False

        deleted = False
        # If it's a blob marker, remove blob first
        try:
            meta = json.loads(s)
        except Exception:
            meta = None

        if (
            isinstance(meta, dict)
            and meta.get("__blob__") is True
            and meta.get("codec") == "zlib"
        ):
            start = meta.get("start")
            if isinstance(start, int):
                sz = self.n.blobsize(start, BLOB_TAG)
                self.n.delblob(start, BLOB_TAG)
                deleted = deleted or (sz > 0)

        deleted = bool(self._h_del(hkey)) or deleted
        self._idx_remove(ns, k)
        return deleted

    def exists(self, key: str | int, ns: Optional[str] = None) -> bool:
        """
        True if hash entry exists (and, for blob markers, the blob is present).
        """
        k = str(key)
        hkey = _row_key(ns, k)
        s = self._h_get_str(hkey)
        if not s:
            return False
        if not (s.startswith("{") and "__" in s):
            return True
        try:
            meta = json.loads(s)
        except Exception:
            return True
        if meta.get("__blob__") is True and isinstance(meta.get("start"), int):
            return self.n.blobsize(meta["start"], BLOB_TAG) > 0
        return True

    def keys(self, ns: Optional[str] = None) -> list[str]:
        """List keys in a namespace (fast via index)."""
        raw = self._h_get_str(_idx_key(ns))
        return sorted(json.loads(raw)) if raw else []

    def items(self, ns: Optional[str] = None) -> Iterator[tuple[str, Any]]:
        """Iterate (key, value) pairs in a namespace."""
        for k in self.keys(ns):
            yield k, self.get(k, ns=ns)

    # ---------- convenience namespaces ----------

    def put_global(self, key: str | int, value: Any) -> bool:
        return self.put(key, value, ns=None)

    def get_global(self, key: str | int, default: Any = None) -> Any:
        return self.get(key, ns=None, default=default)

    def put_func(self, func_ea: int, key: str | int, value: Any) -> bool:
        return self.put(key, value, ns=f"func_{func_ea:x}")

    def get_func(self, func_ea: int, key: str | int, default: Any = None) -> Any:
        return self.get(key, ns=f"func_{func_ea:x}", default=default)

    def clear_ns(self, ns: Optional[str] = None) -> int:
        """Delete all records in a namespace. Returns count deleted."""
        cnt = 0
        for k in list(self.keys(ns)):
            if self.delete(k, ns=ns):
                cnt += 1
        return cnt

    def clear_all_ns(self) -> int:
        """
        Delete ALL records across all namespaces (including global).
        Returns the count of deleted records.
        """

        _CACHE.clear()

        cnt = 0
        # Iterate through all hash keys stored in this netnode
        it = self.n.hashfirst()
        while it is not None and it != "":
            hkey = it
            # advance before possibly deleting
            nxt = self.n.hashnext(hkey)

            val = self._h_get_str(hkey)
            if val:
                # Try to parse marker to see if we need to delete blobs too
                try:
                    meta = json.loads(val)
                except Exception:
                    meta = None
                if (
                    isinstance(meta, dict)
                    and meta.get("__blob__") is True
                    and meta.get("codec") == "zlib"
                ):
                    start = meta.get("start")
                    if isinstance(start, int):
                        try:
                            self.n.delblob(start, BLOB_TAG)
                        except Exception:
                            pass

            if self._h_del(hkey):
                cnt += 1
            it = nxt
        return cnt

    @execute_write
    def put_binary_id(self, binary_id: int) -> bool:
        _CACHE["binary_id"] = None
        success: bool = self.put_global("binary_id", binary_id)
        if success:
            menu_hook_globals.BINARY_ID = binary_id
        return success

    @execute_read
    def get_binary_id(self) -> int | None:
        id: int | None = _CACHE.get("binary_id", None)
        if id is None:
            id = self.get_global("binary_id", default=None)
            _CACHE["binary_id"] = id
        
        return id

    @execute_write
    def put_analysis_id(self, analysis_id: int) -> bool:
        _CACHE["analysis_id"] = None
        success: bool =  self.put_global("analysis_id", analysis_id)
        if success:
            menu_hook_globals.ANALYSIS_ID = analysis_id
        return success

    @execute_read
    def get_analysis_id(self) -> int | None:
        id: int | None = _CACHE.get("analysis_id", None)
        if id is None:
            id = self.get_global("analysis_id")
            _CACHE["analysis_id"] = id
        
        return id

    @execute_write
    def put_model_id(self, model_id: int) -> bool:
        _CACHE["model_id"] = None
        success: bool = self.put_global("model_id", model_id)
        if success:
            menu_hook_globals.MODEL_ID = model_id
        return success

    @execute_read
    def get_model_id(self) -> int | None:
        id: int | None = _CACHE.get("model_id", None)
        if id is None:
            id = self.get_global("model_id")
            _CACHE["model_id"] = id
        
        return id

    @execute_write
    def put_model_name(self, model_name: str) -> bool:
        _CACHE["model_name"] = None
        return self.put_global("model_name", model_name)

    @execute_read
    def get_model_name(self) -> str | None:
        name: str | None = _CACHE.get("model_name")
        if not name:
            name = self.get_global("model_name")
            _CACHE["model_name"] = name
        
        return name

    @execute_write
    def put_function_mapping(self, function_mapping: FunctionMapping) -> bool:
        _CACHE["function_mapping"] = None
        return self.put_global("function_mapping", function_mapping.model_dump())

    @execute_read
    def get_function_mapping(self) -> FunctionMapping | None:
        data: dict | None = _CACHE.get("function_mapping", None)
        if data is None:
            data = self.get_global("function_mapping", default=None)
            _CACHE["function_mapping"] = data
        if isinstance(data, dict):
            try:
                return FunctionMapping.model_validate(data)
            except Exception:
                pass
            
        return None

    @execute_read
    def get_analysis_status(self) -> str | None:
        return self.get_global("analysis_status")

    @execute_write
    def put_analysis_status(self, status: str) -> bool:
        return self.put_global("analysis_status", status)

    @execute_read
    def get_ai_decomp_cache(self, func_ea: int) -> str | None:
        return self.get_func(func_ea, "ai_decomp")

