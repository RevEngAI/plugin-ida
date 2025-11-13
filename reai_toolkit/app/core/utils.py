import hashlib
import json
from pathlib import Path
from typing import Optional

import ida_funcs
import ida_kernwin as kw
import idaapi
import idautils
import idc
from revengai import ApiException, BaseResponse
from revengai.models import FunctionBoundary, Symbols


def parse_exception(exception: ApiException) -> BaseResponse | None:
    """
    If the exception body is JSON and matches BaseResponse, return it.
    Otherwise, return None.
    """

    if exception.body:
        try:
            return BaseResponse(**json.loads(exception.body))
        except Exception:
            return None
    return None


def get_function_boundaries_hash(inclusive_end: bool = False) -> str:
    parts = []

    # Collect (start, end) for each function
    for start_ea in idautils.Functions():
        f = ida_funcs.get_func(start_ea)
        if f is None:
            continue
        # end_ea is exclusive, so if you want inclusive, subtract 1
        end_ea = f.end_ea - 1 if inclusive_end else f.end_ea

        parts.append((start_ea, end_ea))

    # Sort by start address to stabilize order
    parts.sort(key=lambda t: t[0])

    # Build string
    str_parts = [f"{start}-{end}" for (start, end) in parts]
    boundaries_str = ",".join(str_parts)

    # Compute SHA-256
    digest = hashlib.sha256(boundaries_str.encode()).hexdigest()
    return digest


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def demangle(mangled_name: str, attr: int = idc.INF_SHORT_DN) -> str:
    demangled_name = None

    def _do():
        nonlocal demangled_name
        demangled_name = idc.demangle_name(mangled_name, idc.get_inf_attr(attr))

    kw.execute_sync(_do, idaapi.MFF_FAST)

    return demangled_name if demangled_name else mangled_name


def collect_symbols_from_ida(inclusive_end: bool = False) -> Optional[Symbols]:
    symbols = None

    def _do():
        base = idaapi.get_imagebase() or 0
        funcs: list[FunctionBoundary] = []
        mangled_funcs = []

        for start_ea in idautils.Functions():
            f = ida_funcs.get_func(start_ea)
            if not f:
                continue
            end = f.end_ea - 1 if inclusive_end else f.end_ea
            mangled_name = idc.get_func_name(start_ea)

            funcs.append(
                FunctionBoundary(
                    mangled_name=mangled_name,
                    start_address=int(start_ea),
                    end_address=int(end),
                )
            )

            mangled_funcs.append(
                {
                    "mangled_name": mangled_name,
                    "start_address": int(start_ea),
                    "end_address": int(end),
                }
            )

        nonlocal symbols
        symbols = Symbols(base_address=int(base), function_boundaries=funcs)

    kw.execute_sync(_do, idaapi.MFF_FAST)

    return symbols
