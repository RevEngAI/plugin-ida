import hashlib
import json
from pathlib import Path

from libbs.decompilers.ida.compat import execute_read, execute_write

import ida_funcs
import idaapi
import idautils
import idc

from revengai import ApiException, BaseResponse
from revengai.models.function_boundary import FunctionBoundary
from revengai.models.symbols import Symbols


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
        f: ida_funcs.func_t | None = ida_funcs.get_func(start_ea)
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


@execute_write
def demangle(mangled_name: str, attr: int = idc.INF_SHORT_DN) -> str:
    demangled_name: str | None = idc.demangle_name(mangled_name, idc.get_inf_attr(attr))
    return demangled_name if demangled_name else mangled_name


@execute_read
def collect_symbols_from_ida(inclusive_end: bool = False) -> Symbols | None:
    base: int = idaapi.get_imagebase() or 0
    funcs: list[FunctionBoundary] = []

    plt_section: idaapi.segment_t | None = idaapi.get_segm_by_name(".plt")

    for start_ea in idautils.Functions():
        # If this is a .plt stub, we don't want to upload this for analysis.
        if plt_section and plt_section.start_ea <= start_ea <= plt_section.end_ea:
            continue

        f: ida_funcs.func_t = ida_funcs.get_func(start_ea)
        if not f:
            continue

        end_ea: int = f.end_ea - 1 if inclusive_end else f.end_ea
        mangled_name: str = idc.get_func_name(start_ea)

        funcs.append(
            FunctionBoundary(
                mangled_name=mangled_name,
                start_address=start_ea,
                end_address=end_ea,
            )
        )

    symbols = Symbols(base_address=int(base), function_boundaries=funcs)

    return symbols
