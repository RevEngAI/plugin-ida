import hashlib
import json
from pathlib import Path

from loguru import logger

from libbs.decompilers.ida.compat import execute_read, execute_write

import ida_funcs
import idaapi
import idautils
import idc

from revengai import ApiException, BaseResponse
from revengai.models.function_boundary import FunctionBoundary
from revengai.models.symbols import Symbols


MAX_MANGLED_NAME_LENGTH = 4096
MAX_FUNCTION_BOUNDARIES = 200000


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


def build_function_boundary(
    mangled_name: str | None, start_address: int, end_address: int
) -> FunctionBoundary | None:
    if not mangled_name:
        return None

    if start_address < 0 or end_address < 0:
        return None

    return FunctionBoundary(
        mangled_name=mangled_name[:MAX_MANGLED_NAME_LENGTH],
        start_address=start_address,
        end_address=end_address,
    )


def build_symbols(base_address: int, funcs: list[FunctionBoundary]) -> Symbols:
    if len(funcs) > MAX_FUNCTION_BOUNDARIES:
        logger.warning(
            f"RevEng.AI: Truncating function boundaries from {len(funcs)} to "
            f"{MAX_FUNCTION_BOUNDARIES}"
        )
        funcs = funcs[:MAX_FUNCTION_BOUNDARIES]

    return Symbols(base_address=max(int(base_address), 0), function_boundaries=funcs)


@execute_read
def collect_symbols_from_ida(inclusive_end: bool = False) -> Symbols | None:
    base: int = idaapi.get_imagebase() or 0
    funcs: list[FunctionBoundary] = []
    skipped: int = 0

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

        boundary: FunctionBoundary | None = build_function_boundary(
            mangled_name, start_ea, end_ea
        )
        if boundary is None:
            skipped += 1
            continue

        funcs.append(boundary)

    if skipped:
        logger.warning(
            f"RevEng.AI: Skipped {skipped} function boundaries with an empty name "
            "or a negative address"
        )

    return build_symbols(base, funcs)
