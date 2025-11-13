from typing import Generic, List, Optional, TypeVar

from pydantic import BaseModel

from reai_toolkit.vendor.pydantic import Field

T = TypeVar("T")


class IgnoredFunctions(BaseModel):
    """
    Model for ignored functions
    in both RevEng.AI portal and IDA.

    Ignored Portal Functions - Additional functions identified by RevEng.AI portal to be ignored locally.
    Ignored IDA Functions - Functions identified by IDA to be ignored locally.

    ignored_portal_functions: A dictionary mapping function virtual addresses to their corresponding function IDs.
    ignored_ida_functions: A set of function virtual addresses identified by IDA to be ignored.
    """

    ignored_portal_functions: dict[int, int]
    # ignored_ida_functions: set[int]


class GetCurrentFunctionResponse(BaseModel):
    function_id: Optional[int] = None
    function_vaddr: Optional[int] = None


class GenericApiReturn(BaseModel, Generic[T]):
    success: bool
    error_message: Optional[str] = None
    data: Optional[T] = None


class FunctionBoundary(BaseModel):
    name: str = Field(...)
    start_address: int = Field(...)
    end_address: int = Field(...)


class Symbols(BaseModel):
    base_address: int
    function_boundaries: List[FunctionBoundary]
