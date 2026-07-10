from pydantic import BaseModel


class MatchedFunctionSummary(BaseModel):
    matched_function_count: int
    unmatched_function_count: int
    total_function_count: int
    missing_symbol_name_count: int = 0
    data_types_error: str | None = None
    canonicalized_name_count: int = 0
    deduped_name_count: int = 0
    pushed_name_count: int = 0
    pushed_type_count: int = 0
