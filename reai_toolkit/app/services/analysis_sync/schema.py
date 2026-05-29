from pydantic import BaseModel


class MatchedFunctionSummary(BaseModel):
    matched_function_count: int
    unmatched_function_count: int
    total_function_count: int
    data_types_error: str | None = None
