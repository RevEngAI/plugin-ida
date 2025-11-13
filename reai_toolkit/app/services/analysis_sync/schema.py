from pydantic import BaseModel


class MatchedFunctionSummary(BaseModel):
    matched_local_function_count: int
    unmatched_local_function_count: int
    unmatched_remote_function_count: int
    total_function_count: int
