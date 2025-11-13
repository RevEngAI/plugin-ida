from typing import Optional

from pydantic import BaseModel


class RenameInput(BaseModel):
    function_id: Optional[int] = None
    ea: int
    new_name: str


class RenameBatchSummary(BaseModel):
    total_functions: int
    renamed_functions: int
    failed_renames: int
