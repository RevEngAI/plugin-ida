from typing import Optional

from pydantic import BaseModel


class UnstripResponseSuccess(BaseModel):
    message: str
    n_renamed: int


class UnstripResponse(BaseModel):
    data: Optional[UnstripResponseSuccess]
    success: bool


class ApplyDataTypesResponse(BaseModel):
    message: str
