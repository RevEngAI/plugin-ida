from enum import Enum
from typing import List, Optional

from pydantic import BaseModel
from revengai.models import FunctionMatchingResultWithBestMatch


class ValidFunction(BaseModel):
    function_id: int
    mangled_name: str
    demangled_name: str
    vaddr: int


# -------------------------
# Event Types
# -------------------------
class MatchEventType(str, Enum):
    START = "start"
    BATCH_DONE = "batch_done"
    SUMMARY = "summary"


# API_PROGRESS_STATUS
class APIProgressStatus(str, Enum):
    STARTED = "STARTED"
    COMPLETED = "COMPLETED"
    ERROR = "ERROR"


# -------------------------
# Event Models
# -------------------------
class StartEvent(BaseModel):
    event: MatchEventType = MatchEventType.START
    total: int


class BatchDoneEvent(BaseModel):
    event: MatchEventType = MatchEventType.BATCH_DONE
    completed: int
    total: int
    ok: bool
    error: Optional[str] = None


class SummaryEvent(BaseModel):
    event: MatchEventType = MatchEventType.SUMMARY
    ok: bool
    completed: int
    total: int
    errors: List[str]
    results: List[FunctionMatchingResultWithBestMatch]


MatchEvent = StartEvent | BatchDoneEvent | SummaryEvent
