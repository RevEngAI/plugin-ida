import os
import sys

from loguru import logger

# IDA's output window already prepends a timestamp, so skip loguru's own.
_COMPACT = "[RevEng.AI] {message}\n{exception}"
_LEVELED = "[RevEng.AI] {level}: {message}\n{exception}"
_DEBUG = "[RevEng.AI] {level} {name}:{function}:{line} - {message}\n{exception}"


def _format(record) -> str:
    level = record["level"].no
    if level >= 30:
        return _LEVELED
    if level <= 10:
        return _DEBUG
    return _COMPACT


def configure_logging() -> None:
    level = os.environ.get("REAI_LOG_LEVEL")
    if not level:
        level = "DEBUG" if os.environ.get("REAI_DEBUG") == "1" else "INFO"
    logger.remove()
    logger.add(sys.stderr, level=level.upper(), format=_format)
