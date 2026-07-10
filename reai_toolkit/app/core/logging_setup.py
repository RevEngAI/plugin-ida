import os
import sys

from loguru import logger


def configure_logging() -> None:
    level = os.environ.get("REAI_LOG_LEVEL")
    if not level:
        level = "DEBUG" if os.environ.get("REAI_DEBUG") == "1" else "INFO"
    logger.remove()
    logger.add(sys.stderr, level=level.upper())
