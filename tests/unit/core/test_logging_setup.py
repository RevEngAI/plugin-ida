from unittest.mock import MagicMock

import pytest

from reai_toolkit.app.core import logging_setup


@pytest.fixture
def fake_logger(monkeypatch):
    logger = MagicMock()
    monkeypatch.setattr(logging_setup, "logger", logger)
    return logger


def _added_level(logger) -> str:
    return logger.add.call_args.kwargs["level"]


def test_default_is_info(monkeypatch, fake_logger):
    monkeypatch.delenv("REAI_DEBUG", raising=False)
    monkeypatch.delenv("REAI_LOG_LEVEL", raising=False)
    logging_setup.configure_logging()
    fake_logger.remove.assert_called_once()
    assert _added_level(fake_logger) == "INFO"


def test_reai_debug_enables_debug(monkeypatch, fake_logger):
    monkeypatch.delenv("REAI_LOG_LEVEL", raising=False)
    monkeypatch.setenv("REAI_DEBUG", "1")
    logging_setup.configure_logging()
    assert _added_level(fake_logger) == "DEBUG"


def test_reai_debug_zero_stays_info(monkeypatch, fake_logger):
    monkeypatch.delenv("REAI_LOG_LEVEL", raising=False)
    monkeypatch.setenv("REAI_DEBUG", "0")
    logging_setup.configure_logging()
    assert _added_level(fake_logger) == "INFO"


def test_explicit_level_wins_and_is_uppercased(monkeypatch, fake_logger):
    monkeypatch.setenv("REAI_DEBUG", "1")
    monkeypatch.setenv("REAI_LOG_LEVEL", "warning")
    logging_setup.configure_logging()
    assert _added_level(fake_logger) == "WARNING"
