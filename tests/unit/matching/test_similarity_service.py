import threading
from unittest.mock import MagicMock

import pytest
from revengai import GetMatchesOutputBody, GetMatchesStatusOutputBody
from revengai.models.function_match import FunctionMatch
from revengai.models.matched_function import MatchedFunction

from reai_toolkit.app.services.matching import similarity_service as svc_mod
from reai_toolkit.app.services.matching.similarity_service import SimilarityService

ANALYSIS_ID = 321
FUNC_ID = 11
VADDR = 0x401000


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    monkeypatch.setattr(svc_mod.time, "sleep", lambda *_: None)


@pytest.fixture
def netstore():
    ns = MagicMock()
    ns.get_analysis_id.return_value = ANALYSIS_ID
    return ns


@pytest.fixture
def service(netstore):
    return SimilarityService(netstore_service=netstore, sdk_config=MagicMock())


@pytest.fixture
def sdk(mocker):
    mocker.patch.object(SimilarityService, "yield_api_client")
    functions = mocker.patch.object(svc_mod, "FunctionsCoreApi").return_value
    return functions


def _matched(function_id: int) -> MatchedFunction:
    return MatchedFunction.model_construct(function_id=function_id, similarity=0.9)


def _status(status: str) -> GetMatchesStatusOutputBody:
    return GetMatchesStatusOutputBody.model_construct(
        status=status, step="match", step_index=0, steps_total=1, messages=[]
    )


def _matches(matched=None) -> GetMatchesOutputBody:
    matches = (
        [FunctionMatch.model_construct(function_id=FUNC_ID, matched_functions=matched)]
        if matched is not None
        else []
    )
    return GetMatchesOutputBody.model_construct(status="COMPLETED", matches=matches)


def _run(service):
    cb = MagicMock()
    service._perform_function_similarity_request(threading.Event(), FUNC_ID, VADDR, cb)
    return cb


def test_complete_invokes_callback_with_matches(service, sdk):
    sdk.get_functions_matching_status.return_value = _status("COMPLETED")
    sdk.get_functions_matches.return_value = _matches(
        matched=[_matched(2), _matched(3)]
    )

    cb = _run(service)

    cb.assert_called_once()
    func_id, vaddr, matches, analysis_id = cb.call_args[0]
    assert (func_id, vaddr, analysis_id) == (FUNC_ID, VADDR, ANALYSIS_ID)
    assert [m.function_id for m in matches] == [2, 3]


def test_missing_analysis_id_skips(service, sdk, netstore):
    netstore.get_analysis_id.return_value = None

    cb = _run(service)

    cb.assert_not_called()
    sdk.start_functions_matching.assert_not_called()


def test_failed_status_aborts_without_callback(service, sdk):
    sdk.get_functions_matching_status.return_value = _status("FAILED")

    cb = _run(service)

    cb.assert_not_called()
    sdk.get_functions_matches.assert_not_called()


def test_polls_until_status_complete(service, sdk):
    sdk.get_functions_matching_status.side_effect = [
        _status("RUNNING"),
        _status("COMPLETED"),
    ]
    sdk.get_functions_matches.return_value = _matches(matched=[_matched(9)])

    cb = _run(service)

    assert sdk.get_functions_matching_status.call_count == 2
    cb.assert_called_once()
