from unittest.mock import MagicMock

import pytest
from revengai import (
    FunctionMatch,
    GetMatchesOutputBody,
    GetMatchesStatusOutputBody,
    ProgressMessage,
)

from reai_toolkit.app.services.matching import matching_service as svc_mod
from reai_toolkit.app.services.matching.matching_service import MatchingService
from reai_toolkit.app.services.matching.schema import (
    BatchDoneEvent,
    StartEvent,
    SummaryEvent,
)


@pytest.fixture(autouse=True)
def no_sleep(mocker):
    mocker.patch.object(svc_mod.time, "sleep", lambda *_: None)


@pytest.fixture
def netstore():
    ns = MagicMock()
    ns.get_model_name.return_value = "binnet-0.1"
    ns.get_binary_id.return_value = 7
    ns.get_analysis_id.return_value = 55
    return ns


@pytest.fixture
def service(netstore):
    return MatchingService(netstore_service=netstore, sdk_config=MagicMock())


@pytest.fixture
def search_api(mocker):
    mocker.patch.object(MatchingService, "yield_api_client")
    api_class = mocker.patch.object(svc_mod, "SearchApi")
    api_inst = MagicMock()
    api_class.return_value = api_inst
    return api_inst


@pytest.fixture
def collections_api(mocker):
    mocker.patch.object(MatchingService, "yield_api_client")
    api_class = mocker.patch.object(svc_mod, "CollectionsApi")
    api_inst = MagicMock()
    api_class.return_value = api_inst
    return api_inst


@pytest.fixture
def core_api(mocker):
    mocker.patch.object(MatchingService, "yield_api_client")
    api_class = mocker.patch.object(svc_mod, "FunctionsCoreApi")
    api_inst = MagicMock()
    api_class.return_value = api_inst
    return api_inst


def _match(function_id: int) -> FunctionMatch:
    return FunctionMatch.model_construct(
        function_id=function_id, matched_functions=[], confidences=[]
    )


def _status(
    status="COMPLETED", step_index=1, steps_total=1, messages=None
) -> GetMatchesStatusOutputBody:
    return GetMatchesStatusOutputBody.model_construct(
        status=status,
        step="match",
        step_index=step_index,
        steps_total=steps_total,
        messages=messages or [],
    )


def _matches(matches=None) -> GetMatchesOutputBody:
    return GetMatchesOutputBody.model_construct(
        status="COMPLETED", matches=matches or []
    )


def test_search_collections_returns_results(service, collections_api):
    results = [MagicMock(), MagicMock()]
    collections_api.v3_list_collections.return_value = MagicMock(results=results)

    out = service.search_collections("libc")

    assert out.success is True
    assert out.data == results
    collections_api.v3_list_collections.assert_called_once_with(
        search_term="libc", limit=50, offset=0
    )


def test_search_collections_failure_returns_empty_success(service, collections_api):
    collections_api.v3_list_collections.side_effect = RuntimeError("boom")

    out = service.search_collections("libc")

    assert out.success is True
    assert out.data == []


def test_search_binaries_queries_name_and_sha_excluding_current(service, search_api):
    search_api.search_binaries.return_value = MagicMock(
        data=MagicMock(results=[MagicMock()])
    )

    out = service.search_binaries("abc")

    assert out.success is True
    assert len(out.data) == 2  # one per call (name + sha)
    assert search_api.search_binaries.call_count == 2
    for call in search_api.search_binaries.call_args_list:
        assert call.kwargs["exclude_binary_id"] == 7
        assert call.kwargs["model_name"] == "binnet-0.1"


def test_perform_matching_emits_start_batch_summary_and_filters_results(service, core_api):
    core_api.get_functions_matching_status.return_value = _status()
    core_api.get_functions_matches.return_value = _matches(
        [_match(1), _match(2), _match(3)]
    )

    events = list(
        service.perform_matching(
            function_ids=[1, 3], analysis_func_count=10, min_similarity=90
        )
    )

    assert isinstance(events[0], StartEvent)
    assert any(isinstance(e, BatchDoneEvent) and e.ok for e in events)
    summary = events[-1]
    assert isinstance(summary, SummaryEvent)
    assert summary.ok is True
    assert sorted(m.function_id for m in summary.results) == [1, 3]


def test_perform_matching_uses_nns_1_for_multiple_functions(service, core_api):
    core_api.get_functions_matching_status.return_value = _status()
    core_api.get_functions_matches.return_value = _matches([_match(1)])

    list(service.perform_matching([1, 2], analysis_func_count=10, min_similarity=90))

    body = core_api.start_functions_matching.call_args.args[0]
    assert body.results_per_function == 1


def test_perform_matching_uses_nns_10_for_single_function(service, core_api):
    core_api.get_functions_matching_status.return_value = _status()
    core_api.get_functions_matches.return_value = _matches([_match(1)])

    list(service.perform_matching([1], analysis_func_count=10, min_similarity=90))

    body = core_api.start_functions_matching.call_args.args[0]
    assert body.results_per_function == 10


def test_perform_matching_debug_all_sets_system_and_user(service, core_api):
    core_api.get_functions_matching_status.return_value = _status()
    core_api.get_functions_matches.return_value = _matches([])

    list(
        service.perform_matching(
            [1], analysis_func_count=10, min_similarity=90, debug_all=True
        )
    )

    body = core_api.start_functions_matching.call_args.args[0]
    assert body.filters.debug_types == ["USER", "SYSTEM"]


def test_perform_matching_failed_status_yields_failure_summary(service, core_api):
    core_api.get_functions_matching_status.return_value = _status(
        status="FAILED",
        step_index=0,
        messages=[
            ProgressMessage.model_construct(
                level="ERROR", step="match", text="matching exploded", timestamp=None
            )
        ],
    )

    events = list(
        service.perform_matching([1], analysis_func_count=10, min_similarity=90)
    )

    summary = events[-1]
    assert isinstance(summary, SummaryEvent)
    assert summary.ok is False
    assert "matching exploded" in summary.errors
    core_api.get_functions_matches.assert_not_called()


def test_perform_matching_polls_until_completed(service, core_api):
    core_api.get_functions_matching_status.side_effect = [
        _status(status="RUNNING", step_index=0, steps_total=2),
        _status(status="COMPLETED", step_index=2, steps_total=2),
    ]
    core_api.get_functions_matches.return_value = _matches([_match(1)])

    events = list(
        service.perform_matching([1], analysis_func_count=10, min_similarity=90)
    )

    assert core_api.get_functions_matching_status.call_count == 2
    assert events[-1].ok is True


def test_perform_matching_start_failure_yields_failure_summary(service, core_api):
    core_api.start_functions_matching.side_effect = RuntimeError("down")

    events = list(
        service.perform_matching([1], analysis_func_count=10, min_similarity=90)
    )

    assert isinstance(events[-1], SummaryEvent)
    assert events[-1].ok is False
    core_api.get_functions_matching_status.assert_not_called()
