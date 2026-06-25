import pytest
from revengai.models.function_mapping import FunctionMapping

from reai_toolkit.app.core import netstore_service as ns_mod
from reai_toolkit.app.core.netstore_service import SimpleNetStore

pytestmark = pytest.mark.idalib


@pytest.fixture
def store(loaded_binary):
    ns_mod._CACHE.clear()
    s = SimpleNetStore(node_name="$ test_reai_db")
    s.clear_all_ns()
    yield s
    s.clear_all_ns()
    ns_mod._CACHE.clear()


def test_global_round_trip(store):
    assert store.put_global("cfg", {"a": 1, "b": [1, 2, 3]})
    assert store.get_global("cfg") == {"a": 1, "b": [1, 2, 3]}


def test_missing_key_returns_default(store):
    assert store.get_global("absent", default="fallback") == "fallback"


def test_namespaces_are_isolated(store):
    store.put("x", 1, ns="alpha")
    store.put("x", 2, ns="beta")

    assert store.get("x", ns="alpha") == 1
    assert store.get("x", ns="beta") == 2
    assert store.keys("alpha") == ["x"]


def test_large_value_round_trips(store):
    big = {"data": [{"i": i, "s": "x" * 8} for i in range(4000)]}
    assert store.put_global("big", big)
    assert store.get_global("big") == big


def test_delete_and_exists(store):
    store.put_global("k", 123)
    assert store.exists("k") is True

    assert store.delete("k") is True
    assert store.exists("k") is False
    assert store.get_global("k") is None


def test_clear_ns_removes_all_in_namespace(store):
    store.put("a", 1, ns="ns")
    store.put("b", 2, ns="ns")

    assert store.clear_ns("ns") == 2
    assert store.keys("ns") == []


def test_id_helpers_round_trip(store):
    assert store.put_binary_id(111)
    assert store.get_binary_id() == 111
    assert store.put_analysis_id(222)
    assert store.get_analysis_id() == 222
    assert store.put_model_id(333)
    assert store.get_model_id() == 333
    assert store.put_model_name("binnet-0.1")
    assert store.get_model_name() == "binnet-0.1"


def test_function_mapping_round_trip(store):
    fm = FunctionMapping(
        function_map={"1": 4096},
        inverse_function_map={"4096": 1},
        name_map={"4096": "main"},
    )
    assert store.put_function_mapping(fm)

    got = store.get_function_mapping()
    assert isinstance(got, FunctionMapping)
    assert got.function_map == {"1": 4096}
    assert got.inverse_function_map == {"4096": 1}
    assert got.name_map == {"4096": "main"}
