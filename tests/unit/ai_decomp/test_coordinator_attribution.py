import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, call

import pytest

# The coordinator's imports reach Qt, which only loads inside the IDA GUI.
_QT_BOUND = (
    "reai_toolkit.app.app",
    "reai_toolkit.app.factory",
    "reai_toolkit.app.components.tabs.ai_decomp_tab",
)
_stubbed = [name for name in _QT_BOUND if name not in sys.modules]
for name in _stubbed:
    sys.modules[name] = MagicMock()
import reai_toolkit.app.coordinators.ai_decomp_coordinator as coord_mod
from reai_toolkit.app.coordinators.ai_decomp_coordinator import (
    AiDecompCoordinator,
)

for name in _stubbed:
    del sys.modules[name]

from reai_toolkit.app.coordinators.ai_decomp_render import RenderModel
from reai_toolkit.app.services.ai_decomp.attribution import (
    AttributionMap,
    invert_attributions,
)

FUNC_START = 0x1000


@pytest.fixture
def kw(mocker):
    kw = mocker.patch.object(coord_mod, "ida_kernwin")
    mocker.patch.object(coord_mod, "ida_funcs").get_func.return_value = SimpleNamespace(
        start_ea=FUNC_START
    )
    return kw


@pytest.fixture
def coord(kw):
    c = AiDecompCoordinator(
        app=MagicMock(), factory=MagicMock(), log=MagicMock(), ai_decomp_service=MagicMock()
    )
    c.refresh_disassembly_view = MagicMock()
    c._decomp_view = MagicMock()
    c._attribution_hooks = MagicMock()
    c._baseline = RenderModel(
        summary_line_count=0,
        code_lines=["int f() {", "  int a = 1;", "  return a;", "}"],
        comment_by_source={},
        display_source=[1, 2, 3, 4],
        display_is_code=[True] * 4,
    )
    # decomp row 1 <- 0x1001, decomp row 2 <- 0x1006
    c._current_attributions = AttributionMap(
        invert_attributions({"0": [1], "1": [2]}), [FUNC_START, 0x1001, 0x1006]
    )
    return c


def lit_addresses(c):
    return c._attribution_hooks.set_addresses.call_args[0][0]


def lit_rows(c):
    return c._decomp_view.set_highlighted_lines.call_args[0][0]


def test_decomp_line_lights_itself_and_its_disassembly(coord, kw):
    coord.focus_decomp_line(1)

    assert lit_addresses(coord) == frozenset({0x1001})
    assert lit_rows(coord) == (1,)
    assert kw.jumpto.call_args_list == [
        call(FUNC_START, -1, kw.UIJMP_DONTPUSH),
        call(0x1001, -1, kw.UIJMP_DONTPUSH),
    ]


def test_own_jumps_do_not_count_as_disassembly_moves(coord, kw):
    coord.focus_decomp_line(1)
    coord.on_disassembly_ea(FUNC_START)
    coord.on_disassembly_ea(0x1001)

    assert lit_addresses(coord) == frozenset({0x1001})
    assert lit_rows(coord) == (1,)


def test_moving_within_a_line_does_not_jump_again(coord, kw):
    coord.focus_decomp_line(1)
    coord.focus_decomp_line(1)

    assert kw.jumpto.call_count == 2


def test_unattributed_line_clears_everything(coord, kw):
    coord.focus_decomp_line(1)
    coord.focus_decomp_line(0)

    assert lit_addresses(coord) == frozenset()
    assert lit_rows(coord) == ()
    assert kw.jumpto.call_count == 2


def test_disassembly_move_clears_disassembly_and_reveals_decomp(coord, kw):
    coord.focus_decomp_line(1)
    coord.on_disassembly_ea(FUNC_START)
    coord.on_disassembly_ea(0x1001)

    coord.on_disassembly_ea(0x1006)

    assert lit_addresses(coord) == frozenset()
    assert lit_rows(coord) == (2,)
    coord._decomp_view.reveal_line.assert_called_with(2)


def test_returning_to_a_line_after_a_disassembly_move_lights_it_again(coord, kw):
    coord.focus_decomp_line(1)
    coord.on_disassembly_ea(FUNC_START)
    coord.on_disassembly_ea(0x1001)
    coord.on_disassembly_ea(0x1006)

    coord.focus_decomp_line(1)

    assert lit_addresses(coord) == frozenset({0x1001})
    assert kw.jumpto.call_count == 4


def test_no_jump_to_where_the_cursor_already_is(coord, kw):
    kw.get_screen_ea.return_value = FUNC_START

    coord.focus_decomp_line(1)
    coord.on_disassembly_ea(0x1001)
    coord.on_disassembly_ea(FUNC_START)

    assert kw.jumpto.call_args_list == [call(0x1001, -1, kw.UIJMP_DONTPUSH)]
    assert lit_rows(coord) == ()
