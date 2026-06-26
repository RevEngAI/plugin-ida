import pytest

import ida_dirtree
import ida_name
import idaapi
import idc

from reai_toolkit.app.interfaces.base_service import BaseService

pytestmark = pytest.mark.idalib


@pytest.fixture
def add_func(loaded_binary):
    ea = idc.get_name_ea_simple("add")
    assert ea != idaapi.BADADDR, "fixture binary missing 'add'"
    original = ida_name.get_name(ea)
    yield ea
    ida_name.set_name(ea, original, ida_name.SN_CHECK)


def test_update_function_name_renames(add_func):
    assert BaseService.update_function_name(add_func, "reai_renamed") is True
    assert ida_name.get_name(add_func) == "reai_renamed"


def test_update_function_name_idempotent_when_unchanged(add_func):
    BaseService.update_function_name(add_func, "reai_same")
    assert BaseService.update_function_name(add_func, "reai_same") is True


def test_update_function_name_respects_user_names(add_func):
    ida_name.set_name(add_func, "user_picked", ida_name.SN_CHECK)

    result = BaseService.update_function_name(
        add_func, "auto_pick", check_user_flags=True
    )

    assert result is False
    assert ida_name.get_name(add_func) == "user_picked"


def test_tag_function_as_renamed_creates_revengai_dir(add_func):
    BaseService.update_function_name(add_func, "tagged_fn")
    BaseService.tag_function_as_renamed("tagged_fn")

    dirtree = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)
    assert dirtree.isdir("/RevEng.AI")
