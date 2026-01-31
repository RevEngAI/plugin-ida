import ida_funcs
import ida_kernwin as kw
from loguru import logger
from revengai import FunctionMapping

from reai_toolkit.app.coordinator import Coordinator

DECOMP_ACTION_NAME = "revengai:toggle_ai_decomp"
VIEW_ACTION_NAME = "revengai:function_portal_view"
MATCHING_ACTION_NAME = "revengai:function_matching_view"
SIMILARITY_ACTION_NAME = "revengai:function_similarity_view"

_HANDLERS = {}


class ToggleAiDecompH(kw.action_handler_t):
    def __init__(self, coordinator: Coordinator):
        super().__init__()
        self.coordinator = coordinator

    def activate(self, ctx):
        """Triggered when user selects the action from the popup menu."""
        self.coordinator.ai_decompc.enable_function_tracking()
        return 1

    def update(self, ctx):
        return kw.AST_ENABLE


def _register_decomp_action(coordinator: Coordinator):
    try:
        kw.unregister_action(DECOMP_ACTION_NAME)
    except Exception:
        pass
    h = ToggleAiDecompH(coordinator)
    _HANDLERS[DECOMP_ACTION_NAME] = h
    desc = kw.action_desc_t(
        DECOMP_ACTION_NAME,
        "AI Decomp",
        h,
        None,
        "Decompile with RevEng.AI Decompiler",
    )
    kw.register_action(desc)
    return DECOMP_ACTION_NAME


class FunctionPortalViewH(kw.action_handler_t):
    """Calls Coordinator.redirect_function_portal() when clicked."""

    def __init__(self, coordinator: Coordinator):
        super().__init__()
        self.coordinator = coordinator

    def activate(self, ctx):
        self.coordinator.redirect_function_portal()
        return 1

    def update(self, ctx):
        return kw.AST_ENABLE_FOR_WIDGET


def _register_function_view_action(coordinator: Coordinator):
    try:
        kw.unregister_action(VIEW_ACTION_NAME)
    except Exception:
        pass
    h = FunctionPortalViewH(coordinator)
    _HANDLERS[VIEW_ACTION_NAME] = h
    desc = kw.action_desc_t(
        VIEW_ACTION_NAME,
        "View function in Portal",
        h,
        None,
        "Open function in RevEng.AI portal",
    )
    kw.register_action(desc)
    return VIEW_ACTION_NAME


class FunctionMatchingViewH(kw.action_handler_t):
    def __init__(self, coordinator: Coordinator):
        super().__init__()
        self.coordinator = coordinator

    def activate(self, ctx):
        self.coordinator.matchingc.fetch_functions(restrict_function_id=True)
        return 1

    def update(self, ctx):
        return kw.AST_ENABLE_FOR_WIDGET


def _register_function_matching_action(coordinator: Coordinator):
    try:
        kw.unregister_action(MATCHING_ACTION_NAME)
    except Exception:
        pass
    h = FunctionMatchingViewH(coordinator)
    _HANDLERS[MATCHING_ACTION_NAME] = h
    desc = kw.action_desc_t(
        MATCHING_ACTION_NAME,
        "Match Function",
        h,
        None,
        "Run RevEng.AI function matching",
    )
    kw.register_action(desc)
    return MATCHING_ACTION_NAME


class FunctionSimilarityViewH(kw.action_handler_t):
    def __init__(self, coordinator: Coordinator):
        super().__init__()
        self.coordinator: Coordinator = coordinator

    def activate(self, ctx):
        self.coordinator.similarityc.enable_function_tracking()
        return 1

    def update(self, ctx):
        return kw.AST_ENABLE_FOR_WIDGET


def _register_function_similarity_action(coordinator: Coordinator):
    try:
        kw.unregister_action(SIMILARITY_ACTION_NAME)
    except Exception:
        pass
    h = FunctionSimilarityViewH(coordinator)  # type: ignore
    _HANDLERS[SIMILARITY_ACTION_NAME] = h
    desc = kw.action_desc_t(
        SIMILARITY_ACTION_NAME,
        "Find Similar Functions",
        h,
        None,
        "Run RevEng.AI function matching and show similar functions in dockable tab",
    )
    kw.register_action(desc)
    return SIMILARITY_ACTION_NAME


def build_hooks(coordinator: Coordinator):
    """Attach our action directly to all popups (IDA 9.1 compatible)."""
    decomp_action = _register_decomp_action(coordinator)
    func_view_action = _register_function_view_action(coordinator)
    func_matching_action = _register_function_matching_action(coordinator)
    func_similarity_action = _register_function_similarity_action(coordinator)

    def _on_popup(widget, popup_handle) -> None:
        try:
            current_func_ea: int | None = kw.get_screen_ea()
            current_func: ida_funcs.func_t | None = ida_funcs.get_func(current_func_ea)

            func_map: FunctionMapping | None = (
                coordinator.app.analysis_sync_service.netstore_service.get_function_mapping()
            )

            if func_map and current_func and func_map.inverse_function_map.get(str(current_func.start_ea)):
                kw.attach_action_to_popup(
                    widget, popup_handle, decomp_action, "RevEng.AI/", 0
                )
                kw.attach_action_to_popup(
                    widget, popup_handle, func_view_action, "RevEng.AI/", 0
                )
                kw.attach_action_to_popup(
                    widget, popup_handle, func_matching_action, "RevEng.AI/", 0
                )
                kw.attach_action_to_popup(
                    widget, popup_handle, func_similarity_action, "RevEng.AI/", 0
                )
        except Exception as e:
            logger.error(f"[RevEng.AI] attach_action_to_popup error: {e}")

    class Hooks(kw.UI_Hooks):
        def finish_populating_widget_popup(self, widget, popup_handle) -> None:
            _on_popup(widget, popup_handle)

    h = Hooks() # type: ignore
    return h
