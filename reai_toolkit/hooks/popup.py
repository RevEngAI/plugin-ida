# from typing import Optional
#
# import ida_kernwin as kw
#
# from reai_toolkit.app import Coordinator
# from reai_toolkit.app.components.states.function_info import UIState
#
# # Keep handlers alive so IDA can call update()/activate()
# _HANDLERS = {}
#
#
# def _fast_update(coordinator, ctx):
#     try:
#         if not ctx or not ctx.widget:
#             return kw.AST_DISABLE_FOR_WIDGET
#         ui_state = getattr(coordinator, "ui_state", None)
#         if not ui_state:
#             return kw.AST_DISABLE_FOR_WIDGET
#
#         # (optional) debug
#         print(
#             f"[RevEng.AI] Popup action update: has_analysis={ui_state.has_analysis}, has_function={ui_state.has_function}"
#         )
#
#         if not (ui_state.has_analysis and ui_state.has_function):
#             return kw.AST_DISABLE_FOR_WIDGET
#         return kw.AST_ENABLE_FOR_WIDGET
#     except Exception as e:
#         print(f"[RevEng.AI] Popup action update error: {e}")
#         return kw.AST_DISABLE_FOR_WIDGET
#
#
# class AiDecompH(kw.action_handler_t):
#     """Calls Coordinator.enqueue_func_ai_decomp() when clicked."""
#
#     def __init__(self, coordinator: Coordinator):
#         super().__init__()
#         self.coordinator = coordinator
#
#     def activate(self, ctx):
#         self.coordinator.enqueue_func_ai_decomp()
#         return 1
#
#     def update(self, ctx):
#         return kw.AST_ENABLE_FOR_WIDGET
#
#
# class AnnH(kw.action_handler_t):
#     """Calls Coordinator.run_ann(limit_function=True) when clicked."""
#
#     def __init__(self, coordinator: Coordinator):
#         super().__init__()
#         self.coordinator = coordinator
#
#     def activate(self, ctx):
#         self.coordinator.run_ann(limit_function=True)
#         return 1
#
#     def update(self, ctx):
#         return kw.AST_ENABLE_FOR_WIDGET
#
#
#
#
# def register_ai_decomp_action(coordinator: Coordinator):
#     ACTION_NAME = "reveng:ai_decomp"
#     try:
#         kw.unregister_action(ACTION_NAME)
#     except Exception:
#         pass
#     h = AiDecompH(coordinator)
#     _HANDLERS[ACTION_NAME] = h
#     desc = kw.action_desc_t(
#         ACTION_NAME,
#         "AI Decomp",
#         h,
#         None,
#         "Decompile with RevEng.AI Decompiler",
#     )
#     kw.register_action(desc)
#     return ACTION_NAME
#
#
# def register_ann_action(coordinator: Coordinator):
#     ACTION_NAME = "reveng:ann"
#     try:
#         kw.unregister_action(ACTION_NAME)
#     except Exception:
#         pass
#     h = AnnH(coordinator)
#     _HANDLERS[ACTION_NAME] = h
#     desc = kw.action_desc_t(
#         ACTION_NAME,
#         "Match Function",
#         h,
#         None,
#         "Run RevEng.AI function ANN",
#     )
#     kw.register_action(desc)
#     return ACTION_NAME
#
#
# def register_function_view_action(coordinator: Coordinator):
#     ACTION_NAME = "reveng:function_view"
#     try:
#         kw.unregister_action(ACTION_NAME)
#     except Exception:
#         pass
#     h = FunctionViewH(coordinator)
#     _HANDLERS[ACTION_NAME] = h
#     desc = kw.action_desc_t(
#         ACTION_NAME,
#         "View function in Portal",
#         h,
#         None,
#         "Open function in RevEng.AI portal",
#     )
#     kw.register_action(desc)
#     return ACTION_NAME
#
#
# def build_hooks(coordinator: Coordinator):
#     """Attach our action directly to all popups (IDA 9.1 compatible)."""
#     decomp_action = register_ai_decomp_action(coordinator)
#     ann_action = register_ann_action(coordinator)
#     func_view_action = register_function_view_action(coordinator)
#
#     def _on_popup(widget, popup_handle):
#         # Ensure flags are up-to-date *now*
#         ui: Optional[UIState] = getattr(coordinator, "ui_state", None)
#         if ui is not None:
#             try:
#                 ui.refresh()
#             except Exception:
#                 print("[RevEng.AI] UIState.refresh() error in popup")
#                 pass
#
#             # Decide per-open whether to include each item
#             has_analysis = bool(ui and ui.has_analysis)
#             has_function = bool(ui and ui.has_function)
#             print(
#                 f"[RevEng.AI] Popup open: has_analysis={has_analysis}, has_function={has_function}"
#             )
#             allow = has_analysis and has_function
#
#             try:
#                 if allow:
#                     kw.attach_action_to_popup(
#                         widget, popup_handle, decomp_action, "RevEng.AI/", 0
#                     )
#                     kw.attach_action_to_popup(
#                         widget, popup_handle, ann_action, "RevEng.AI/", 0
#                     )
#                     kw.attach_action_to_popup(
#                         widget, popup_handle, func_view_action, "RevEng.AI/", 0
#                     )
#                 else:
#                     # Optionally, show a disabled-looking separator/label instead.
#                     # IDA popup API can't truly "disable" an action in-place, so the
#                     # standard approach is to simply not attach the item.
#                     pass
#             except Exception as e:
#                 print(f"[RevEng.AI] attach_action_to_popup error: {e}")
#
#     class Hooks(kw.UI_Hooks):
#         def finish_populating_widget_popup(self, widget, popup_handle):
#             _on_popup(widget, popup_handle)
#             return  # don’t return an int
#
#     h = Hooks()
#     return h
import ida_funcs
import ida_kernwin as kw
from loguru import logger

from reai_toolkit.app.coordinator import Coordinator

DECOMP_ACTION_NAME = "revengai:toggle_ai_decomp"
VIEW_ACTION_NAME = "revengai:function_portal_view"
MATCHING_ACTION_NAME = "revengai:function_matching_view"

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


class FunnctionMatchingViewH(kw.action_handler_t):
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
    h = FunnctionMatchingViewH(coordinator)
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


def build_hooks(coordinator: Coordinator):
    """Attach our action directly to all popups (IDA 9.1 compatible)."""
    decomp_action = _register_decomp_action(coordinator)
    func_view_action = _register_function_view_action(coordinator)
    func_matching_action = _register_function_matching_action(coordinator)

    def _on_popup(widget, popup_handle):
        try:
            current_func_ea = kw.get_screen_ea()
            current_func = ida_funcs.get_func(current_func_ea)

            func_map = (
                coordinator.app.analysis_sync_service.safe_get_function_mapping_local()
            )

            has_portal_func = (
                func_map is not None
                and func_map.inverse_function_map.get(str(current_func.start_ea), None)
                is not None
            )

            if has_portal_func:
                kw.attach_action_to_popup(
                    widget, popup_handle, decomp_action, "RevEng.AI/", 0
                )
                kw.attach_action_to_popup(
                    widget, popup_handle, func_view_action, "RevEng.AI/", 0
                )
                kw.attach_action_to_popup(
                    widget, popup_handle, func_matching_action, "RevEng.AI/", 0
                )
        except Exception as e:
            logger.error(f"[RevEng.AI] attach_action_to_popup error: {e}")

    class Hooks(kw.UI_Hooks):
        def finish_populating_widget_popup(self, widget, popup_handle):
            _on_popup(widget, popup_handle)
            return  # don’t return an int

    h = Hooks()
    return h
