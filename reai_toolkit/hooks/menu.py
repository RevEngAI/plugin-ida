from importlib.metadata import version

import ida_kernwin  # type: ignore

from reai_toolkit.app.coordinator import Coordinator
import reai_toolkit.hooks.globals as menu_hook_globals


MENU_TITLE: str = "RevEng.AI"
MENU_ROOT: str = MENU_TITLE + "/"


class PingH(ida_kernwin.action_handler_t):
    def activate(self, ctx) -> int:
        ida_kernwin.info("Pong from RevEng.AI!")
        return 1

    def update(self, ctx) -> int:
        return ida_kernwin.AST_ENABLE


class AboutH(ida_kernwin.action_handler_t):
    def __init__(self, coordinator: Coordinator) -> None:
        super().__init__()
        self.coordinator: Coordinator = coordinator

    def activate(self, ctx) -> int:
        self.coordinator.aboutc.run_dialog()
        return 1

    def update(self, ctx) -> int:
        return ida_kernwin.AST_ENABLE_ALWAYS


class VersionH(ida_kernwin.action_handler_t):
    def __init__(self, version: str = "unknown") -> None:
        super().__init__()
        self.version: str = version

    def activate(self, ctx) -> int:
        ida_kernwin.info(
            f"RevEng.AI Toolkit Version: {self.version}\nRevEng.AI SDK Version: {version('revengai')}"
        )
        return 1

    def update(self, ctx) -> int:
        return ida_kernwin.AST_ENABLE_ALWAYS


class AuthH(ida_kernwin.action_handler_t):
    def __init__(self, coordinator: Coordinator) -> None:
        super().__init__()
        self.coordinator: Coordinator = coordinator

    def activate(self, ctx) -> int:
        self.coordinator.authc.run_dialog()
        return 1

    def update(self, ctx) -> int:
        return ida_kernwin.AST_ENABLE_ALWAYS


class AnalyseH(ida_kernwin.action_handler_t):
    def __init__(self, coordinator: Coordinator) -> None:
        super().__init__()
        self.coordinator: Coordinator = coordinator

    def activate(self, ctx) -> int:
        self.coordinator.create_analysisc.run_dialog()
        return 1

    def update(self, ctx) -> int:
        is_authed: bool = self.coordinator.app.auth_service.is_authenticated()
        if is_authed is False or menu_hook_globals.ANALYSIS_ID is not None:
            return ida_kernwin.AST_DISABLE
        return ida_kernwin.AST_ENABLE


class SyncH(ida_kernwin.action_handler_t):
    def __init__(self, coordinator: Coordinator) -> None:
        super().__init__()
        self.coordinator: Coordinator = coordinator

    def activate(self, ctx) -> int:
        self.coordinator.sync_analysisc.sync_analysis()
        return 1

    def update(self, ctx) -> int:
        is_authed: bool = self.coordinator.app.auth_service.is_authenticated()

        if is_authed is False or menu_hook_globals.ANALYSIS_ID is None:
            return ida_kernwin.AST_DISABLE
        return ida_kernwin.AST_ENABLE


class DetachAnalysisH(ida_kernwin.action_handler_t):
    def __init__(self, coordinator: Coordinator) -> None:
        super().__init__()
        self.coordinator: Coordinator = coordinator

    def activate(self, ctx) -> int:
        self.coordinator.detachc.run_dialog()
        menu_hook_globals.ANALYSIS_ID = None
        menu_hook_globals.BINARY_ID = None
        menu_hook_globals.MODEL_ID = None
        return 1

    def update(self, ctx) -> int:
        if menu_hook_globals.ANALYSIS_ID is None:
            return ida_kernwin.AST_DISABLE
        return ida_kernwin.AST_ENABLE


class ViewAnalysisH(ida_kernwin.action_handler_t):
    def __init__(self, coordinator: Coordinator) -> None:
        super().__init__()
        self.coordinator: Coordinator = coordinator

    def activate(self, ctx) -> int:
        self.coordinator.redirect_analysis_portal()
        return 1

    def update(self, ctx) -> int:
        if menu_hook_globals.BINARY_ID is None:
            return ida_kernwin.AST_DISABLE
        return ida_kernwin.AST_ENABLE


class ExistingAnalysesH(ida_kernwin.action_handler_t):
    def __init__(self, coordinator: Coordinator) -> None:
        super().__init__()
        self.coordinator: Coordinator = coordinator

    def activate(self, ctx) -> int:
        self.coordinator.existing_analysisc.run_dialog()
        return 1

    def update(self, ctx) -> int:
        is_authed: bool = self.coordinator.app.auth_service.is_authenticated()

        if is_authed is False or menu_hook_globals.ANALYSIS_ID is not None:
            return ida_kernwin.AST_DISABLE
        return ida_kernwin.AST_ENABLE


class AutoUnstripH(ida_kernwin.action_handler_t):
    def __init__(self, coordinator: Coordinator) -> None:
        super().__init__()
        self.coordinator: Coordinator = coordinator

    def activate(self, ctx) -> int:
        self.coordinator.auto_unstripc.run_dialog()
        return 1

    def update(self, ctx) -> int:
        if menu_hook_globals.MODEL_ID is None:
            return ida_kernwin.AST_DISABLE
        return ida_kernwin.AST_ENABLE


class MatchingH(ida_kernwin.action_handler_t):
    def __init__(self, coordinator: Coordinator) -> None:
        super().__init__()
        self.coordinator: Coordinator = coordinator

    def activate(self, ctx) -> int:
        self.coordinator.matchingc.fetch_functions()
        return 1

    def update(self, ctx) -> int:
        if menu_hook_globals.MODEL_ID is None:
            return ida_kernwin.AST_DISABLE
        return ida_kernwin.AST_ENABLE


def _safe_detach(aid: str, path: str) -> None:
    try:
        ida_kernwin.detach_action_from_menu(path, aid)
    except Exception:
        pass


def _safe_unregister(aid: str) -> None:
    try:
        ida_kernwin.unregister_action(aid)
    except Exception:
        pass


def register_menu_hooks(coordinator: Coordinator, plugin_version: str) -> dict:
    _handlers: dict[str, ida_kernwin.action_handler_t] = {
        "ping": PingH(),
        "about": AboutH(coordinator),
        "help": VersionH(version=plugin_version),
        "auth": AuthH(coordinator),
        "analyse": AnalyseH(coordinator),
        "autounstrip": AutoUnstripH(coordinator),
        "sync_and_poll": SyncH(coordinator),
        "function_match": MatchingH(coordinator),
        "existing_analysis": ExistingAnalysesH(coordinator),
        "detach_analysis": DetachAnalysisH(coordinator),
        "view_analysis": ViewAnalysisH(coordinator),
    }

    all_aids: list[str] = [
        "reai:analyse",
        "reai:existing_analysis",
        "reai:detach_analysis",
        "reai:sync_and_poll",
        "reai:view_analysis",
        "reai:autounstrip",
        "reai:function_match",
        "reai:auth",
        "reai:help",
        "reai:about",
        "reai:ping",
        "reai:separator",
    ]
    for aid in all_aids:
        _safe_detach(aid, MENU_ROOT + "Analysis/")
        _safe_detach(aid, MENU_ROOT)
        _safe_unregister(aid)

    ida_kernwin.register_action(
        ida_kernwin.action_desc_t("reai:ping", "Ping", _handlers["ping"])
    )
    ida_kernwin.register_action(
        ida_kernwin.action_desc_t("reai:about", "About", _handlers["about"])
    )

    ida_kernwin.register_action(
        ida_kernwin.action_desc_t("reai:help", "Help", _handlers["help"])
    )

    ida_kernwin.register_action(
        ida_kernwin.action_desc_t("reai:auth", "Configure", _handlers["auth"])
    )

    ida_kernwin.register_action(
        ida_kernwin.action_desc_t("reai:analyse", "Create new", _handlers["analyse"])
    )

    ida_kernwin.register_action(
        ida_kernwin.action_desc_t(
            "reai:existing_analysis",
            "Attach to existing",
            _handlers["existing_analysis"],
        )
    )
    #
    ida_kernwin.register_action(
        ida_kernwin.action_desc_t(
            "reai:detach_analysis", "Detach", _handlers["detach_analysis"]
        )
    )

    ida_kernwin.register_action(
        ida_kernwin.action_desc_t(
            "reai:sync_and_poll", "Check status", _handlers["sync_and_poll"]
        )
    )

    ida_kernwin.register_action(
        ida_kernwin.action_desc_t(
            "reai:view_analysis", "View in portal", _handlers["view_analysis"]
        )
    )

    ida_kernwin.register_action(
        ida_kernwin.action_desc_t(
            "reai:autounstrip", "Auto Unstrip", _handlers["autounstrip"]
        )
    )

    ida_kernwin.register_action(
        ida_kernwin.action_desc_t(
            "reai:function_match", "Function Matching", _handlers["function_match"]
        )
    )

    ida_kernwin.create_menu("reai:menubar", MENU_TITLE, "View")
    ida_kernwin.attach_action_to_menu(
        MENU_ROOT + "Analysis/", "reai:analyse", ida_kernwin.SETMENU_APP
    )
    ida_kernwin.attach_action_to_menu(
        MENU_ROOT + "Analysis/", "reai:existing_analysis", ida_kernwin.SETMENU_APP
    )
    ida_kernwin.attach_action_to_menu(
        MENU_ROOT + "Analysis/", "reai:detach_analysis", ida_kernwin.SETMENU_APP
    )
    ida_kernwin.attach_action_to_menu(
        MENU_ROOT + "Analysis/", "reai:sync_and_poll", ida_kernwin.SETMENU_APP
    )
    ida_kernwin.attach_action_to_menu(
        MENU_ROOT + "Analysis/", "reai:view_analysis", ida_kernwin.SETMENU_APP
    )

    ida_kernwin.attach_action_to_menu(
        MENU_ROOT + "Auto Unstrip", "reai:autounstrip", ida_kernwin.SETMENU_APP
    )
    ida_kernwin.attach_action_to_menu(
        MENU_ROOT + "Function Matching", "reai:function_match", ida_kernwin.SETMENU_APP
    )

    ida_kernwin.attach_action_to_menu(
        MENU_ROOT + "Configure", "reai:auth", ida_kernwin.SETMENU_APP
    )
    ida_kernwin.attach_action_to_menu(
        MENU_ROOT + "Help", "reai:help", ida_kernwin.SETMENU_APP
    )
    ida_kernwin.attach_action_to_menu(
        MENU_ROOT + "About", "reai:about", ida_kernwin.SETMENU_APP
    )
    ida_kernwin.refresh_idaview_anyway()
    return _handlers
