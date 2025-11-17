from importlib.metadata import version

import ida_kernwin

from reai_toolkit.app.coordinator import Coordinator

MENU_TITLE = "RevEng.AI"
MENU_ROOT = MENU_TITLE + "/"


class PingH(ida_kernwin.action_handler_t):
    def activate(self, ctx):
        ida_kernwin.info("Pong from RevEng.AI!")
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE


class AboutH(ida_kernwin.action_handler_t):
    def __init__(self, coordinator: Coordinator):
        super().__init__()
        self.coordinator = coordinator

    def activate(self, ctx):
        self.coordinator.aboutc.run_dialog()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class VersionH(ida_kernwin.action_handler_t):
    def __init__(self, version: str = "unknown"):
        super().__init__()
        self.version = version

    def activate(self, ctx):
        ida_kernwin.info(
            f"RevEng.AI Toolkit Version: {self.version}\nRevEng.AI SDK Version: {version('revengai')}"
        )
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class AuthH(ida_kernwin.action_handler_t):
    """Calls Coordinator.run_auth() when clicked."""

    def __init__(self, coordinator: Coordinator):
        super().__init__()
        self.coordinator = coordinator

    def activate(self, ctx):
        self.coordinator.authc.run_dialog()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class AnalyseH(ida_kernwin.action_handler_t):
    """Calls Coordinator.run_auth() when clicked."""

    def __init__(self, coordinator: Coordinator):
        super().__init__()
        self.coordinator = coordinator

    def activate(self, ctx):
        self.coordinator.create_analysisc.run_dialog()
        return 1

    def update(self, ctx):
        is_authed = self.coordinator.app.auth_service.is_authenticated()
        analysis_id = self.coordinator.app.upload_service.safe_get_analysis_id_local()

        # print(f"AnalyseH.update: is_authed={is_authed}, analysis_id={analysis_id}")

        if not is_authed or analysis_id is not None:
            return ida_kernwin.AST_DISABLE
        return ida_kernwin.AST_ENABLE


class SyncH(ida_kernwin.action_handler_t):
    """Calls Coordinator.run_auth() when clicked."""

    def __init__(self, coordinator: Coordinator):
        super().__init__()
        self.coordinator = coordinator

    def activate(self, ctx):
        self.coordinator.sync_analysisc.sync_analysis()
        return 1

    def update(self, ctx):
        is_authed = self.coordinator.app.auth_service.is_authenticated()
        analysis_id = self.coordinator.app.analysis_sync_service.safe_get_analysis_id_local()

        if not is_authed or analysis_id is None:
            return ida_kernwin.AST_DISABLE
        return ida_kernwin.AST_ENABLE


class DetachAnalysisH(ida_kernwin.action_handler_t):
    """Calls Coordinator.run_auth() when clicked."""

    def __init__(self, coordinator: Coordinator):
        super().__init__()
        self.coordinator = coordinator

    def activate(self, ctx):
        self.coordinator.detachc.run_dialog()
        return 1

    def update(self, ctx):
        analysis_id = self.coordinator.app.analysis_sync_service.safe_get_analysis_id_local()

        if analysis_id is None:
            return ida_kernwin.AST_DISABLE
        return ida_kernwin.AST_ENABLE


class ViewAnalysisH(ida_kernwin.action_handler_t):
    """Calls Coordinator.run_auth() when clicked."""

    def __init__(self, coordinator: Coordinator):
        super().__init__()
        self.coordinator = coordinator

    def activate(self, ctx):
        self.coordinator.redirect_analysis_portal()
        return 1

    def update(self, ctx):
        binary_id = self.coordinator.app.analysis_sync_service.safe_get_binary_id_local()
        if binary_id is None:
            return ida_kernwin.AST_DISABLE
        return ida_kernwin.AST_ENABLE


class ExistingAnalysesH(ida_kernwin.action_handler_t):
    """Calls Coordinator.run_auth() when clicked."""

    def __init__(self, coordinator: Coordinator):
        super().__init__()
        self.coordinator = coordinator

    def activate(self, ctx):
        self.coordinator.existing_analysisc.run_dialog()
        return 1

    def update(self, ctx):
        is_authed = self.coordinator.app.auth_service.is_authenticated()
        analysis_id = self.coordinator.app.upload_service.safe_get_analysis_id_local()

        if not is_authed or analysis_id is not None:
            return ida_kernwin.AST_DISABLE
        return ida_kernwin.AST_ENABLE


class AutoUnstripH(ida_kernwin.action_handler_t):
    """Calls Coordinator.run_auth() when clicked."""

    def __init__(self, coordinator: Coordinator):
        super().__init__()
        self.coordinator = coordinator

    def activate(self, ctx):
        self.coordinator.auto_unstripc.run_dialog()
        return 1

    def update(self, ctx):
        model_id = self.coordinator.app.matching_service.safe_get_model_id_local()

        if model_id is None:
            return ida_kernwin.AST_DISABLE
        return ida_kernwin.AST_ENABLE


class MatchingH(ida_kernwin.action_handler_t):
    def __init__(self, coordinator: Coordinator):
        super().__init__()
        self.coordinator = coordinator

    def activate(self, ctx):
        self.coordinator.matchingc.fetch_functions()
        return 1

    def update(self, ctx):
        model_id = self.coordinator.app.matching_service.safe_get_model_id_local()

        if model_id is None:
            return ida_kernwin.AST_DISABLE
        return ida_kernwin.AST_ENABLE


def _safe_detach(aid: str, path: str):
    try:
        ida_kernwin.detach_action_from_menu(path, aid)
    except Exception:
        pass


def _safe_unregister(aid: str):
    try:
        ida_kernwin.unregister_action(aid)
    except Exception:
        pass


def register_menu_hooks(coordinator: Coordinator, plugin_version: str) -> dict:
    _handlers = {
        "ping": PingH(),
        "help": AboutH(coordinator),
        "about": VersionH(version=plugin_version),
        "auth": AuthH(coordinator),
        "analyse": AnalyseH(coordinator),
        "autounstrip": AutoUnstripH(coordinator),
        "sync_and_poll": SyncH(coordinator),
        "function_match": MatchingH(coordinator),
        "existing_analysis": ExistingAnalysesH(coordinator),
        "detatch_analysis": DetachAnalysisH(coordinator),
        "view_analysis": ViewAnalysisH(coordinator),
    }

    all_aids = [
        "reai:analyse",
        "reai:existing_analysis",
        "reai:detatch_analysis",
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

    # Register actions
    ida_kernwin.register_action(ida_kernwin.action_desc_t("reai:ping", "Ping", _handlers["ping"]))
    ida_kernwin.register_action(
        ida_kernwin.action_desc_t("reai:about", "About", _handlers["about"])
    )

    ida_kernwin.register_action(ida_kernwin.action_desc_t("reai:help", "Help", _handlers["help"]))

    # Auth action registration
    ida_kernwin.register_action(
        ida_kernwin.action_desc_t("reai:auth", "Configure", _handlers["auth"])
    )

    # Analyse action registration
    ida_kernwin.register_action(
        ida_kernwin.action_desc_t("reai:analyse", "Create new", _handlers["analyse"])
    )
    #
    # Analyse action registration
    ida_kernwin.register_action(
        ida_kernwin.action_desc_t(
            "reai:existing_analysis",
            "Attach to existing",
            _handlers["existing_analysis"],
        )
    )
    #
    # Analyse action registration
    ida_kernwin.register_action(
        ida_kernwin.action_desc_t("reai:detatch_analysis", "Detach", _handlers["detatch_analysis"])
    )
    #
    # Sync & Poll Analysis action registration
    ida_kernwin.register_action(
        ida_kernwin.action_desc_t("reai:sync_and_poll", "Check status", _handlers["sync_and_poll"])
    )
    #
    # View portal action registration
    ida_kernwin.register_action(
        ida_kernwin.action_desc_t(
            "reai:view_analysis", "View in portal", _handlers["view_analysis"]
        )
    )

    # Auto Unstrip action registration
    ida_kernwin.register_action(
        ida_kernwin.action_desc_t("reai:autounstrip", "Auto Unstrip", _handlers["autounstrip"])
    )

    # Auto Unstrip action registration
    ida_kernwin.register_action(
        ida_kernwin.action_desc_t(
            "reai:function_match", "Function Matching", _handlers["function_match"]
        )
    )
    #
    # class _SepH(ida_kernwin.action_handler_t):
    #     def activate(self, ctx):
    #         return 1
    #
    #     def update(self, ctx):
    #         return ida_kernwin.AST_DISABLE
    #
    # ida_kernwin.register_action(
    #     ida_kernwin.action_desc_t("reai:separator", "-", _SepH())
    # )

    ida_kernwin.create_menu("reai:menubar", MENU_TITLE, "View")
    ida_kernwin.attach_action_to_menu(
        MENU_ROOT + "Analysis/", "reai:analyse", ida_kernwin.SETMENU_APP
    )
    ida_kernwin.attach_action_to_menu(
        MENU_ROOT + "Analysis/", "reai:existing_analysis", ida_kernwin.SETMENU_APP
    )
    ida_kernwin.attach_action_to_menu(
        MENU_ROOT + "Analysis/", "reai:detatch_analysis", ida_kernwin.SETMENU_APP
    )
    ida_kernwin.attach_action_to_menu(
        MENU_ROOT + "Analysis/", "reai:sync_and_poll", ida_kernwin.SETMENU_APP
    )
    ida_kernwin.attach_action_to_menu(
        MENU_ROOT + "Analysis/", "reai:view_analysis", ida_kernwin.SETMENU_APP
    )
    #
    # ida_kernwin.attach_action_to_menu(
    #     MENU_ROOT, "reai:separator", ida_kernwin.SETMENU_APP
    # )

    ida_kernwin.attach_action_to_menu(
        MENU_ROOT + "Auto Unstrip", "reai:autounstrip", ida_kernwin.SETMENU_APP
    )
    ida_kernwin.attach_action_to_menu(
        MENU_ROOT + "Function Matching", "reai:function_match", ida_kernwin.SETMENU_APP
    )

    # ida_kernwin.attach_action_to_menu(
    #     MENU_ROOT, "reai:separator", ida_kernwin.SETMENU_APP
    # )

    ida_kernwin.attach_action_to_menu(MENU_ROOT + "Configure", "reai:auth", ida_kernwin.SETMENU_APP)
    ida_kernwin.attach_action_to_menu(MENU_ROOT + "Help", "reai:help", ida_kernwin.SETMENU_APP)
    ida_kernwin.attach_action_to_menu(MENU_ROOT + "About", "reai:about", ida_kernwin.SETMENU_APP)
    ida_kernwin.refresh_idaview_anyway()
    return _handlers
