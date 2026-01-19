from contextlib import contextmanager
from typing import Any, Callable, Optional

import ida_kernwin as kw
import ida_name
import ida_dirtree
from libbs.decompilers.ida.compat import execute_write

from loguru import logger
from revengai import ApiClient, ApiException, Configuration, FunctionMapping

from reai_toolkit.app.core.netstore_service import SimpleNetStore
from reai_toolkit.app.core.shared_schema import GenericApiReturn
from reai_toolkit.app.core.utils import parse_exception


class BaseService:
    netstore_service: SimpleNetStore
    sdk_config: Configuration

    def __init__(self, netstore_service: SimpleNetStore, sdk_config: Configuration):
        self.netstore_service = netstore_service
        self.sdk_config = sdk_config

    # =========================================
    # Netstore Safe Methods
    # =========================================

    def safe_put_analysis_status(self, status: str) -> bool:
        success: bool = False

        def _do():
            nonlocal success
            success = self.netstore_service.put_analysis_status(status=status)

        kw.execute_sync(_do, kw.MFF_FAST)

        return success

    def safe_get_analysis_status(self) -> Optional[str]:
        status: Optional[str] = None

        def _do():
            nonlocal status
            status = self.netstore_service.get_analysis_status()

        kw.execute_sync(_do, kw.MFF_FAST)

        return status

    def safe_put_model_id(self, model_id: int) -> bool:
        success: bool = False

        def _do():
            nonlocal success
            success = self.netstore_service.put_model_id(model_id=model_id)

        kw.execute_sync(_do, kw.MFF_FAST)

        return success

    def safe_get_model_id_local(self) -> Optional[int]:
        model_id: Optional[int] = None

        def _do():
            nonlocal model_id
            model_id = self.netstore_service.get_model_id()

        kw.execute_sync(_do, kw.MFF_FAST)

        return model_id

    def safe_put_model_name_local(self, model_name: str) -> bool:
        success: bool = False

        def _do():
            nonlocal success
            success = self.netstore_service.put_model_name(model_name=model_name)

        kw.execute_sync(_do, kw.MFF_FAST)

        return success

    def safe_get_model_name_local(self) -> Optional[str]:
        model_name: Optional[str] = None

        def _do():
            nonlocal model_name
            model_name = self.netstore_service.get_model_name()

        kw.execute_sync(_do, kw.MFF_FAST)

        return model_name

    def safe_put_analysis_id(self, analysis_id: int) -> bool:
        success: bool = False

        def _do():
            nonlocal success
            success = self.netstore_service.put_analysis_id(analysis_id=analysis_id)

        kw.execute_sync(_do, kw.MFF_FAST)

        return success

    def safe_get_analysis_id_local(self) -> Optional[int]:
        analysis_id: Optional[int] = None

        def _do():
            nonlocal analysis_id
            analysis_id = self.netstore_service.get_analysis_id()

        kw.execute_sync(_do, kw.MFF_FAST)

        return analysis_id

    def safe_put_binary_id(self, binary_id: int) -> bool:
        success: bool = False

        def _do():
            nonlocal success
            success = self.netstore_service.put_binary_id(binary_id=binary_id)

        kw.execute_sync(_do, kw.MFF_FAST)

        return success

    def safe_get_binary_id_local(self) -> Optional[int]:
        binary_id: Optional[int] = None

        def _do():
            nonlocal binary_id
            binary_id = self.netstore_service.get_binary_id()

        kw.execute_sync(_do, kw.MFF_FAST)

        return binary_id

    def safe_put_function_mapping(self, func_map: FunctionMapping) -> bool:
        success: bool = False

        def _do():
            nonlocal success
            success = self.netstore_service.put_function_mapping(
                function_mapping=func_map
            )

        kw.execute_sync(_do, kw.MFF_FAST)

        return success

    def safe_get_function_mapping_local(self) -> Optional[FunctionMapping]:
        func_map: Optional[FunctionMapping] = None

        def _do():
            nonlocal func_map
            func_map = self.netstore_service.get_function_mapping()

        kw.execute_sync(_do, kw.MFF_FAST)

        return func_map
    
    @staticmethod
    @execute_write
    def tag_function_as_renamed(func_name: str) -> None:
        """
        Adds the function to the directory `/RevEng.AI` in order to indicate to the user
        that a function was renamed by the platform.

        Args:
            func_name (str): Name of the function to tag.
        """
        dirtree: ida_dirtree.dirtree_t = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)

        namespace: str = "/RevEng.AI"
        if dirtree.isdir(namespace) is False:
            dirtree.mkdir(namespace)
        
        dirtree.rename(func_name, f"{namespace}/{func_name}")


    # =========================================
    # RevEng safe update ida function name
    # =========================================
    @staticmethod
    def safe_set_name(ea: int, new_name: str, check_user_flags: bool = False) -> bool:
        """
        Safely rename an address.
        - If check_user_flags=True, do not overwrite user-defined names.
        - Names set by this helper are marked as AUTO so users can override later.
        - Returns True if name is already the same or successfully set.
        """
        result = {"ok": False}

        def _do():
            cur = ida_name.get_name(ea) or ""
            # If it's already the desired name, consider it success.
            if cur == new_name:
                result["ok"] = True
                return

            if check_user_flags:
                # Don't overwrite user-defined names
                try:
                    if cur and ida_name.is_uname(cur):
                        # user-specified name present -> skip
                        result["ok"] = False
                        return
                except Exception:
                    # If is_uname isn't available/behaves oddly, treat unknown as not user
                    pass

            # Prefer setting sync names as AUTO so users can easily override them later.
            # https://python.docs.hex-rays.com/ida_name/index.html#ida_name.set_name
            # SN_CHECK: check for validity
            # SN_AUTO:   mark as auto-generated name
            # SN_NODUMMY: Prevents warning "can't rename byte as '<func_name>' because the name has a reserved prefix".
            flags = ida_name.SN_CHECK | ida_name.SN_AUTO | ida_name.SN_NODUMMY
            result["ok"] = bool(ida_name.set_name(ea, new_name, flags))

        # hop to UI thread, make it a write transaction
        kw.execute_sync(_do, kw.MFF_WRITE)
        return result["ok"]

    # =========================================
    # RevEng API WRAPPER SAFE METHODS
    # =========================================
    @staticmethod
    @contextmanager
    def yield_api_client(
        sdk_config: Configuration,
    ) -> ApiClient:
        """
        Yields an ApiClient with the given sdk_config.
        Usage:
            with BaseService.yeild_api_client(sdk_config) as api_client:
                # use api_client
        """
        api_client = ApiClient(configuration=sdk_config)
        if hasattr(sdk_config, "user_agent"):
            api_client.user_agent = sdk_config.user_agent
            api_client.default_headers["X-RevEng-Application"] = sdk_config.user_agent
        yield api_client

    @staticmethod
    def api_request_no_return(
        fn: Callable[..., Any], *args, **kwargs
    ) -> GenericApiReturn[Any]:
        """
        Executes a callable under the same try/except logic used for API calls.
        Returns (success, error_message).
        """
        try:
            fn(*args, **kwargs)
            return GenericApiReturn(success=True)
        except ApiException as e:
            error_response = parse_exception(e)
            if (
                error_response
                and error_response.errors
                and len(error_response.errors) > 0
            ):
                return GenericApiReturn(
                    success=False,
                    error_message=f"{error_response.errors[0].code}: {error_response.errors[0].message}",
                )
            return GenericApiReturn(
                success=False,
                error_message=f"API Exception: {str(e)}",
            )

        except Exception as e:
            return GenericApiReturn(
                success=False,
                error_message=f"Unexpected error: {e}",
            )

    @staticmethod
    def api_request_returning(
        fn: Callable[..., Any], *args, **kwargs
    ) -> GenericApiReturn[Any]:
        """
        Executes a callable under the same try/except logic used for API calls.
        Returns (success, error_message, data).
        """
        try:
            result = fn(*args, **kwargs)
            return GenericApiReturn(success=True, data=result)
        except ApiException as e:
            logger.debug(f"API Exception caught: {e}")
            error_response = parse_exception(e)
            if (
                error_response
                and error_response.errors
                and len(error_response.errors) > 0
            ):
                return GenericApiReturn(
                    success=False,
                    error_message=f"{error_response.errors[0].code}: {error_response.errors[0].message}",
                )
            return GenericApiReturn(
                success=False,
                error_message=f"API Exception: {str(e)}",
            )

        except Exception as e:
            logger.error(f"Unexpected error caught: {e}")
            return GenericApiReturn(
                success=False,
                error_message=f"Unexpected error: {e}",
            )
