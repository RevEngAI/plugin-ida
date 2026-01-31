from contextlib import contextmanager
from typing import Any, Callable

import ida_name
import ida_dirtree
from libbs.decompilers.ida.compat import execute_write

from loguru import logger
from revengai import ApiClient, ApiException, Configuration

from reai_toolkit.app.core.netstore_service import SimpleNetStore
from reai_toolkit.app.core.shared_schema import GenericApiReturn
from reai_toolkit.app.core.utils import parse_exception


class BaseService:
    def __init__(self, netstore_service: SimpleNetStore, sdk_config: Configuration) -> None:
        self.netstore_service: SimpleNetStore = netstore_service
        self.sdk_config: Configuration = sdk_config

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
    @execute_write
    def update_function_name(ea: int, new_name: str, check_user_flags: bool = False) -> bool:
        """
        Safely rename an address.
        - If check_user_flags=True, do not overwrite user-defined names.
        - Names set by this helper are marked as AUTO so users can override later.
        - Returns True if name is already the same or successfully set.
        """

        cur: str = ida_name.get_name(ea) or ""
        # If it's already the desired name, consider it success.
        if cur == new_name:
            return True

        if check_user_flags:
            # Don't overwrite user-defined names
            try:
                if cur and ida_name.is_uname(cur):
                    # user-specified name present -> skip
                    return False
            except Exception:
                # If is_uname isn't available/behaves oddly, treat unknown as not user
                pass

        # Prefer setting sync names as AUTO so users can easily override them later.
        # https://python.docs.hex-rays.com/ida_name/index.html#ida_name.set_name
        # SN_CHECK: check for validity
        # SN_AUTO:   mark as auto-generated name
        # SN_NODUMMY: Prevents warning "can't rename byte as '<func_name>' because the name has a reserved prefix".
        flags: int = ida_name.SN_CHECK | ida_name.SN_AUTO | ida_name.SN_NODUMMY

        return ida_name.set_name(ea, new_name, flags)

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
