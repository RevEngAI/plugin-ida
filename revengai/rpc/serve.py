import logging
import threading

import uvicorn
from fastapi import FastAPI

from revengai.actions import generate_function_data_types, upload_binary
from revengai.features.auto_unstrip import AutoUnstrip
from revengai.misc.qtutils import inmain, inthread
from revengai.rpc.hmac import HMACMiddleware
from revengai.rpc.models import (
    UnstripResponse,
    UnstripResponseSuccess,
    ApplyDataTypesResponse,
)
from revengai.rpc.state import get_global_state

app = FastAPI(
    title="RevEngAI IDA JSON-RPC server",
    description="This server allows you to directly interact with the IDA plugin over an RPC channel, by default, it listens on localhost:7331",
    middleware=[HMACMiddleware]
)

logger = logging.getLogger("REAI-RPC")


@app.get("/init")
def init():
    logging.info("Uploading binary..")
    inmain(upload_binary)
    return {"message": "uploaded binary successfully", "success": True}


@app.get("/auto-unstrip")
def auto_unstrip():
    def _handle() -> int:
        unstrip = AutoUnstrip(get_global_state())
        numb_renamed = unstrip.unstrip()

        return numb_renamed

    logger.info("Received command to auto-unstrip..")

    numb_renamed = inthread(inmain(_handle))
    if numb_renamed == 0:
        return UnstripResponse(data=None, success=False)

    return UnstripResponse(
        data=UnstripResponseSuccess(
            message="unstripped binary successfully",
        ),
        success=True,
    )


@app.get("/apply-data-types")
def apply_data_types():
    def _handle() -> None:
        generate_function_data_types(get_global_state(), ui=False)

    logger.info("Received command to apply data types..")
    inmain(_handle)

    return ApplyDataTypesResponse(message="completed task for applying data types")


def run_server():
    def _run():
        logger.info("Starting RevEngAI IDA RPC server..")
        uvicorn.run(app, host="localhost", port=7331)

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
