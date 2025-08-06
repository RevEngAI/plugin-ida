import hashlib
import hmac
from os import environ as env

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse


class HMACMiddleware(BaseHTTPMiddleware):
    HMAC_HEADER_NAME = "X-HMAC-SIGNATURE"
    HMAC_SECRET = 'test'

    async def dispatch(self, request: Request, call_next):
        if request.url.path == "/rpc":
            body = await request.body()
            received_signature = request.headers.get(self.HMAC_HEADER_NAME)

            if not received_signature:
                return JSONResponse(
                    status_code=401, content={"error": "Missing HMAC signature for the RPC request"}
                )

            computed_signature = hmac.new(self.HMAC_SECRET.encode(), body, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(received_signature, computed_signature):
                return JSONResponse(
                    status_code=401, content={"error": "Invalid HMAC signature for the RPC request"}
                )

        response: Response = await call_next(request)
        return response
