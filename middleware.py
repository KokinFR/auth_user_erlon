from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from auth_utils import verify_token

PUBLIC_PATHS = [
    "/api/v1/auth/signup",
    "/api/v1/auth/login",
    "/api/v1/auth/recuperar-senha",
    "/api/v1/auth/recuperar-senha-conf",
    "/docs",
    "/openapi.json"
]

class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):

        if request.url.path in PUBLIC_PATHS:
            response = await call_next(request)
            return response
        
        token = request.headers.get("Authorization")

        if not token:
            return JSONResponse(
                status_code=400,
                content={"error": "Token não fornecido."}
            )
        
        user = verify_token(token)

        if not user:
            return JSONResponse(
                status_code=400,
                content={"error": "Token inválido."}
            )
        
        request.state.user = user
        response = await call_next(request)
        return response