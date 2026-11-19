import httpx

from core.plugin import BasePlugin, PluginContext, logger, register


class BearerAuth(httpx.Auth):
    def __init__(self, token: str):
        self.token = token

    def auth_flow(self, request):
        request.headers["Authorization"] = f"Bearer {self.token}"
        yield request


class MyPlugin(BasePlugin):
    def __init__(self, ctx: PluginContext, cfg: dict):
        super().__init__(ctx, cfg)

    async def initialize(self):
        self.server_url = (self.plugin_cfg.get("server_url") or "").rstrip("/")
        self.username = self.plugin_cfg.get("username")
        self.password = self.plugin_cfg.get("password")
        self._token = None
        self._refresh_token = None
        self._client = httpx.AsyncClient(base_url=self.server_url)
        await self._login()

    async def _login(self) -> bool:
        if not all((self.server_url, self.username, self.password)):
            logger.error("[todo-api] Missing required configuration parameters: server_url, username, password")
            return False
        try:
            resp = await self._client.post(
                "/api/v1/auth/login",
                json={"user_id": self.username, "password": self.password},
            )
            resp.raise_for_status()
            data = resp.json()
            access_token = data.get("access_token")
            if not access_token:
                logger.warning("[todo-api] Login response is missing an access token")
                return False
            self._token = access_token
            self._refresh_token = data.get("refresh_token")
            logger.info("[todo-api] Login OK")
            return True
        except Exception as e:
            logger.error(f"[todo-api] Login failed: {e}")
            return False

    async def _refresh(self) -> bool:
        """Refresh the access token using the refresh token."""
        if not self._refresh_token:
            return False
        try:
            resp = await self._client.post(
                "/api/v1/auth/refresh",
                json={"refresh_token": self._refresh_token},
            )
            if resp.status_code != 200:
                logger.warning(f"[todo-api] Token refresh failed: {resp.status_code}")
                return False
            data = resp.json()
            access_token = data.get("access_token")
            if not access_token:
                logger.warning("[todo-api] Refresh response is missing an access token")
                return False
            self._token = access_token
            self._refresh_token = data.get("refresh_token") or self._refresh_token
            logger.info("[todo-api] Token refreshed")
            return True
        except Exception as e:
            logger.error(f"[todo-api] Token refresh error: {e}")
            return False

    async def _ensure_token(self):
        """Make sure we have a token, refreshing or logging in if needed."""
        if self._token:
            return
        if not await self._refresh():
            await self._login()

    async def terminate(self):
        await self._client.aclose()

    @register.tool(
        name="get_openapi_spec",
        description=(
            "Retrieve the TODO API OpenAPI specification to find task endpoints and request formats. "
            "The plugin handles authentication; do not call login or token endpoints from the specification."
        ),
        params={"type": "object", "properties": {}},
    )
    async def get_openapi_spec(self, *args, **kwargs):
        resp = await self._client.get("/openapi.json")
        return {"status": "success", "spec": resp.json()}

    @register.tool(
        name="todo_api_request",
        description=(
            "Make a request to a TODO API task endpoint. The plugin logs in, attaches, and refreshes its token automatically. "
            "Do not call login or token endpoints, ask for credentials, or pass credentials, tokens, "
            "or Authorization headers."
        ),
        params={
            "type": "object",
            "properties": {
                "method": {"type": "string", "description": "The HTTP method to use"},
                "endpoint": {"type": "string", "description": "The API endpoint to call"},
                "data": {"type": "object", "description": "The data to send with the request"},
            },
            "required": ["method", "endpoint"],
        },
    )
    async def todo_api_request(self, *_, method: str, endpoint: str, data: dict = None):
        path = endpoint if endpoint.startswith("/") else f"/{endpoint}"
        m = method.upper()
        await self._ensure_token()
        if not self._token:
            return {
                "status": "error",
                "code": "auth_unavailable",
                "message": "The plugin is not authenticated. Check the TODO API plugin configuration and startup logs.",
            }

        async def _do_request(auth):
            if m == "GET":
                return await self._client.get(path, auth=auth)
            if m == "POST":
                return await self._client.post(path, json=data, auth=auth)
            if m == "PUT":
                return await self._client.put(path, json=data, auth=auth)
            if m == "DELETE":
                return await self._client.delete(path, auth=auth)
            if m == "PATCH":
                return await self._client.patch(path, json=data, auth=auth)
            return None

        resp = await _do_request(BearerAuth(self._token))
        if resp is None:
            return {"status": "error", "message": f"Unsupported HTTP method: {method}"}
        if resp.status_code == 401 and (await self._refresh() or await self._login()):
            resp = await _do_request(BearerAuth(self._token))
        try:
            body = resp.json()
        except Exception:
            body = resp.text
        result = {
            "status": "error" if resp.is_error else "success",
            "status_code": resp.status_code,
            "data": body,
        }
        if resp.status_code == 401:
            result.update(
                code="auth_unauthorized",
                message="The server rejected the plugin's authentication. Check the TODO API plugin configuration.",
            )
        elif resp.status_code == 403:
            result.update(
                code="auth_forbidden",
                message="The configured TODO API account does not have permission for this request.",
            )
        return result
