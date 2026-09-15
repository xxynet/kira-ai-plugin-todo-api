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
        self.server_url = self.plugin_cfg.get("server_url").rstrip("/")
        self.username = self.plugin_cfg.get("username")
        self.password = self.plugin_cfg.get("password")
        self._token = None
        self._refresh_token = None
        self._client = httpx.AsyncClient(base_url=self.server_url)
        if any(not v for v in [self.server_url, self.username, self.password]):
            logger.error("[todo-api] Missing required configuration parameters: server_url, username, password")
            return
        await self._login()

    async def _login(self):
        try:
            resp = await self._client.post(
                "/api/v1/auth/login",
                json={"user_id": self.username, "password": self.password},
            )
            resp.raise_for_status()
            data = resp.json()
            self._token = data.get("access_token")
            self._refresh_token = data.get("refresh_token")
            logger.info("[todo-api] Login OK")
        except Exception as e:
            logger.error(f"[todo-api] Login failed: {e}")

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
            self._token = data.get("access_token")
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
        description="Retrieve the OpenAPI specification for the TODO API",
        params={"type": "object", "properties": {}},
    )
    async def get_openapi_spec(self, *args, **kwargs):
        resp = await self._client.get("/openapi.json")
        return {"status": "success", "spec": resp.json()}

    @register.tool(
        name="todo_api_request",
        description="Make a request to the TODO API",
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

        auth = BearerAuth(self._token) if self._token else None
        resp = await _do_request(auth)
        if resp is None:
            return {"status": "error", "message": f"Unsupported HTTP method: {method}"}
        # 401: access token 可能过期，刷新后重试一次
        if resp.status_code == 401:
            if await self._refresh():
                resp = await _do_request(BearerAuth(self._token))
            else:
                await self._login()
                if self._token:
                    resp = await _do_request(BearerAuth(self._token))
        try:
            body = resp.json()
        except Exception:
            body = resp.text
        return {"status": "success", "status_code": resp.status_code, "data": body}
