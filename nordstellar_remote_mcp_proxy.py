"""
NordStellar MCP auth proxy.

Performs cookie-based browser login, extracts the JWT from the AccessToken
cookie, then proxies all MCP calls to the remote Go server over StreamableHTTP
using that JWT as a Bearer token.  Re-authenticates transparently when the
token expires.

Usage:
  uvx --from git+https://github.com/sirakav/ns-mcp-prroxy \\
      nordstellar-remote-mcp-proxy <remote_mcp_url>

  e.g.  nordstellar-remote-mcp-proxy http://my-server:8080/mcp

Cursor mcp.json:
  "nordstellar-graphql": {
    "command": "uvx",
    "args": [
      "--from", "git+https://github.com/sirakav/ns-mcp-prroxy",
      "nordstellar-remote-mcp-proxy",
      "http://my-server:8080/mcp"
    ]
  }
"""

import asyncio
import json
import logging
import sys
import urllib.parse
import webbrowser
from contextlib import AsyncExitStack
from pathlib import Path
from typing import Any

import httpx
from jinja2 import Environment, FileSystemLoader
from mcp import server, types
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from mcp.server.stdio import stdio_server

logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format="[%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("nordstellar-proxy")

BACKEND_BASE = "https://platform-api.nordstellar.com"
CALLBACK_PORT = 54321
CALLBACK_URI = f"http://127.0.0.1:{CALLBACK_PORT}/callback"

_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
_JINJA_ENV = Environment(
    loader=FileSystemLoader(_TEMPLATES_DIR),
    autoescape=True,
)


# ---------------------------------------------------------------------------
# Auth state — mirrors cmd/local/pkg/auth/
# ---------------------------------------------------------------------------

class AuthState:
    """
    Cookie-based NordStellar authentication.

    Replicates the Go auth flow from cmd/local/pkg/auth/:
      - refresh_session  → POST /auth/refresh-token
      - login_flow       → GET  /auth/initiate-login/{redirect} → browser
                           → callback → POST /auth/login
      - ensure_authenticated → refresh then login if needed
      - extract_jwt      → URL-decode AccessToken cookie, parse JSON, return Token
    """

    def __init__(self) -> None:
        # follow_redirects=True for all calls except initiate-login (overridden per-request)
        self._client = httpx.AsyncClient(follow_redirects=True, timeout=30.0)

    def is_authenticated(self) -> bool:
        return bool(self._client.cookies.get("AccessToken"))

    async def _refresh_session(self) -> bool:
        """POST /auth/refresh-token; return True if a new AccessToken cookie was set."""
        try:
            resp = await self._client.post(
                f"{BACKEND_BASE}/auth/refresh-token",
                headers={"Content-Type": "application/json"},
            )
            return resp.status_code == 200 and self.is_authenticated()
        except Exception as exc:
            log.debug("Refresh request failed: %s", exc)
            return False

    async def _login_flow(self) -> None:
        """
        Full browser OAuth flow, mirroring login.go:
          1. Bind local callback server on 127.0.0.1:54321
          2. GET /auth/initiate-login/{encoded_redirect} (no redirects)
          3. Open Keycloak URL in the browser
          4. Receive OAuth callback (code + state)
          5. POST /auth/login to exchange the code
        """
        result_queue: asyncio.Queue[dict[str, str]] = asyncio.Queue(maxsize=1)

        async def _handle_connection(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            try:
                raw = await asyncio.wait_for(reader.read(8192), timeout=10)
                first_line = raw.decode(errors="replace").split("\r\n")[0]
                # "GET /callback?code=xxx&state=yyy HTTP/1.1"
                parts = first_line.split(" ")
                params: dict[str, str] = {}
                if len(parts) >= 2:
                    qs = urllib.parse.urlparse(parts[1]).query
                    params = dict(urllib.parse.parse_qsl(qs))

                if "error" in params:
                    desc = params.get("error_description", "")
                    body = _JINJA_ENV.get_template("login-error.html").render(
                        message=f"{params['error']}: {desc}"
                    ).encode()
                    await result_queue.put({"error": params["error"]})
                else:
                    body = _JINJA_ENV.get_template("login-success.html").render().encode()
                    await result_queue.put(
                        {"code": params.get("code", ""), "state": params.get("state", "")}
                    )

                writer.write(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: text/html; charset=utf-8\r\n"
                    b"Connection: close\r\n\r\n"
                    + body
                )
                await writer.drain()
            finally:
                writer.close()

        cb_server = await asyncio.start_server(_handle_connection, "127.0.0.1", CALLBACK_PORT)
        try:
            encoded = urllib.parse.quote(CALLBACK_URI, safe="")
            init_resp = await self._client.get(
                f"{BACKEND_BASE}/auth/initiate-login/{encoded}",
                headers={"Accept": "application/json"},
                follow_redirects=False,
            )

            if init_resp.status_code == 200:
                try:
                    auth_url = init_resp.json()["auth_url"]
                except Exception:
                    raise RuntimeError(
                        f"Unexpected initiate-login response body: {init_resp.text}"
                    )
            elif init_resp.status_code in (301, 302, 303, 307, 308):
                auth_url = init_resp.headers.get("Location", "")
                if not auth_url:
                    raise RuntimeError("initiate-login redirect had no Location header")
            else:
                raise RuntimeError(
                    f"initiate-login failed (HTTP {init_resp.status_code}): {init_resp.text}"
                )

            print("NordStellar: Opening browser for login...", file=sys.stderr)
            webbrowser.open(auth_url)

            result = await asyncio.wait_for(result_queue.get(), timeout=300)
        finally:
            cb_server.close()

        if "error" in result:
            raise RuntimeError(f"OAuth callback error: {result['error']}")

        login_resp = await self._client.post(
            f"{BACKEND_BASE}/auth/login",
            json={
                "authorization_code": result["code"],
                "state": result["state"],
                "redirect_uri": CALLBACK_URI,
            },
        )
        if login_resp.status_code != 200:
            raise RuntimeError(
                f"Code exchange failed (HTTP {login_resp.status_code}): {login_resp.text}"
            )
        print("NordStellar: Login successful.", file=sys.stderr)

    async def ensure_authenticated(self) -> None:
        """Refresh or run browser login, mirroring ensureAuthenticated in refresh.go."""
        if self.is_authenticated():
            return
        log.info("Attempting token refresh...")
        if await self._refresh_session():
            log.info("Token refreshed successfully.")
            return
        log.info("Starting browser login flow...")
        await self._login_flow()

    def extract_jwt(self) -> str:
        """
        Decode the AccessToken cookie and return the raw JWT.

        The platform API sets the cookie as:
          URL-encode({"token":"<jwt>","expires_in":<n>})

        Note: graphql.go's comment describes the *reverse* direction (Go remote server
        synthesising a cookie from a Bearer token for the GraphQL backend), which uses
        PascalCase keys. The backend itself uses lowercase keys.
        """
        raw = self._client.cookies.get("AccessToken")
        if not raw:
            raise RuntimeError("AccessToken cookie not found after authentication")
        decoded = urllib.parse.unquote(raw)
        data = json.loads(decoded)
        # Backend sets lowercase "token"; accept PascalCase "Token" as fallback
        jwt = data.get("token") or data.get("Token")
        if not jwt:
            raise RuntimeError(
                f"JWT not found in AccessToken cookie. Got keys: {list(data.keys())}"
            )
        return jwt

    async def aclose(self) -> None:
        await self._client.aclose()


# ---------------------------------------------------------------------------
# Connection manager — reconnectable StreamableHTTP ↔ ClientSession
# ---------------------------------------------------------------------------

class ConnectionManager:
    """
    Manages the StreamableHTTP connection to the remote Go MCP server.

    Holds a live ClientSession and an AsyncExitStack so the connection
    can be torn down and re-established on re-authentication without
    restarting the stdio server that Cursor is connected to.
    """

    def __init__(self) -> None:
        self._session: ClientSession | None = None
        self._stack: AsyncExitStack | None = None
        self.server_name: str = "nordstellar-graphql"
        self.capabilities: types.ServerCapabilities | None = None

    async def connect(self, url: str, jwt: str) -> None:
        # Do NOT call aclose() on the old stack here.
        # streamablehttp_client uses anyio TaskGroups whose cancel scopes are
        # task-owned. If connect() is called from a request-handler task (e.g.
        # during re-auth), closing a stack that was created in the main task
        # raises "Attempted to exit cancel scope in a different task than it was
        # entered in". The old stack is orphaned and will time out naturally;
        # close() (called from the main task's finally block) handles it safely.
        stack = AsyncExitStack()
        read, write, _ = await stack.enter_async_context(
            streamablehttp_client(
                url=url,
                headers={"Authorization": f"Bearer {jwt}"},
            )
        )
        session = await stack.enter_async_context(ClientSession(read, write))
        init_result = await session.initialize()

        self._session = session
        self._stack = stack
        self.server_name = init_result.serverInfo.name
        self.capabilities = init_result.capabilities
        log.info("Connected to remote MCP server: %s", self.server_name)

    async def close(self) -> None:
        # Safe to call aclose() here because close() is always invoked from
        # the _run() coroutine (main task) — the same task that called connect()
        # on startup.
        if self._stack is not None:
            await self._stack.aclose()
            self._stack = None
            self._session = None

    @property
    def session(self) -> ClientSession:
        if self._session is None:
            raise RuntimeError("Not connected to remote MCP server")
        return self._session


# ---------------------------------------------------------------------------
# Auth error detection
# ---------------------------------------------------------------------------

def _is_auth_error(result: types.CallToolResult) -> bool:
    """
    Detect the AUTH_NOT_AUTHENTICATED sentinel that the remote Go server
    returns when the Bearer token has expired (see graphql.go remote mode branch).
    """
    for content in result.content:
        if isinstance(content, types.TextContent):
            try:
                data = json.loads(content.text)
                if isinstance(data, dict) and data.get("error") == "AUTH_NOT_AUTHENTICATED":
                    return True
            except (json.JSONDecodeError, ValueError):
                pass
    return False


# ---------------------------------------------------------------------------
# Proxy server factory
# ---------------------------------------------------------------------------

async def _create_proxy_server(
    conn: ConnectionManager, auth: AuthState, url: str
) -> server.Server:
    """
    Build a local MCP server whose handlers forward every call through conn.

    Tool calls include a re-authentication retry: if the remote server returns
    AUTH_NOT_AUTHENTICATED (or the connection raises), the proxy refreshes/re-logs
    in, reconnects with the new JWT, and retries the call once.
    """
    caps = conn.capabilities
    app: server.Server = server.Server(name=conn.server_name)

    async def _reauth_and_reconnect() -> None:
        log.info("Auth error detected — re-authenticating...")
        await auth.ensure_authenticated()
        jwt = auth.extract_jwt()
        await conn.connect(url, jwt)
        log.info("Reconnected with new token.")

    # --- Tools ---
    if caps and caps.tools:
        async def _list_tools(_: Any) -> types.ServerResult:
            return types.ServerResult(await conn.session.list_tools())

        async def _call_tool(req: types.CallToolRequest) -> types.ServerResult:
            for attempt in range(2):
                try:
                    result = await conn.session.call_tool(
                        req.params.name, req.params.arguments or {}
                    )
                    if _is_auth_error(result) and attempt == 0:
                        await _reauth_and_reconnect()
                        continue
                    return types.ServerResult(result)
                except Exception as exc:  # noqa: BLE001
                    log.warning(
                        "call_tool(%s) raised on attempt %d: %s: %s",
                        req.params.name, attempt, type(exc).__name__, exc,
                    )
                    # Only attempt reauth for exceptions that are plausibly
                    # auth/connection failures, not arbitrary SDK errors.
                    exc_str = str(exc).lower()
                    looks_like_auth = any(
                        kw in exc_str
                        for kw in ("401", "unauthorized", "unauthenticated", "expired", "forbidden")
                    )
                    if attempt == 0 and looks_like_auth:
                        try:
                            await _reauth_and_reconnect()
                            continue
                        except Exception as reauth_exc:
                            log.error("Re-authentication failed: %s", reauth_exc)
                    return types.ServerResult(
                        types.CallToolResult(
                            content=[types.TextContent(type="text", text=str(exc))],
                            isError=True,
                        )
                    )
            return types.ServerResult(
                types.CallToolResult(
                    content=[
                        types.TextContent(
                            type="text",
                            text="Authentication failed after retry. Please restart the MCP server.",
                        )
                    ],
                    isError=True,
                )
            )

        app.request_handlers[types.ListToolsRequest] = _list_tools
        app.request_handlers[types.CallToolRequest] = _call_tool

    # --- Resources ---
    if caps and caps.resources:
        async def _list_resources(_: Any) -> types.ServerResult:
            return types.ServerResult(await conn.session.list_resources())

        async def _list_resource_templates(_: Any) -> types.ServerResult:
            return types.ServerResult(await conn.session.list_resource_templates())

        async def _read_resource(req: types.ReadResourceRequest) -> types.ServerResult:
            return types.ServerResult(await conn.session.read_resource(req.params.uri))

        app.request_handlers[types.ListResourcesRequest] = _list_resources
        app.request_handlers[types.ListResourceTemplatesRequest] = _list_resource_templates
        app.request_handlers[types.ReadResourceRequest] = _read_resource

    # --- Prompts ---
    if caps and caps.prompts:
        async def _list_prompts(_: Any) -> types.ServerResult:
            return types.ServerResult(await conn.session.list_prompts())

        async def _get_prompt(req: types.GetPromptRequest) -> types.ServerResult:
            return types.ServerResult(
                await conn.session.get_prompt(req.params.name, req.params.arguments)
            )

        app.request_handlers[types.ListPromptsRequest] = _list_prompts
        app.request_handlers[types.GetPromptRequest] = _get_prompt

    return app


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def _run(url: str) -> None:
    auth = AuthState()
    conn = ConnectionManager()
    try:
        await auth.ensure_authenticated()
        jwt = auth.extract_jwt()
        await conn.connect(url, jwt)

        app = await _create_proxy_server(conn, auth, url)

        async with stdio_server() as (read_stream, write_stream):
            await app.run(
                read_stream,
                write_stream,
                app.create_initialization_options(),
            )
    finally:
        await conn.close()
        await auth.aclose()


def main() -> None:
    if len(sys.argv) < 2:
        print(
            "Usage: proxy.py <remote_mcp_url>\n"
            "  e.g. proxy.py http://localhost:8080/mcp",
            file=sys.stderr,
        )
        sys.exit(1)

    url = sys.argv[1]
    log.info("Starting NordStellar MCP proxy → %s", url)
    asyncio.run(_run(url))


if __name__ == "__main__":
    main()
