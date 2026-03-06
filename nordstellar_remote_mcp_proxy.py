"""
NordStellar MCP auth proxy.

Performs cookie-based browser login, extracts the JWT from the AccessToken
cookie, then proxies all MCP calls to the remote Go server over StreamableHTTP
using that JWT as a Bearer token.  Re-authenticates transparently when the
token expires.

Usage:
  uvx --from git+https://github.com/sirakav/ns-mcp-proxy \\
      nordstellar-remote-mcp-proxy <remote_mcp_url>

  e.g.  nordstellar-remote-mcp-proxy https://platform-mcp.nordstellar.com/mcp

Cursor mcp.json:
  "nordstellar-graphql": {
    "command": "uvx",
    "args": [
      "--from", "git+https://github.com/sirakav/ns-mcp-proxy",
      "nordstellar-remote-mcp-proxy",
      "https://platform-mcp.nordstellar.com/mcp"
    ]
  }
"""

import asyncio
from collections.abc import Awaitable, Callable
from contextlib import AsyncExitStack
from dataclasses import dataclass
import json
import logging
from pathlib import Path
import secrets
import sys
from typing import Any, TypeVar
import urllib.parse
import webbrowser

T = TypeVar("T")

import httpx
from jinja2 import Environment, FileSystemLoader
from mcp import server, types
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from mcp.server.stdio import stdio_server
from mcp.shared.exceptions import MCPError

logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format="[%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("nordstellar-proxy")

BACKEND_BASE = "https://platform-api.nordstellar.com"
CALLBACK_PORT = 54321

_LOOPBACK_HOSTNAMES = {"localhost", "127.0.0.1", "::1"}
_ALLOWED_SCHEMES = {"http", "https"}


_TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
_JINJA_ENV = Environment(
    loader=FileSystemLoader(_TEMPLATES_DIR),
    autoescape=True,
)


def _validate_mcp_url(url: str) -> None:
    """
    Validate the remote MCP server URL.

    Only http and https schemes are permitted. Plain HTTP is allowed only for
    loopback addresses (localhost, 127.0.0.1, ::1, or the 127.x.x.x range)
    because sending Bearer tokens over unencrypted connections on non-loopback
    networks exposes credentials in cleartext.
    """
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception as exc:
        raise SystemExit(f"Invalid MCP URL: {exc}") from exc

    scheme = (parsed.scheme or "").lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise SystemExit(
            f"Invalid MCP URL scheme '{parsed.scheme}'. "
            "Only 'https' and 'http' (loopback only) are allowed."
        )

    hostname = (parsed.hostname or "").lower()
    is_loopback = hostname in _LOOPBACK_HOSTNAMES or hostname.startswith("127.")
    if scheme == "http" and not is_loopback:
        raise SystemExit(
            f"Plain HTTP is not allowed for non-loopback host '{hostname}'. "
            "Use HTTPS to protect Bearer token transmission."
        )


def _callback_uri(port: int) -> str:
    return f"http://127.0.0.1:{port}/callback"


def _oauth_state_from_auth_url(auth_url: str) -> str:
    params = urllib.parse.parse_qs(urllib.parse.urlparse(auth_url).query)
    states = params.get("state", [])
    return states[0] if states else ""


# ---------------------------------------------------------------------------
# Auth state
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
                raw_line = await asyncio.wait_for(reader.readline(), timeout=10)
                first_line = raw_line.decode(errors="replace").rstrip("\r\n")
                # "GET /callback?code=xxx&state=yyy HTTP/1.1"
                parts = first_line.split(" ")
                params: dict[str, str] = {}
                if (
                    len(parts) >= 3
                    and parts[0] == "GET"
                    and urllib.parse.urlparse(parts[1]).path == "/callback"
                ):
                    qs = urllib.parse.urlparse(parts[1]).query
                    params = dict(urllib.parse.parse_qsl(qs))
                else:
                    writer.write(
                        b"HTTP/1.1 400 Bad Request\r\n"
                        b"Content-Type: text/plain; charset=utf-8\r\n"
                        b"Connection: close\r\n\r\n"
                        b"Bad Request"
                    )
                    await writer.drain()
                    return

                if "error" in params:
                    desc = params.get("error_description", "")
                    body = (
                        _JINJA_ENV.get_template("login-error.html")
                        .render(message=f"{params['error']}: {desc}")
                        .encode()
                    )
                    await result_queue.put({"error": params["error"]})
                else:
                    body = (
                        _JINJA_ENV.get_template("login-success.html").render().encode()
                    )
                    await result_queue.put(
                        {
                            "code": params.get("code", ""),
                            "state": params.get("state", ""),
                        }
                    )

                writer.write(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: text/html; charset=utf-8\r\n"
                    b"Connection: close\r\n\r\n" + body
                )
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        cb_server = await asyncio.start_server(
            _handle_connection, "127.0.0.1", CALLBACK_PORT
        )
        try:
            callback_uri = _callback_uri(CALLBACK_PORT)

            encoded = urllib.parse.quote(callback_uri, safe="")
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

            expected_state = _oauth_state_from_auth_url(auth_url)
            if not expected_state:
                raise RuntimeError(
                    "initiate-login response did not include OAuth state"
                )

            print("NordStellar: Opening browser for login...", file=sys.stderr)
            webbrowser.open(auth_url)

            result = await asyncio.wait_for(result_queue.get(), timeout=300)
        finally:
            cb_server.close()
            await cb_server.wait_closed()

        if "error" in result:
            raise RuntimeError(f"OAuth callback error: {result['error']}")
        if not result.get("code"):
            raise RuntimeError("OAuth callback missing authorization code")
        if not result.get("state"):
            raise RuntimeError("OAuth callback missing state")
        if not secrets.compare_digest(result["state"], expected_state):
            raise RuntimeError("OAuth callback state mismatch")

        login_resp = await self._client.post(
            f"{BACKEND_BASE}/auth/login",
            json={
                "authorization_code": result["code"],
                "state": result["state"],
                "redirect_uri": callback_uri,
            },
        )
        if login_resp.status_code != 200:
            raise RuntimeError(
                f"Code exchange failed (HTTP {login_resp.status_code}): {login_resp.text}"
            )
        print("NordStellar: Login successful.", file=sys.stderr)

    def invalidate(self) -> None:
        """Remove the AccessToken cookie so the next ensure_authenticated call is forced to refresh."""
        self._client.cookies.delete("AccessToken")

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
        self.server_name: str = "nordstellar-graphql"
        self.capabilities: types.ServerCapabilities | None = None
        self._commands: asyncio.Queue[_ConnectionCommand] = asyncio.Queue()
        self._owner_task: asyncio.Task[None] | None = None

    async def _open_connection(
        self, url: str, jwt: str
    ) -> tuple[AsyncExitStack, ClientSession, Any]:
        stack = AsyncExitStack()
        try:
            read, write, _ = await stack.enter_async_context(
                streamablehttp_client(
                    url=url,
                    headers={"Authorization": f"Bearer {jwt}"},
                )
            )
            session = await stack.enter_async_context(ClientSession(read, write))
            init_result = await session.initialize()
        except Exception:
            await stack.aclose()
            raise
        return stack, session, init_result

    @staticmethod
    async def _close_stack(stack: AsyncExitStack, context: str) -> None:
        try:
            await stack.aclose()
        except Exception as exc:
            raise RuntimeError(f"{context}: {exc}") from exc

    @staticmethod
    def _finish_command(
        command: "_ConnectionCommand", exc: Exception | None = None
    ) -> None:
        if command.future.done():
            return
        if exc is None:
            command.future.set_result(None)
            return
        command.future.set_exception(exc)

    async def _connection_owner(self) -> None:
        current_stack: AsyncExitStack | None = None
        try:
            while True:
                command = await self._commands.get()
                if isinstance(command, _ConnectCommand):
                    try:
                        new_stack, session, init_result = await self._open_connection(
                            command.url, command.jwt
                        )
                    except Exception as exc:
                        self._finish_command(command, exc)
                        continue

                    old_stack = current_stack
                    current_stack = new_stack
                    self._session = session
                    self.server_name = init_result.serverInfo.name
                    self.capabilities = init_result.capabilities

                    if old_stack is not None:
                        try:
                            await self._close_stack(
                                old_stack, "close previous connection stack"
                            )
                        except Exception as exc:
                            log.warning(
                                "Connected to replacement session but cleanup failed: %s",
                                exc,
                            )
                            self._finish_command(command, exc)
                            continue

                    self._finish_command(command)
                    log.info("Connected to remote MCP server: %s", self.server_name)
                    continue

                stack_to_close = current_stack
                current_stack = None
                self._session = None
                self.capabilities = None

                if stack_to_close is not None:
                    try:
                        await self._close_stack(
                            stack_to_close, "close active connection stack"
                        )
                    except Exception as exc:
                        self._finish_command(command, exc)
                        break

                self._finish_command(command)
                break
        finally:
            if current_stack is not None:
                try:
                    await self._close_stack(
                        current_stack, "close connection stack during owner shutdown"
                    )
                except Exception as exc:
                    log.warning("Connection owner shutdown cleanup failed: %s", exc)
            self._session = None
            self.capabilities = None

    def _ensure_owner_task(self) -> None:
        if self._owner_task is not None and self._owner_task.done():
            # Discard any stored exception — the owner exited due to a transport
            # failure (e.g. TaskGroup from streamablehttp_client) and a fresh task
            # must be created so connect() can succeed.  Re-raising here would
            # prevent reconnection after a 401.
            try:
                self._owner_task.result()
            except (Exception, asyncio.CancelledError) as exc:
                log.warning("Connection owner task exited: %s", exc)
            self._owner_task = None
        if self._owner_task is None:
            self._owner_task = asyncio.create_task(
                self._connection_owner(),
                name="nordstellar-proxy-connection-owner",
            )

    async def connect(self, url: str, jwt: str) -> None:
        self._ensure_owner_task()
        future: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        await self._commands.put(_ConnectCommand(url=url, jwt=jwt, future=future))
        await future

    async def close(self) -> None:
        if self._owner_task is None:
            return

        if self._owner_task.done():
            try:
                self._owner_task.result()
            except (Exception, asyncio.CancelledError) as exc:
                log.warning("Connection owner task already exited: %s", exc)
            self._owner_task = None
            self._session = None
            self.capabilities = None
            return

        future: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        await self._commands.put(_CloseCommand(future=future))
        await future
        await self._owner_task
        self._owner_task = None

    @property
    def session(self) -> ClientSession:
        if self._session is None:
            raise RuntimeError("Not connected to remote MCP server")
        return self._session


@dataclass(slots=True)
class _ConnectCommand:
    url: str
    jwt: str
    future: asyncio.Future[None]


@dataclass(slots=True)
class _CloseCommand:
    future: asyncio.Future[None]


_ConnectionCommand = _ConnectCommand | _CloseCommand


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
                if (
                    isinstance(data, dict)
                    and data.get("error") == "AUTH_NOT_AUTHENTICATED"
                ):
                    return True
            except (json.JSONDecodeError, ValueError):
                pass
    return False


# ---------------------------------------------------------------------------
# Proxy server factory
# ---------------------------------------------------------------------------


def _is_auth_exception(exc: BaseException) -> bool:
    """
    Return True if exc indicates the remote MCP server rejected the Bearer token
    or that the remote session has been terminated and reconnection is needed.

    Four precise cases are recognised:

    1. httpx.HTTPStatusError with status 401 — the streamablehttp_client (which
       uses httpx) raises this when the remote Go server returns HTTP 401 for any
       auth failure (missing token, invalid JWT, expired token, backend rejection).

    2. MCPError("Session terminated") — the streamablehttp_client converts a 404
       response from the remote into MCPError(code=INVALID_REQUEST, message=
       "Session terminated") sent through the read stream. This happens when the
       remote server's session has expired or restarted.

    3. RuntimeError("AUTH_NOT_AUTHENTICATED") — raised by _call_tool's _do()
       when the Go tool returns an AUTH_NOT_AUTHENTICATED sentinel in its content
       (HTTP 200). This happens within the tokenauth cache window when the backend
       rejects the token mid-request after tokenauth has already accepted it.

    4. RuntimeError("Not connected to remote MCP server") — raised by
       ConnectionManager.session when _session is None, which happens after the
       connection owner task exits because the streamablehttp_client TaskGroup
       crashed on a 401.

    ExceptionGroup recursion is required because anyio / asyncio.TaskGroup wraps
    transport failures in a group whose top-level message contains no auth signal.
    """
    if isinstance(exc, httpx.HTTPStatusError) and exc.response.status_code == 401:
        return True
    if isinstance(exc, MCPError) and exc.message == "Session terminated":
        return True
    if isinstance(exc, RuntimeError) and exc.args in (
        ("AUTH_NOT_AUTHENTICATED",),
        ("Not connected to remote MCP server",),
    ):
        return True
    subs = getattr(exc, "exceptions", None)
    if subs is not None:
        return any(_is_auth_exception(sub) for sub in subs)
    return False


async def _create_proxy_server(
    conn: ConnectionManager, auth: AuthState, url: str
) -> server.Server:
    """
    Build a local MCP server whose handlers forward every call through conn.

    All handlers include a re-authentication retry: if the remote server returns
    AUTH_NOT_AUTHENTICATED or the connection raises an auth-related error, the
    proxy refreshes/re-logs in, reconnects with the new JWT, and retries once.
    This prevents Cursor from caching an empty capabilities set after a 401.
    """
    caps = conn.capabilities
    app: server.Server = server.Server(name=conn.server_name)

    async def _reauth_and_reconnect() -> None:
        log.info("Auth/session error detected — re-authenticating and reconnecting...")
        auth.invalidate()
        await auth.ensure_authenticated()
        jwt = auth.extract_jwt()
        await conn.connect(url, jwt)
        log.info("Reconnected with refreshed token.")

    async def _with_reauth(coro_factory: "Callable[[], Awaitable[T]]") -> T:
        """
        Call coro_factory(). On an auth-related exception, re-authenticate,
        reconnect, and retry once. Re-raises on the second failure.
        """
        for attempt in range(2):
            try:
                return await coro_factory()
            except Exception as exc:  # noqa: BLE001
                if attempt == 0 and _is_auth_exception(exc):
                    log.warning(
                        "Auth error on attempt %d (%s: %s) — re-authenticating...",
                        attempt,
                        type(exc).__name__,
                        exc,
                    )
                    try:
                        await _reauth_and_reconnect()
                    except Exception as reauth_exc:
                        log.error("Re-authentication failed: %s", reauth_exc)
                        raise exc from reauth_exc
                    continue
                raise
        raise RuntimeError("unreachable")  # pragma: no cover

    # --- Tools ---
    if caps and caps.tools:

        async def _list_tools(_: Any) -> types.ServerResult:
            return types.ServerResult(await _with_reauth(lambda: conn.session.list_tools()))

        async def _call_tool(req: types.CallToolRequest) -> types.ServerResult:
            async def _do() -> types.CallToolResult:
                result = await conn.session.call_tool(
                    req.params.name, req.params.arguments or {}
                )
                if _is_auth_error(result):
                    raise RuntimeError("AUTH_NOT_AUTHENTICATED")
                return result

            try:
                return types.ServerResult(await _with_reauth(_do))
            except Exception as exc:  # noqa: BLE001
                log.warning("call_tool(%s) failed: %s: %s", req.params.name, type(exc).__name__, exc)
                return types.ServerResult(
                    types.CallToolResult(
                        content=[
                            types.TextContent(
                                type="text",
                                text="Tool call failed. Please try again or restart the MCP server.",
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
            return types.ServerResult(await _with_reauth(lambda: conn.session.list_resources()))

        async def _list_resource_templates(_: Any) -> types.ServerResult:
            return types.ServerResult(
                await _with_reauth(lambda: conn.session.list_resource_templates())
            )

        async def _read_resource(req: types.ReadResourceRequest) -> types.ServerResult:
            return types.ServerResult(
                await _with_reauth(
                    lambda: conn.session.read_resource(req.params.uri)
                )
            )

        app.request_handlers[types.ListResourcesRequest] = _list_resources
        app.request_handlers[types.ListResourceTemplatesRequest] = (
            _list_resource_templates
        )
        app.request_handlers[types.ReadResourceRequest] = _read_resource

    # --- Prompts ---
    if caps and caps.prompts:

        async def _list_prompts(_: Any) -> types.ServerResult:
            return types.ServerResult(await _with_reauth(lambda: conn.session.list_prompts()))

        async def _get_prompt(req: types.GetPromptRequest) -> types.ServerResult:
            return types.ServerResult(
                await _with_reauth(
                    lambda: conn.session.get_prompt(
                        req.params.name, req.params.arguments
                    )
                )
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
    _validate_mcp_url(url)
    log.info("Starting NordStellar MCP proxy → %s", url)
    asyncio.run(_run(url))


if __name__ == "__main__":
    main()
