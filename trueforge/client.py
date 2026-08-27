"""Thin, typed-ish HTTP client for the TrueForge v0.1.4 API.

Only this module talks HTTP to TrueForge. It maps transport and protocol
problems onto a small exception family so callers can report something useful
instead of a raw traceback.

Endpoint shapes are taken from the running server's OpenAPI document
(``/api/v1/openapi.json``), not guessed.
"""

import json
import time

import httpx2

from trueforge.config import TrueForgeConfig


class TrueForgeError(Exception):
    """Base class for every TrueForge integration failure."""


class TrueForgeUnavailable(TrueForgeError):
    """TrueForge could not be reached at all."""


class TrueForgeTimeout(TrueForgeError):
    """A TrueForge request or turn exceeded its deadline."""


class TrueForgeHTTPError(TrueForgeError):
    """TrueForge returned a non-2xx response."""

    def __init__(self, method: str, path: str, status: int, body: str):
        self.method = method
        self.path = path
        self.status = status
        self.body = body

        super().__init__(
            f"{method} {path} failed with HTTP {status}: {body[:500]}"
        )


class TrueForgeProtocolError(TrueForgeError):
    """TrueForge returned a response we could not understand."""


class TrueForgeClient:
    """Synchronous client for the endpoints Sentinel needs."""

    def __init__(self, config: TrueForgeConfig | None = None, http=None):
        self.config = config or TrueForgeConfig.from_env()

        # Injectable for tests; owned here otherwise.
        self._owns_http = http is None
        self._http = http or httpx2.Client(timeout=self.config.timeout)

    # -----------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------

    def close(self) -> None:
        if self._owns_http:
            self._http.close()

    def __enter__(self) -> "TrueForgeClient":
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    # -----------------------------------------------------------------
    # Transport
    # -----------------------------------------------------------------

    def _request(self, method: str, path: str, **kwargs) -> dict:
        """Issue one request and return the decoded JSON body."""

        url = f"{self.config.api}{path}"

        try:
            response = self._http.request(method, url, **kwargs)

        except httpx2.TimeoutException as exc:
            raise TrueForgeTimeout(
                f"{method} {path} timed out after "
                f"{self.config.timeout}s"
            ) from exc

        except httpx2.ConnectError as exc:
            raise TrueForgeUnavailable(
                f"Cannot reach TrueForge at {self.config.base_url}. "
                "Is it running? Start it and retry."
            ) from exc

        except httpx2.HTTPError as exc:
            raise TrueForgeUnavailable(
                f"Transport failure talking to TrueForge: {exc}"
            ) from exc

        if response.status_code >= 400:
            raise TrueForgeHTTPError(
                method,
                path,
                response.status_code,
                response.text,
            )

        if not response.content:
            return {}

        try:
            return response.json()

        except (json.JSONDecodeError, ValueError) as exc:
            raise TrueForgeProtocolError(
                f"{method} {path} returned a non-JSON body: "
                f"{response.text[:200]!r}"
            ) from exc

    @staticmethod
    def _data(payload: dict, context: str):
        """Unwrap TrueForge's ``{"data": ...}`` envelope."""

        if not isinstance(payload, dict) or "data" not in payload:
            raise TrueForgeProtocolError(
                f"{context}: expected a 'data' envelope, got "
                f"{str(payload)[:200]!r}"
            )

        return payload["data"]

    # -----------------------------------------------------------------
    # Health
    # -----------------------------------------------------------------

    def ping(self) -> bool:
        """Confirm TrueForge is up. Raises TrueForgeUnavailable if not."""

        self._request("GET", "/capabilities")
        return True

    def list_models(self) -> list:
        return self._data(self._request("GET", "/models"), "list_models")

    # -----------------------------------------------------------------
    # MCP servers
    # -----------------------------------------------------------------

    def list_mcp_servers(self) -> list:
        return self._data(
            self._request("GET", "/settings/mcp-servers"),
            "list_mcp_servers",
        )

    def register_mcp_server(
        self,
        name: str,
        url: str,
        description: str,
        headers: dict | None = None,
    ) -> dict:
        """Create or replace a remote MCP server registration.

        TrueForge v0.1.4 supports remote (HTTP) MCP servers only -- its
        ``MCPServerType`` enum has the single value ``"remote"`` -- so the
        Sentinel MCP server must be reachable over HTTP.

        ``headers`` becomes the manifest's ``header`` auth, which is how
        TrueForge presents the Sentinel MCP bearer token on every call.

        PUT is create-or-replace, which makes this idempotent.
        """

        manifest = {
            "type": "remote",
            "name": name,
            "url": url,
            "description": description,
        }

        if headers:
            manifest["auth"] = {"type": "header", "headers": dict(headers)}

        payload = {"manifest": manifest}

        return self._data(
            self._request("PUT", "/settings/mcp-servers", json=payload),
            "register_mcp_server",
        )

    def list_mcp_tools(self, name: str) -> list:
        """List the tools TrueForge can actually see on an MCP server.

        This makes TrueForge connect to the MCP server, so it doubles as a
        reachability check.
        """

        return self._data(
            self._request("GET", f"/mcp-servers/{name}/tools"),
            "list_mcp_tools",
        )

    # -----------------------------------------------------------------
    # Agents
    # -----------------------------------------------------------------

    def list_agents(self) -> list:
        return self._data(self._request("GET", "/agents"), "list_agents")

    def find_agent(self, name: str) -> dict | None:
        for agent in self.list_agents():
            if agent.get("name") == name:
                return agent

        return None

    def create_agent(self, name: str, spec: dict) -> dict:
        return self._data(
            self._request(
                "POST",
                "/agents",
                json={"name": name, "manifest": spec},
            ),
            "create_agent",
        )

    def update_agent(self, agent_id: str, spec: dict) -> dict:
        return self._data(
            self._request(
                "PUT",
                f"/agents/{agent_id}",
                json={"manifest": spec},
            ),
            "update_agent",
        )

    def upsert_agent(self, name: str, spec: dict) -> dict:
        """Create the agent, or update it in place when it already exists."""

        existing = self.find_agent(name)

        if existing is None:
            return self.create_agent(name, spec)

        return self.update_agent(existing["id"], spec)

    # -----------------------------------------------------------------
    # Sessions and turns
    # -----------------------------------------------------------------

    def create_session(self, agent_name: str) -> dict:
        return self._data(
            self._request(
                "POST",
                "/sessions",
                json={"agent": {"name": agent_name}},
            ),
            "create_session",
        )

    def create_turn(
        self,
        session_id: str,
        message: str,
        stream: bool = False,
    ) -> dict:
        """Start a turn.

        With ``stream=False`` TrueForge returns the running turn immediately
        and the caller polls :meth:`get_turn`.
        """

        payload = {
            "input": [{"type": "user.message", "content": message}],
            "stream": stream,
        }

        return self._data(
            self._request(
                "POST",
                f"/sessions/{session_id}/turns",
                json=payload,
            ),
            "create_turn",
        )

    def get_turn(self, session_id: str, turn_id: str) -> dict:
        return self._data(
            self._request(
                "GET",
                f"/sessions/{session_id}/turns/{turn_id}",
            ),
            "get_turn",
        )

    def list_turn_events(self, session_id: str, turn_id: str) -> list:
        """Every event TrueForge recorded for a turn, oldest first."""

        events = []
        page_token = None

        while True:
            params = {"limit": 100, "order": "asc"}

            if page_token:
                params["page_token"] = page_token

            payload = self._request(
                "GET",
                f"/sessions/{session_id}/turns/{turn_id}/events",
                params=params,
            )

            events.extend(self._data(payload, "list_turn_events"))

            page_token = (
                payload.get("pagination", {}).get("next_page_token")
            )

            if not page_token:
                return events

    def wait_for_turn(
        self,
        session_id: str,
        turn_id: str,
        timeout: float | None = None,
        poll_interval: float = 1.0,
    ) -> dict:
        """Poll until the turn leaves the ``running`` state."""

        deadline = time.monotonic() + (timeout or self.config.timeout)

        while True:
            turn = self.get_turn(session_id, turn_id)
            status = turn.get("state", {}).get("status")

            if status is None:
                raise TrueForgeProtocolError(
                    f"Turn {turn_id} has no state.status: {str(turn)[:200]!r}"
                )

            if status != "running":
                return turn

            if time.monotonic() >= deadline:
                raise TrueForgeTimeout(
                    f"Turn {turn_id} was still running after "
                    f"{timeout or self.config.timeout}s"
                )

            time.sleep(poll_interval)
