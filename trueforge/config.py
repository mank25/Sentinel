"""Configuration for the Sentinel TrueForge integration.

Everything is environment-driven with working local defaults. No model
provider API key is read or stored here -- those live in TrueForge's own
model-provider settings, not in this repository. The only secret this module
touches is the Sentinel MCP bearer token (see :mod:`trueforge.mcp_auth`),
which is generated locally and gitignored.
"""

import os
from dataclasses import dataclass, field

from trueforge.mcp_auth import resolve_token

DEFAULT_BASE_URL = "http://localhost:8790"

# The default must be a model that can actually complete a tool-using turn.
# groq/gpt-oss-120b cannot: TrueForge replays its reasoning to the provider as
# `reasoning_content`, which Groq rejects, so the turn dies on the second
# model call. gemini-3-6-flash is verified working end-to-end, and its 1M
# context comfortably fits a full login history.
DEFAULT_MODEL = "google-gemini/gemini-3-6-flash"
DEFAULT_MCP_SERVER_NAME = "sentinel-security"
DEFAULT_MCP_URL = "http://127.0.0.1:8791/mcp"
DEFAULT_AGENT_NAME = "sentinel-investigator"
DEFAULT_TIMEOUT = 300.0

# The tools the agent is allowed to reach, named explicitly rather than with
# "@all" so a future tool cannot silently widen the agent's reach.
EVIDENCE_TOOLS = [
    "get_login_history",
    "get_network_activity",
    "assess_user_risk",
    "get_account_status",
    "get_ip_status",
]

# Containment tools change state. They are annotated destructive on the MCP
# server, so TrueForge pauses for human approval before either can run.
CONTAINMENT_TOOLS = [
    "contain_account",
    "block_ip",
]

SENTINEL_TOOLS = EVIDENCE_TOOLS + CONTAINMENT_TOOLS


def _env(name: str, default: str) -> str:
    value = os.environ.get(name)
    return value if value else default


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)

    if not raw:
        return default

    try:
        return float(raw)

    except ValueError:
        raise ValueError(
            f"{name} must be a number, got {raw!r}"
        ) from None


@dataclass
class TrueForgeConfig:
    """Resolved settings for one TrueForge integration run."""

    base_url: str = DEFAULT_BASE_URL
    model: str = DEFAULT_MODEL
    mcp_server_name: str = DEFAULT_MCP_SERVER_NAME
    mcp_url: str = DEFAULT_MCP_URL
    agent_name: str = DEFAULT_AGENT_NAME
    timeout: float = DEFAULT_TIMEOUT
    tools: list = field(default_factory=lambda: list(SENTINEL_TOOLS))
    # Bearer token the Sentinel MCP HTTP server requires. Resolved lazily so
    # constructing a config never creates a token as a side effect.
    mcp_token: str | None = None

    def require_mcp_token(self) -> str:
        """The token to register with TrueForge, generating one if needed."""

        if not self.mcp_token:
            from trueforge.mcp_auth import require_token

            self.mcp_token = require_token()

        return self.mcp_token

    @classmethod
    def from_env(cls) -> "TrueForgeConfig":
        """Build a config from environment variables."""

        return cls(
            base_url=_env("TRUEFORGE_BASE_URL", DEFAULT_BASE_URL).rstrip("/"),
            model=_env("TRUEFORGE_MODEL", DEFAULT_MODEL),
            mcp_server_name=_env(
                "SENTINEL_MCP_SERVER_NAME", DEFAULT_MCP_SERVER_NAME
            ),
            mcp_url=_env("SENTINEL_MCP_URL", DEFAULT_MCP_URL),
            agent_name=_env("SENTINEL_AGENT_NAME", DEFAULT_AGENT_NAME),
            timeout=_env_float("TRUEFORGE_TIMEOUT", DEFAULT_TIMEOUT),
            mcp_token=resolve_token(),
        )

    @property
    def api(self) -> str:
        """Base path for the TrueForge v1 API."""

        return f"{self.base_url.rstrip('/')}/api/v1"
