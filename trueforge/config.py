"""Configuration for the Sentinel TrueForge integration.

Everything is environment-driven with working local defaults. No secrets are
read or stored here: the Groq API key lives in TrueForge's own model-provider
settings, not in this repository.
"""

import os
from dataclasses import dataclass, field

DEFAULT_BASE_URL = "http://localhost:8790"
DEFAULT_MODEL = "groq/gpt-oss-120b"
DEFAULT_MCP_SERVER_NAME = "sentinel-security"
DEFAULT_MCP_URL = "http://127.0.0.1:8791/mcp"
DEFAULT_AGENT_NAME = "sentinel-investigator"
DEFAULT_TIMEOUT = 300.0

# The tools the agent is allowed to reach, named explicitly rather than with
# "@all" so a future tool cannot silently widen the agent's reach.
SENTINEL_TOOLS = [
    "get_login_history",
    "get_network_activity",
    "assess_user_risk",
]


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
        )

    @property
    def api(self) -> str:
        """Base path for the TrueForge v1 API."""

        return f"{self.base_url.rstrip('/')}/api/v1"
