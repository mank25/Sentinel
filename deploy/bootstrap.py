"""Make a freshly-started TrueForge ready to run Sentinel.

A container starts with an empty TrueForge database. Almost all of the setup
Sentinel needs is already automatic: :meth:`SentinelAgent.provision` registers
the MCP server and upserts the agent at the start of every investigation, so
those self-heal on a blank instance.

Exactly one thing does not, because it is a secret and cannot live in the
image: the model provider. This configures it from ``$GEMINI_API_KEY`` and
then gets out of the way.

Run after TrueForge is listening:

    python deploy/bootstrap.py
"""

import os
import sys
import time

import httpx2

BASE_URL = os.environ.get("TRUEFORGE_BASE_URL", "http://127.0.0.1:8790")
API = f"{BASE_URL.rstrip('/')}/api/v1"

# Matches the FQN in trueforge/config.py. The provider name and the model
# name together form "google-gemini/gemini-3-6-flash".
PROVIDER = "google-gemini"

MODELS = [
    {
        "model_id": "gemini-3.6-flash",
        "name": "gemini-3-6-flash",
        "properties": {
            "context_length": 1048576,
            "max_output_tokens": 65536,
            "reasoning_efforts": ["minimal", "low", "medium", "high"],
        },
    },
]

STARTUP_TIMEOUT = 120.0


def wait_for_trueforge(timeout: float = STARTUP_TIMEOUT) -> None:
    """Block until TrueForge answers, or give up with a clear message."""

    deadline = time.monotonic() + timeout

    while True:
        try:
            response = httpx2.get(f"{API}/capabilities", timeout=5)

            if response.status_code < 400:
                print(f"[bootstrap] TrueForge is up at {BASE_URL}")
                return

        except httpx2.HTTPError:
            pass

        if time.monotonic() >= deadline:
            sys.exit(
                f"[bootstrap] TrueForge did not start within {timeout:.0f}s "
                f"at {BASE_URL}. Check the container logs above."
            )

        time.sleep(1.0)


def configure_model_provider(api_key: str) -> None:
    """Create or replace the Gemini provider.

    PUT is create-or-replace, which makes a container restart idempotent:
    the same call works on a blank database and on one that already has the
    provider from a previous boot.
    """

    manifest = {
        "type": PROVIDER,
        "auth": {"api_key": api_key},
        "models": MODELS,
    }

    response = httpx2.put(
        f"{API}/settings/model-providers",
        json={"manifest": manifest},
        timeout=30,
    )

    if response.status_code >= 400:
        # Never echo the body verbatim -- it is a request that contained the
        # API key, and this output goes to a hosting provider's logs.
        sys.exit(
            f"[bootstrap] TrueForge rejected the model provider "
            f"(HTTP {response.status_code}). The key may be invalid, or the "
            "provider schema may have changed."
        )

    print(f"[bootstrap] Model provider '{PROVIDER}' configured")


def verify_model(expected: str) -> None:
    """Confirm the model Sentinel will ask for is actually listed."""

    response = httpx2.get(f"{API}/models", timeout=15)
    response.raise_for_status()

    available = [model["name"] for model in response.json().get("data", [])]

    if expected not in available:
        sys.exit(
            f"[bootstrap] '{expected}' is not available after configuring "
            f"the provider. TrueForge reports: {available or '(none)'}"
        )

    print(f"[bootstrap] Model '{expected}' is available")


def main() -> int:
    api_key = (os.environ.get("GEMINI_API_KEY") or "").strip()

    if not api_key:
        sys.exit(
            "[bootstrap] GEMINI_API_KEY is not set.\n"
            "Sentinel needs a model provider, and the key cannot live in the\n"
            "image. Set it as a secret on your hosting platform:\n"
            "  Hugging Face Spaces -> Settings -> Variables and secrets\n"
            "  Render              -> Environment -> Add Secret File/Var\n"
            "Get a key at https://aistudio.google.com/apikey"
        )

    # GET /models reports fully-qualified names ("google-gemini/gemini-3-6-
    # flash"), which is the same form $TRUEFORGE_MODEL takes, so this
    # compares like with like.
    wait_for_trueforge()
    configure_model_provider(api_key)
    verify_model(
        os.environ.get("TRUEFORGE_MODEL", "google-gemini/gemini-3-6-flash")
    )

    print("[bootstrap] TrueForge is ready for Sentinel")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
