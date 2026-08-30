# Hosting Sentinel

The whole stack runs in one container: TrueForge, the Sentinel MCP server and
the operator console. Only the console is published.

```
internet ──https──> :$PORT  console (token required)
                       │
                       ├─ localhost:8790  TrueForge      ← holds the model key
                       └─ localhost:8791  Sentinel MCP   ← serves login history
```

TrueForge and the MCP server stay on loopback **inside** the container.
TrueForge's own startup banner says standalone mode is not hardened for shared
internet access, and it has no authentication of its own — so it is never
exposed. The console is the only public surface, and it requires a bearer
token on every route.

---

## What you need

| | |
|---|---|
| A Gemini API key | <https://aistudio.google.com/apikey> — the free tier is enough for a demo |
| A host that runs a Docker container **always on** | see below |

**Serverless will not work.** An investigation takes 30–60s, streams over SSE,
and *pauses indefinitely* at the approval gate (up to 10 minutes by default).
Vercel/Netlify functions cap out long before that. You need a real container.

---

## Option A — Hugging Face Spaces (recommended: free, no credit card)

1. Create a Space → **Docker** → *Blank*.
2. Push this repository to it (a Space is a git remote):

   ```bash
   git remote add space https://huggingface.co/spaces/<you>/sentinel
   git push space fix/trace-thread-correlation:main
   ```

3. **Settings → Variables and secrets**, add as *Secrets*:

   | Name | Value |
   |---|---|
   | `GEMINI_API_KEY` | your key |
   | `SENTINEL_CONSOLE_TOKEN` | `openssl rand -hex 24` |

4. Wait for the build. Your URL is:

   ```
   https://<you>-sentinel.hf.space/?token=<SENTINEL_CONSOLE_TOKEN>
   ```

Spaces listens on 7860, which is this image's default. Free Spaces sleep after
~48h idle and wake on the next request.

## Option B — Render (free web service)

1. **New → Web Service**, connect the repo, Runtime **Docker**.
2. Environment: `GEMINI_API_KEY`, `SENTINEL_CONSOLE_TOKEN`. Render supplies
   `$PORT`; the entrypoint reads it.
3. Free instances **spin down after 15 minutes idle** and take ~1 minute to
   cold-start. Warm it up before a judge clicks the link.

## Option C — Google Cloud Run (free tier, needs a card)

Scales to zero, and its request timeout goes to 60 minutes, so SSE and the
approval pause both survive.

```bash
gcloud run deploy sentinel --source . \
  --port 7860 --timeout 3600 --min-instances 0 --allow-unauthenticated \
  --set-env-vars TRUEFORGE_MODEL=google-gemini/gemini-3-6-flash \
  --set-secrets GEMINI_API_KEY=gemini-key:latest,SENTINEL_CONSOLE_TOKEN=console-token:latest
```

`--allow-unauthenticated` puts Cloud Run's own gate aside; Sentinel's console
token is still enforced.

---

## Run it locally first

Always do this before pushing — it is the same image the host will build.

```bash
docker build -t sentinel:live .
docker run --rm -p 7860:7860 \
  -e GEMINI_API_KEY="$GEMINI_API_KEY" \
  -e SENTINEL_CONSOLE_TOKEN=demotoken \
  sentinel:live
```

Then open <http://127.0.0.1:7860/?token=demotoken>.

Healthy startup ends with all five checks green:

```
Sentinel readiness
  [OK  ] Evidence DB       READY      1 user(s), 51 login events, 2 network records, read-only
  [OK  ] MCP server        READY      7 tools, authenticated at http://127.0.0.1:8791/mcp
  [OK  ] TrueForge         READY      v0.1.4 API at http://localhost:8790
  [OK  ] Model             READY      google-gemini/gemini-3-6-flash
  [OK  ] Operator console  READY      built (ui/web/dist)
```

If a check fails the container exits and prints the fix, plus the tails of
`trueforge.log` and `mcp.log`.

---

## Configuration

| Variable | Default | Notes |
|---|---|---|
| `GEMINI_API_KEY` | — | **Required.** Never baked into the image. |
| `SENTINEL_CONSOLE_TOKEN` | generated per boot | Set it, or the URL changes on every restart. |
| `TRUEFORGE_MODEL` | `google-gemini/gemini-3-6-flash` | Must be tool-calling capable. |
| `PORT` | `7860` | Supplied by most hosts. |
| `SENTINEL_MCP_TOKEN` | generated per boot | Internal only; never leaves the container. |

---

## What survives a restart, and what does not

The container is **stateless by design**, which is what makes it deployable to
a free ephemeral host:

- **Self-healing.** `SentinelAgent.provision()` registers the MCP server and
  upserts the agent at the start of every investigation, so a blank TrueForge
  database needs no setup. `deploy/bootstrap.py` handles the one thing that
  cannot self-heal — the model provider, because it is a secret.
- **Reset every boot.** The evidence database is reseeded from
  `data/init_db.py`. The demo is identical on every restart, which is what you
  want for a judged demo.
- **Lost on restart.** The containment audit log, in-flight investigations,
  and TrueForge session history. None of it matters for a demo; all of it
  would matter in production, where you would mount a volume at
  `/app/data` and `~/.local/share/trueforge`.

---

## Cost and abuse

A public URL with your API key behind it means **anyone who has the URL can
spend your quota.** The console token is what stands between the two, which is
why the entrypoint refuses to run without one and generates it if you did not.

For a submission link, treat the token as part of the URL and accept that
whoever you send it to can run investigations. If you need tighter control,
rotate the token by restarting, or put the Space in private mode and share
access instead.

Gemini's free tier is rate-limited, which caps the damage but also means a
burst of concurrent judges may hit 429s. `gemini-3-6-flash` is the cheapest
model that reliably completes a tool-using turn here.

---

## Known limits

- **Sandbox is unavailable in the container**, exactly as it is locally. The
  image has no `bwrap`/`socat`/`rg`, so TrueForge logs
  `Local sandbox fallback is unavailable` at startup. Harmless — Sentinel sets
  `sandbox.enabled: false` and never asks for one.
- **`--delegate` is slower and more rate-limit-prone**, and more so on a small
  free instance. Keep the default linear path for a hosted demo.
- **Cold starts.** On Render and Spaces, the first request after idle pays
  container start plus ~15s of TrueForge migrations and readiness checks.
