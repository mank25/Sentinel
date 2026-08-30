# Sentinel, whole stack, one container.
#
# Needs both runtimes: TrueForge is Node (@truefoundry/trueforge), Sentinel is
# Python. Debian bookworm ships Python 3.11, which is what pyproject requires,
# so starting from the Node image and adding Python is the shorter path.
FROM node:22-bookworm-slim

# openssl is used by the entrypoint to mint the two tokens.
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip python3-venv openssl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Pinned. TrueForge 0.1.4 is the version Sentinel's client was written
# against -- its MCP servers are remote-only and its approval-gate semantics
# are what the safety model depends on, so this is not a "latest" candidate.
RUN npm install -g @truefoundry/trueforge@0.1.4

WORKDIR /app

# Dependencies before source, so a code change does not reinstall them.
COPY pyproject.toml README.md ./
COPY investigator/__init__.py investigator/
COPY trueforge/__init__.py trueforge/
COPY ui/__init__.py ui/
COPY sentinel/__init__.py sentinel/

ENV PIP_BREAK_SYSTEM_PACKAGES=1
RUN pip3 install --no-cache-dir -e .

COPY . .

RUN chmod +x deploy/entrypoint.sh

# Hosting platforms hand the port over in $PORT; 7860 is the Hugging Face
# Spaces default and a reasonable fallback elsewhere.
ENV PORT=7860
ENV PYTHONUNBUFFERED=1

# Written to at runtime: the demo databases, the MCP token file, and
# TrueForge's own SQLite state. Hugging Face Spaces runs as a non-root user,
# so these have to be writable by anyone.
RUN mkdir -p /app/data /home/node/.config \
    && chmod -R 777 /app/data /home/node/.config

EXPOSE 7860

# Only the console is published. TrueForge (8790) and the MCP server (8791)
# stay on loopback inside the container -- TrueForge holds the model provider
# key and has no auth of its own.
CMD ["./deploy/entrypoint.sh"]
