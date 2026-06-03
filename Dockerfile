# Rook — self-hostable security scanner. Includes the pentest toolkit so the
# guarded-local exploit sandbox has curl/python available in-image.
FROM node:22-bookworm-slim
RUN apt-get update \
  && apt-get install -y --no-install-recommends git python3 make g++ ca-certificates curl \
  && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci
COPY . .
RUN npm run build && chmod +x docker-entrypoint.sh
# Run as the unprivileged `node` user, not root. (Untrusted target apps spawned
# during a scan therefore also run unprivileged; for stronger isolation set
# ROOK_SANDBOX=docker so exploits/targets run in their own container.)
RUN mkdir -p /app/data && chown -R node:node /app
USER node
ENV NODE_ENV=production
ENV ROOK_MODE=local
EXPOSE 3000
# Entrypoint routes subcommands: `start` (default, serves the app) and `scan-pr`
# (one-shot PR scan for the self-hosted GitHub Action, spec §9.4).
ENTRYPOINT ["./docker-entrypoint.sh"]
CMD ["start"]
