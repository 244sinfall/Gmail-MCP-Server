# Build stage: compile TypeScript to dist/
FROM node:20-slim AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci --ignore-scripts
COPY . .
RUN npm run build

# Runtime stage: production deps + compiled output
FROM node:20-slim AS runtime
WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev --ignore-scripts

COPY --from=build /app/dist ./dist

RUN mkdir -p /config

RUN mkdir -p /mnt/auth

# Runtime helper to drop privileges after fixing volume permissions
RUN apt-get update \
  && apt-get install -y --no-install-recommends gosu \
  && rm -rf /var/lib/apt/lists/*

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENV NODE_ENV=production
ENV GMAIL_OAUTH_PATH=/config/gcp-oauth.keys.json
ENV GMAIL_MCP_TOKEN_PATH=/config/tokens.json
ENV GMAIL_MCP_HOST=0.0.0.0
ENV GMAIL_MCP_PORT=3000

EXPOSE 3000

USER root

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["node", "dist/index.js", "start"]
