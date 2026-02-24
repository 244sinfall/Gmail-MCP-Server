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

ENV NODE_ENV=production
ENV GMAIL_OAUTH_PATH=/config/gcp-oauth.keys.json
ENV GMAIL_MCP_TOKEN_PATH=/config/tokens.json
ENV GMAIL_MCP_HOST=0.0.0.0
ENV GMAIL_MCP_PORT=3000

EXPOSE 3000

USER node

ENTRYPOINT ["node", "dist/index.js", "start"]
