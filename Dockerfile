# syntax=docker/dockerfile:1

# --- Build stage: install all deps and build both workspaces ---
FROM node:22-bookworm-slim AS builder
WORKDIR /app

# Install deps first (better layer caching). All workspace manifests must be present
# before `npm ci` so the workspace graph resolves.
COPY package.json package-lock.json ./
COPY backend/package.json backend/package.json
COPY frontend/package.json frontend/package.json
RUN npm ci

COPY . .
RUN npm run build
# Drop dev dependencies so only runtime deps are copied into the final image.
RUN npm prune --omit=dev

# --- Runtime stage: minimal image that serves the API + built frontend ---
FROM node:22-bookworm-slim AS runner
WORKDIR /app
ENV NODE_ENV=production
ENV PORT=4000
ENV DATA_DIR=/app/data

COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./package.json
COPY --from=builder /app/backend/package.json ./backend/package.json
COPY --from=builder /app/backend/dist ./backend/dist
COPY --from=builder /app/frontend/dist ./frontend/dist

RUN mkdir -p /app/data && chown -R node:node /app

EXPOSE 4000
WORKDIR /app/backend
USER node
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:4000/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "dist/index.js"]
