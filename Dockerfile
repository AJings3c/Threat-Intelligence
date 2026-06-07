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

COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package.json ./package.json
COPY --from=builder /app/backend/package.json ./backend/package.json
COPY --from=builder /app/backend/dist ./backend/dist
COPY --from=builder /app/frontend/dist ./frontend/dist

EXPOSE 4000
WORKDIR /app/backend
CMD ["node", "dist/index.js"]
