# syntax=docker/dockerfile:1

# ---- Build stage: install all deps and build backend + frontend ----
FROM node:22-alpine AS build
WORKDIR /app

# Install dependencies first (better layer caching). Workspaces need every
# package.json present before `npm ci`.
COPY package.json package-lock.json ./
COPY backend/package.json backend/package.json
COPY frontend/package.json frontend/package.json
RUN npm ci

COPY . .
RUN npm run build

# ---- Runtime stage: production deps + built artifacts only ----
FROM node:22-alpine AS runtime
ENV NODE_ENV=production
WORKDIR /app

COPY package.json package-lock.json ./
COPY backend/package.json backend/package.json
COPY frontend/package.json frontend/package.json
RUN npm ci --omit=dev && npm cache clean --force

# Backend serves the built SPA from ../../frontend/dist (see backend/src/index.ts).
COPY --from=build /app/backend/dist ./backend/dist
COPY --from=build /app/frontend/dist ./frontend/dist

EXPOSE 4000
USER node
CMD ["node", "backend/dist/index.js"]
