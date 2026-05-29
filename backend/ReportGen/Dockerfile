# syntax=docker/dockerfile:1.4
# ReportGen Dockerfile (Debian-based for Puppeteer compatibility)
# Builder stage (with dev deps to compile TypeScript)
FROM node:18-bullseye-slim AS builder
WORKDIR /app
COPY package.json ./
RUN npm install
# Force Puppeteer to download Chromium at build time so runtime has browser available
RUN node -e "try { require('puppeteer'); console.log('puppeteer OK'); } catch (e) { console.error('puppeteer install check failed', e); process.exit(0); }"
COPY . .
RUN npm run build

# Runtime stage
FROM node:18-bullseye-slim

# Install dependencies required by Chromium/Puppeteer. Debian mirrors can drop
# large installs on slow links, so retry the install without discarding downloads.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
  --mount=type=cache,target=/var/lib/apt/lists,sharing=locked \
  set -eux; \
  apt_opts='-o Acquire::Retries=8 -o Acquire::http::Timeout=120 -o Acquire::https::Timeout=120 -o Acquire::http::No-Cache=True'; \
  apt-get $apt_opts update; \
  for attempt in 1 2 3 4 5; do \
    apt-get $apt_opts install -y --no-install-recommends \
      ca-certificates \
      fonts-liberation \
      libasound2 \
      libatk1.0-0 \
      libcups2 \
      libdbus-1-3 \
      libgdk-pixbuf2.0-0 \
      libgtk-3-0 \
      libx11-xcb1 \
      libxcomposite1 \
      libxdamage1 \
      libxrandr2 \
      libxss1 \
      libnss3 \
      libgbm1 \
      libpangocairo-1.0-0 \
      fonts-noto-color-emoji \
      wget \
      gnupg \
      && break; \
    if [ "$attempt" = 5 ]; then exit 1; fi; \
    apt-get $apt_opts update; \
    sleep 15; \
  done; \
  rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy only production deps
COPY package.json ./
RUN npm install --only=production

# Copy built artifacts and templates from builder
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/src/templates ./src/templates
COPY --from=builder /app/src/templates/assets ./src/templates/assets
COPY --from=builder /app/package.json ./package.json

# Copy Puppeteer's downloaded Chromium from builder to a path accessible by the runtime 'node' user
COPY --from=builder /root/.cache/puppeteer /home/node/.cache/puppeteer
RUN chown -R node:node /home/node/.cache/puppeteer || true

# Create tmp and reports directories
RUN mkdir -p /app/tmp /app/reports && chown -R node:node /app/tmp /app/reports

# Use non-root user
# Keep default user (root) so we can chown mounted volumes at startup
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=false
ENV PUPPETEER_CACHE_DIR=/home/node/.cache/puppeteer
ENV PORT=3005
EXPOSE ${PORT}

# On container start: ensure mounted volumes are writable by the 'node' user, then drop privileges to run as 'node'
CMD ["sh", "-c", "chown -R node:node /app/tmp /app/reports 2>/dev/null || true; su node -c 'node dist/app.js'"]
