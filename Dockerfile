ARG NODEJS_IMAGE=node:24.16.0-alpine3.23
FROM $NODEJS_IMAGE AS base

# Install dependencies only when needed
FROM base AS deps
# Check https://github.com/nodejs/docker-node/tree/b4117f9333da4138b03a546ec926ef50a31506c3#nodealpine to understand why libc6-compat might be needed.
RUN apk add --no-cache libc6-compat
# Install dependencies including Python
RUN apk add --no-cache python3 py3-pip make g++ \
    && ln -sf python3 /usr/bin/python \
    && ln -sf pip3 /usr/bin/pip
WORKDIR /app

# Install dependencies based on the preferred package manager
COPY package.json package-lock.json  ./
COPY npm npm
COPY internal-ui internal-ui
COPY migrate.sh ./
RUN npm i
RUN npm rebuild --arch=x64 --platform=linux --libc=musl sharp


# Rebuild the source code only when needed
FROM base AS builder
WORKDIR /app

COPY --from=deps /app/npm ./npm
COPY --from=deps /app/internal-ui ./internal-ui
COPY --from=deps /app/node_modules ./node_modules
COPY . .


# Next.js collects completely anonymous telemetry data about general usage.
# Learn more here: https://nextjs.org/telemetry
# Uncomment the following line in case you want to disable telemetry during the build.
ENV NEXT_TELEMETRY_DISABLED=1

RUN npm run build

# Production image, copy all the files and run next
FROM $NODEJS_IMAGE AS runner

# Required to get the latest, CVE-free dependencies.
RUN apk update && apk upgrade
WORKDIR /app

ENV NODE_OPTIONS="--max-http-header-size=81920 --dns-result-order=ipv4first"


ENV NODE_ENV=production
# Uncomment the following line in case you want to disable telemetry during runtime.
ENV NEXT_TELEMETRY_DISABLED=1

RUN addgroup --system --gid 1001 nodejs
RUN adduser --system --uid 1001 nextjs


COPY --from=builder /app/public ./public

# Automatically leverage output traces to reduce image size
# https://nextjs.org/docs/advanced-features/output-file-tracing
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static

# Support for DB migration
COPY --from=builder --chown=nextjs:nodejs /app/migrate.sh ./migrate.sh
COPY npm npm
RUN chmod +x migrate.sh
# Pin npm to a patched version so the bundled npm CLI no longer ships
# vulnerable transitive deps (picomatch, minimatch, brace-expansion, tar).
RUN npm install -g npm@11.13.0
# Install migration tools from a checked-in package.json + lockfile so npm
# overrides apply to transitive dependencies (e.g., uuid in typeorm/mssql)
# and the install is reproducible. migrate.sh resolves them via
# MIGRATE_DEPS_DIR/NODE_PATH.
COPY migrate-deps /opt/migrate-deps
RUN cd /opt/migrate-deps && \
    npm ci --ignore-scripts && \
    ln -sf /opt/migrate-deps/node_modules/.bin/ts-node /usr/local/bin/ts-node && \
    ln -sf /opt/migrate-deps/node_modules/.bin/migrate-mongo /usr/local/bin/migrate-mongo && \
    ln -sf /opt/migrate-deps/node_modules/.bin/typeorm /usr/local/bin/typeorm
ENV MIGRATE_DEPS_DIR=/opt/migrate-deps/node_modules
ENV NODE_PATH=/opt/migrate-deps/node_modules
USER nextjs

EXPOSE 5225

ENV PORT=5225

CMD ["node", "server.js"]
