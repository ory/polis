ARG NODEJS_IMAGE=node:24.13.1-alpine3.23
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
# mongodb peer dependency would be automatically installed for migrate-mongo
RUN npm install -g ts-node migrate-mongo typeorm reflect-metadata mssql mysql2 pg
USER nextjs

EXPOSE 5225

ENV PORT=5225

CMD ["node", "server.js"]
