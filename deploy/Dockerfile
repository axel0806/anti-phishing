# One image for both the API and the worker; the ROLE environment variable picks which runs.
FROM node:22-slim

ENV NODE_ENV=production
WORKDIR /app

# Install dependencies first so source changes don't invalidate this layer.
COPY package.json package-lock.json ./
COPY apps/api/package.json apps/api/
COPY apps/local/package.json apps/local/
COPY apps/extension/package.json apps/extension/
COPY packages/shared/package.json packages/shared/
COPY packages/scoring/package.json packages/scoring/
COPY packages/parser/package.json packages/parser/
COPY packages/detectors/package.json packages/detectors/
COPY packages/pipeline/package.json packages/pipeline/
COPY packages/mail/package.json packages/mail/
COPY packages/settings/package.json packages/settings/
COPY packages/db/package.json packages/db/
COPY corpus/package.json corpus/
# tsx runs the TypeScript sources directly, so dev dependencies are needed at runtime.
RUN npm ci --include=dev

COPY tsconfig.json ./
COPY packages packages
COPY apps/api apps/api

# Run as the unprivileged "node" user that ships with the image.
USER node
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s \
  CMD node -e "fetch('http://127.0.0.1:' + (process.env.PORT || 8080) + '/v1/health').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"
CMD ["node_modules/.bin/tsx", "apps/api/src/main.ts"]
