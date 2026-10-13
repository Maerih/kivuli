FROM node:22-alpine AS build
WORKDIR /app
ENV NEXT_TELEMETRY_DISABLED=1
COPY package.json package-lock.json ./
# Packages fetched ahead of time by tools/fetch_deps.py - which ./ctl.sh runs
# before building - are installed offline through a throwaway local registry;
# npm still verifies each one against package-lock.json. With an empty
# .npm-offline/ folder npm downloads from the public registry as usual.
COPY .npm-offline/ /npm-offline/
COPY tools/offline-registry.mjs /tools/offline-registry.mjs
RUN if [ -n "$(find /npm-offline -name '*.tgz' -print -quit)" ]; then \
      (node /tools/offline-registry.mjs /npm-offline &) && sleep 1 \
      && npm ci --no-audit --no-fund --registry http://127.0.0.1:4873/; \
    else \
      npm ci --no-audit --no-fund --fetch-retries 8 --fetch-retry-maxtimeout 120000; \
    fi
COPY . .
RUN npm run build

FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production \
    NEXT_TELEMETRY_DISABLED=1 \
    PORT=3000 \
    HOSTNAME=0.0.0.0
COPY --from=build --chown=node:node /app/.next/standalone ./
COPY --from=build --chown=node:node /app/.next/static ./.next/static
COPY --from=build --chown=node:node /app/public ./public
USER node
EXPOSE 3000
CMD ["node", "server.js"]
