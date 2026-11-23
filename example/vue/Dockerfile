# Built from the repository root (see compose.yaml) so the example can
# compile the sealbase-client lib from ./client.

# 1. Build: install the npm workspace, build the lib, then the example.
FROM node:24-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
COPY client client
COPY example/vue/package.json example/vue/
RUN npm ci
COPY example/vue example/vue
RUN npm run build -w sealbase-example-vue

# 2. Serve the static build.
FROM nginx:1.25-alpine AS prod
WORKDIR /usr/share/nginx/html
COPY --from=build /app/example/vue/dist .

# SPA fallback: unknown paths (e.g. /demo/1) serve index.html
COPY example/vue/nginx.conf /etc/nginx/conf.d/default.conf

# The entrypoint regenerates env.js from container env vars at startup, so
# VITE_API_BASE_URL can change without rebuilding.
COPY example/vue/docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

EXPOSE 80
ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["nginx", "-g", "daemon off;"]
