# HORUS frontend — Vite production build served by nginx.
# The built app calls same-origin /api/*, which nginx proxies to the
# backend service, so no VITE_API_BASE_URL is needed at build time.
# Build from the repo root:  docker build -f frontend/Dockerfile ./frontend

# ---- build stage ----
FROM node:20-slim AS build
WORKDIR /app

# Install dependencies first (better layer caching).
COPY package.json package-lock.json ./
RUN npm ci

# Build the static bundle.
COPY . ./
RUN npm run build

# ---- serve stage ----
FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
