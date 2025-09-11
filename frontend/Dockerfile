# Build stage
FROM node:lts-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci

# Inject Vite build-time env so API base is baked into the bundle
ARG VITE_API_BASE
ENV VITE_API_BASE=${VITE_API_BASE}

COPY . .
RUN npm run build

# Runtime (static file server)
FROM caddy:2
WORKDIR /app
COPY Caddyfile ./
COPY --from=build /app/dist ./dist
# Railway injects $PORT; Caddyfile uses it
CMD ["caddy","run","--config","Caddyfile","--adapter","caddyfile"]
