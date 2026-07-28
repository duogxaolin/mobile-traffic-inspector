FROM node:22.12.0-alpine AS build
WORKDIR /build
COPY web/package.json web/package-lock.json ./
RUN npm ci
COPY web/ .
RUN npm run build

FROM caddy:2.8.4-alpine
RUN addgroup -S -g 10001 caddyapp && adduser -S -D -H -u 10001 -G caddyapp caddyapp \
    && chown -R caddyapp:caddyapp /data /config /tmp /run
COPY --from=build /build/dist /srv
COPY Caddyfile /etc/caddy/Caddyfile
USER caddyapp
