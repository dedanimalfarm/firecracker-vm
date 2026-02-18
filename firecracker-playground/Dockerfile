# Optional development container. Recommended production mode is host systemd + nginx.
FROM node:18-bookworm-slim

WORKDIR /opt/firecracker-playground/app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    iproute2 \
    iptables \
    procps \
  && rm -rf /var/lib/apt/lists/*

COPY app/package.json ./
RUN npm install --omit=dev

COPY app/server.js ./server.js

ENV PORT=8080
EXPOSE 8080

CMD ["node", "server.js"]
