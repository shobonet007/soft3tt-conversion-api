FROM node:22-bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ffmpeg imagemagick libreoffice fonts-dejavu \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY package*.json ./
RUN npm install --omit=dev
COPY src ./src
RUN mkdir -p /app/storage/jobs && chown -R node:node /app
USER node
ENV NODE_ENV=production PORT=8080 STORAGE_DIR=/app/storage/jobs
EXPOSE 8080
CMD ["node","src/server.js"]
