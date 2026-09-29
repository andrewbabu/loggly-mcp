FROM node:18-slim

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY src ./src
COPY scripts ./scripts
COPY tool-manifest.json ./

EXPOSE 8787

CMD ["node", "src/http-server.js"]
