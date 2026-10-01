FROM node:22-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY src ./src
COPY scripts ./scripts
COPY public ./public
RUN mkdir -p /app/data && chown -R node:node /app/data
USER node
ENV PORT=3000 DATABASE_PATH=/app/data/pagoradar.db
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:3000/health || exit 1
CMD ["node", "--disable-warning=ExperimentalWarning", "src/server.js"]
