# Argus MCP Server - Standalone Container
# RAP-295: Air-Gap Foundation - MCP Server Docker Image
#
# Build:
#   docker build -t argus-mcp-server:latest .
#
# Run:
#   docker run -p 3000:3000 \
#     -e ARGUS_BRAIN_URL=http://brain:8000 \
#     -e MINIO_ENDPOINT=minio:9000 \
#     argus-mcp-server:latest

FROM node:20-alpine AS builder

WORKDIR /app

# Install dependencies
COPY package*.json ./
RUN npm ci

# Copy source and build
COPY tsconfig.json ./
COPY src/ ./src/
RUN npm run build

# Production image
FROM node:20-alpine AS runner

WORKDIR /app

# Create non-root user
RUN addgroup -g 1001 -S argus && \
    adduser -S argus -u 1001 -G argus

# Copy built files
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/node_modules ./node_modules
COPY package.json ./

# Set ownership
RUN chown -R argus:argus /app

USER argus

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/health || exit 1

# Environment defaults
ENV NODE_ENV=production
ENV PORT=3000
ENV HOST=0.0.0.0
ENV STORAGE_PROVIDER=minio
ENV MINIO_ENDPOINT=localhost:9000
ENV MINIO_ACCESS_KEY=minioadmin
ENV MINIO_SECRET_KEY=minioadmin
ENV MINIO_BUCKET=argus-artifacts
ENV MINIO_SECURE=false
ENV REDIS_URL=redis://localhost:6379
ENV ARGUS_BRAIN_URL=http://localhost:8000
ENV LOG_LEVEL=info

# Start server
CMD ["node", "dist/server.js"]
