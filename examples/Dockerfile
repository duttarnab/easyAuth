# Examples Dockerfile: runs examples/backend and serves examples/web-client
FROM node:20-bullseye as builder

WORKDIR /examples

# Install backend deps
COPY examples/backend/package.json examples/backend/package-lock.json ./backend/
RUN cd backend && npm ci

# Install web-client deps and build
COPY examples/web-client/package.json examples/web-client/package-lock.json ./web-client/
RUN cd web-client && npm ci

# Copy source
COPY examples/backend ./backend
COPY examples/web-client ./web-client

# Build web-client (VITE_CLIENT_ID can be provided at build time)
ARG VITE_CLIENT_ID=your_client_id
ENV VITE_CLIENT_ID=$VITE_CLIENT_ID
RUN cd web-client && npm run build

# Runtime image
FROM node:20-bullseye
WORKDIR /examples

# Copy backend runtime files
COPY --from=builder /examples/backend /examples/backend

# Copy built web-client dist
COPY --from=builder /examples/web-client/dist /examples/web-client/dist

# Minimal static server for the built web-client
RUN npm install -g serve

ENV PORT=3001 \
    BACKEND_PORT=3002

EXPOSE 3001 3002

# Start both: backend (3002) and static web (3001)
CMD bash -lc "node backend/index.js & serve -s web-client/dist -l 3001 && wait"
