# Multi-service container: Node.js app + MongoDB
# Base image: Node 20 on Debian (bullseye)
FROM node:20-bullseye

# Install MongoDB (mongodb-org) for Debian 11 (bullseye)
RUN apt-get update \
  && apt-get install -y curl gnupg ca-certificates \
  && install -m 0755 -d /etc/apt/keyrings \
  && curl -fsSL https://www.mongodb.org/static/pgp/server-6.0.asc | gpg --dearmor -o /etc/apt/keyrings/mongodb-org-6.0.gpg \
  && echo "deb [ signed-by=/etc/apt/keyrings/mongodb-org-6.0.gpg ] https://repo.mongodb.org/apt/debian bullseye/mongodb-org/6.0 main" \
     | tee /etc/apt/sources.list.d/mongodb-org-6.0.list \
  && apt-get update \
  && apt-get install -y mongodb-org \
  && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Prepare MongoDB data dir
RUN mkdir -p /data/db

# Copy only package files first to leverage Docker layer caching
COPY package.json package-lock.json ./

# Install dependencies
RUN npm ci

# Copy the rest of the server source
COPY tsconfig.json ./
COPY src ./src

# Build TypeScript and copy views
RUN npm run build

# Environment defaults (can be overridden)
ENV PORT=3000 \
    NODE_ENV=production \
    MONGODB_URI=mongodb://127.0.0.1:27017/oauth-server \
    CLIENT_URL=http://localhost:3001 \
    UI_BASE_URL=http://localhost:3001 \
    SESSION_SECRET=your-session-secret

# Expose app and MongoDB ports
EXPOSE 3000 27017

# Start MongoDB in background then start Node server
CMD bash -lc "mongod --dbpath /data/db --bind_ip_all & sleep 3 && node dist/app.js"
