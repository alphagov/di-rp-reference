ARG VERSION=16-alpine
FROM node:$VERSION AS build-env
WORKDIR /app

# Copy package and restore as distinct layers
COPY package*.json ./
RUN npm ci

# Copy everything else and build
COPY ./ ./
RUN npm run build

# Runtime image
FROM node:$VERSION
ARG NODE_PORT=8080

RUN adduser \
  --disabled-password \
  --home /app \
  --gecos '' app \
  && chown -R app /app
USER app
WORKDIR /app

COPY package*.json ./
RUN npm ci --production

COPY --from=build-env /app/dist .

ENV NODE_PORT=${NODE_PORT}
EXPOSE ${NODE_PORT}

ENTRYPOINT ["node", "./index.js"]