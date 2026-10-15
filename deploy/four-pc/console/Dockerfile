FROM node:22-alpine AS builder
WORKDIR /src
COPY console/package*.json ./
RUN npm install --no-audit --no-fund
COPY console/ ./
RUN npm run build

FROM nginx:stable-alpine
COPY deploy/four-pc/console/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /src/dist/ /usr/share/nginx/html/
EXPOSE 8088
