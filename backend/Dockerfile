# ----------- BUILD STAGE -----------
FROM node:20 AS builder

WORKDIR /app

COPY package*.json ./
RUN npm install --include=dev   # 🔥 quan trọng

COPY . .
RUN npm run build


# ----------- PRODUCTION STAGE -----------
FROM node:20

WORKDIR /app

COPY package*.json ./
RUN npm install --omit=dev

COPY --from=builder /app/dist ./dist

EXPOSE 5000

CMD ["node", "dist/main.js"]