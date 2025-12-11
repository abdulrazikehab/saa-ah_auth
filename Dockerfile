FROM node:20-alpine

WORKDIR /app

COPY package.json package-lock.json ./
COPY prisma ./prisma/

RUN npm ci

COPY . .

# Generate Prisma Client
RUN npm run prisma:generate

# Build NestJS app (we added the build script)
RUN npm run build

EXPOSE 3001

CMD ["npm", "run", "start:prod"]
