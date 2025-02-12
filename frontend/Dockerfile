FROM node:22-alpine

WORKDIR /app

COPY package*.json ./
COPY ./certs ./certs/

RUN npm install

COPY . .

EXPOSE 4200

CMD ["npm", "start"]
