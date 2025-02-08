/**
 * index.ts
 * Main entry point for the server.
 * Initializes environment, runs runtime checks, and starts the HTTPS/HTTP server.
 */

import fs from 'fs';
import path from 'path';
import https from 'https';
import { getFilePath, resolveFromRoot } from './utils/paths';
import { logger } from './logger';
import { createApp } from './app';
import { PORT, SESSION_SECRET, KEYCLOAK_REALM, KEYCLOAK_AUTH_SERVER_URL,
  KEYCLOAK_CLIENT_ID, KEYCLOAK_CALLBACK_URL, BFF_LOGOUT_CALLBACK_URL } from './config/env';

export * from './app';

const { __dirname } = getFilePath(import.meta.url);

// Runtime checks
if (!PORT) {
  logger.error('PORT not defined.');
  process.exit(1);
}
if (!SESSION_SECRET) {
  logger.error('SESSION_SECRET not defined.');
  process.exit(1);
}
if (!KEYCLOAK_REALM) {
  logger.error('KEYCLOAK_REALM not defined.');
  process.exit(1);
}
if (!KEYCLOAK_AUTH_SERVER_URL) {
  logger.error('KEYCLOAK_AUTH_SERVER_URL not defined.');
  process.exit(1);
}
if (!KEYCLOAK_CLIENT_ID) {
  logger.error('KEYCLOAK_CLIENT_ID not defined.');
  process.exit(1);
}
if (!KEYCLOAK_CALLBACK_URL) {
  logger.error('KEYCLOAK_CALLBACK_URL not defined.');
  process.exit(1);
}
if (!BFF_LOGOUT_CALLBACK_URL) {
  logger.error('BFF_LOGOUT_CALLBACK_URL not defined.');
  process.exit(1);
}

const SERVER_PORT = parseInt(PORT, 10) || 3000;
const app = createApp();

const BACKEND_CERT = path.join(__dirname, '../certs/backend.cert.pem');
const BACKEND_KEY = path.join(__dirname, '../certs/backend.key.pem');

if (fs.existsSync(BACKEND_CERT) && fs.existsSync(BACKEND_KEY)) {
  const httpsOptions = {
    key: fs.readFileSync(BACKEND_KEY),
    cert: fs.readFileSync(BACKEND_CERT),
  };
  https.createServer(httpsOptions, app).listen(SERVER_PORT, () => {
    logger.info(`HTTPS server running at https://localhost:${SERVER_PORT}`);
  });
} else {
  app.listen(SERVER_PORT, () => {
    logger.info(`HTTP server running at http://localhost:${SERVER_PORT}`);
  });
}
