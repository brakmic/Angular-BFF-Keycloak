/**
 * env.ts
 *
 * Loads and centralizes environment variable configuration.
 * Exports constants for server, authentication, session, and other settings.
 * 
 * @module config/env
 */

import * as dotenv from 'dotenv-safe';
import path from 'path';
import { getFilePath } from '../utils/paths';

const { __dirname } = getFilePath(import.meta.url);

dotenv.config({
  path: path.join(__dirname, '../../.env'),
  example: path.join(__dirname, '../../.env.example'),
  allowEmptyValues: true,
});

export const {
  PORT,
  SESSION_SECRET,
  KEYCLOAK_REALM,
  KEYCLOAK_AUTH_SERVER_URL,
  KEYCLOAK_CLIENT_ID,
  KEYCLOAK_CALLBACK_URL,
  BFF_LOGOUT_CALLBACK_URL,
  NODE_ENV,
} = process.env as { [key: string]: string | undefined };

export const SESSION_DOMAIN = process.env.SESSION_DOMAIN || 'localhost';
export const COOKIE_ORIGIN = process.env.COOKIE_ORIGIN || 'https://localhost:4200';
export const SESSION_STORE = process.env.SESSION_STORE || 'in-memory';
