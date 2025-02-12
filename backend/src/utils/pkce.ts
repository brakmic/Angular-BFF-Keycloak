/**
 * pkce.ts
 * 
 * Description:
 *  - Provides helper functions for PKCE (Proof Key for Code Exchange) code generation.
 *  - Helps with secure OAuth2-based flows (e.g., Keycloak).
 * 
 * API:
 *  - generateCodeVerifier(length): Returns a random base64URL-safe string.
 *  - generateCodeChallenge(codeVerifier): Returns a SHA-256 code challenge from codeVerifier.
 * 
 @module utils/pkce
 */

import { Buffer } from 'buffer';
import crypto from 'crypto';

/**
 * Generates a random code verifier string.
 */
export function generateCodeVerifier(length: number = 128): string {
  const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
  let codeVerifier = '';
  for (let i = 0; i < length; i++) {
    codeVerifier += possible.charAt(Math.floor(Math.random() * possible.length));
  }
  return codeVerifier;
}

/**
 * Generates a code challenge from a code verifier using SHA-256.
 */
export function generateCodeChallenge(codeVerifier: string): string {
  return base64URLEncode(sha256(codeVerifier));
}

function sha256(str: string): Buffer {
  return crypto.createHash('sha256').update(str).digest();
}

function base64URLEncode(buffer: Buffer): string {
  return buffer
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}
