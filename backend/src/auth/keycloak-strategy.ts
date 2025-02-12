/**
 * Keycloak Authentication Strategy Configuration
 * 
 * This module provides the Keycloak OAuth2 OIDC authentication strategy for Passport.
 * It handles user authentication through Keycloak, including:
 * - Strategy configuration with PKCE support
 * - User profile verification and transformation
 * - Session serialization/deserialization
 * 
 * Usage:
 * ```
 * import { initializeKeycloakStrategy } from './auth/keycloak-strategy';
 * // ... after passport initialization ...
 * initializeKeycloakStrategy();
 * ```
 * 
 * @module auth/keycloak-strategy
 */

import passport from 'passport';
import KeycloakStrategy from 'passport-keycloak-oauth2-oidc-portable';
import { logger } from '../logger';
import { Request } from 'express';
import { 
  KEYCLOAK_REALM, 
  KEYCLOAK_AUTH_SERVER_URL, 
  KEYCLOAK_CLIENT_ID,
  KEYCLOAK_CALLBACK_URL 
} from '../config/env';

export function initializeKeycloakStrategy() {
  passport.use(
    new KeycloakStrategy(
      {
        realm: KEYCLOAK_REALM || '',
        authServerURL: KEYCLOAK_AUTH_SERVER_URL || '',
        clientID: KEYCLOAK_CLIENT_ID || '',
        callbackURL: KEYCLOAK_CALLBACK_URL || '',
        publicClient: true,
        sslRequired: 'all',
        state: true,
        pkce: true,
        debugPKCE: true,
        useCustomStateStore: false,
        scope: 'openid profile email',
      },
      (req: Request, accessToken: string, refreshToken: string, profile: any, done: Function) => {
        try {
          // Log the full session state
          logger.debug('Strategy verify callback - Session state:', {
            sessionID: req.sessionID,
            hasSession: !!req.session,
            oauthState: (req.session as any)?.oauthState ? 'present' : 'missing',
          });

          const idToken = profile._id_token || null;
          const user = {
            ...profile,
            tokens: { accessToken, refreshToken, idToken }
          };
          
          return done(null, user);
        } catch (error) {
          logger.error('Keycloak Strategy Error:', { error });
          return done(error);
        }
      }
    )
  );

  logger.info('Keycloak authentication strategy initialized');
  return passport;
}
