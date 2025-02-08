/**
 * keycloakStrategy.ts
 * Implements the passport Keycloak OAuth2 OIDC strategy.
 * Exports nothing; importing sets up the strategy.
 */

import passport from 'passport';
import KeycloakStrategy from 'passport-keycloak-oauth2-oidc-portable';
import { logger } from '../logger';
import { Request } from 'express';
import { KEYCLOAK_REALM, KEYCLOAK_AUTH_SERVER_URL, KEYCLOAK_CLIENT_ID,
  KEYCLOAK_CALLBACK_URL } from '../config/env';

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
      scope: 'openid profile email',
    },
    (_req: Request, accessToken: string, refreshToken: string, profile: any, done: Function) => {
      try {
        const user = { ...profile, accessToken, refreshToken };
        logger.debug('Keycloak Strategy - user verified:', { userId: user.id });
        return done(null, user);
      } catch (error) {
        logger.error('Keycloak Strategy Error:', { error });
        return done(error);
      }
    }
  )
);

// Serialize/deserialize
passport.serializeUser((user: any, done: Function) => {
  done(null, user);
});
passport.deserializeUser((obj: any, done: Function) => {
  done(null, obj);
});
