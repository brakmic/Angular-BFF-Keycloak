/**
 * auth-routes.ts
 * Defines the routes for Keycloak-based authentication:
 *  - /auth/keycloak-init
 *  - /auth/keycloak
 *  - /auth/keycloak/callback
 *  - /auth/logout
 *  - /auth/logout/callback
 * Exports: authRoutes (function returning an Express.Router)
 */

import { Router, Request, Response, NextFunction } from 'express';
import passport from 'passport';
import { logger } from '../logger';
import { generateCodeVerifier, generateCodeChallenge } from '../utils/pkce';

const {
  KEYCLOAK_AUTH_SERVER_URL,
  KEYCLOAK_REALM,
  BFF_LOGOUT_CALLBACK_URL,
} = process.env as {
  KEYCLOAK_AUTH_SERVER_URL: string;
  KEYCLOAK_REALM: string;
  BFF_LOGOUT_CALLBACK_URL: string;
};

export const authRoutes: Router = Router();

/**
 * 1) /auth/keycloak-init
 * Generates PKCE parameters and saves them in session.
 */
authRoutes.get('/auth/keycloak-init', (req: Request, res: Response) => {
  const code_verifier = generateCodeVerifier();
  const code_challenge = generateCodeChallenge(code_verifier);

  req.session.code_verifier = code_verifier;
  req.session.code_challenge = code_challenge;

  logger.debug('Initializing authentication session:', {
    sessionID: req.sessionID,
    code_verifier: '*** exists ***',
    code_challenge: '*** exists ***',
  });

  req.session.save((err: any) => {
    if (err) {
      logger.error('Could not save session in /auth/keycloak-init:', { error: err });
      return res.status(500).send('Session save error');
    }
    logger.debug('Session saved successfully:', { sessionID: req.sessionID });

    res.send(`
      <html>
        <body>
          <script>
            window.location.href = '/auth/keycloak';
          </script>
        </body>
      </html>
    `);
  });
});

/**
 * 2) /auth/keycloak
 * Initiates the Keycloak login popup redirect
 */
authRoutes.get('/auth/keycloak', (req: Request, res: any, next: NextFunction) => {
  logger.debug('Initiating passport.authenticate:', {
    sessionID: req.sessionID,
    code_challenge: req.session.code_challenge ? '*** exists ***' : 'missing',
  });

  if (!req.session.code_challenge) {
    logger.error('Missing code_challenge in session');
    return res.status(400).send('Invalid authentication request.');
  }

  passport.authenticate('keycloak', {
    scope: ['openid', 'profile', 'email'],
  })(req, res, (err: any) => {
    if (err) {
      logger.error('Error during passport.authenticate:', { error: err });
    }
    const locationHeader = res.getHeader('Location');
    logger.info(`Outbound 302 to Keycloak => ${locationHeader}`);
    next(err);
  });
});

/**
 * 3) /auth/keycloak/callback
 * Keycloak redirects here after successful or failed auth
 */
authRoutes.get('/auth/keycloak/callback', (req: Request, res: Response, next: NextFunction) => {
  logger.info('Keycloak callback received:', {
    queryParams: {
      state: req.query.state ? '*** exists ***' : 'missing',
      code: req.query.code ? '*** exists ***' : 'missing',
    },
    sessionID: req.sessionID,
  });

  passport.authenticate('keycloak', (err: any, user: any, info: any) => {
    logger.debug('Passport auth result:', {
      error: err ? '*** exists ***' : 'none',
      user: user ? '*** exists ***' : 'missing',
      info: info ? '*** exists ***' : 'none',
    });

    if (err) {
      logger.error('Authentication pipeline error:', { error: err, sessionID: req.sessionID });
      return res.status(500).send('Internal Server Error');
    }
    if (!user) {
      logger.warn('Authentication failed:', { info });
      return res.redirect('/login');
    }

    req.logIn(user, (loginErr: any) => {
      if (loginErr) {
        logger.error('Session login error:', { error: loginErr, userId: user.id });
        return res.status(500).send('Login Error');
      }

      logger.info('User authenticated successfully:', {
        userId: user.id,
        sessionID: req.sessionID,
      });

      const popupCloseHtml = `
        <html>
          <body>
            <script>
              window.opener.postMessage({ type: 'LOGIN_SUCCESS' }, '*');
              window.close();
            </script>
          </body>
        </html>
      `;

      logger.debug('Sending login success response');
      res.send(popupCloseHtml);
    });
  })(req, res, next);
});

/**
 * 4) /auth/logout
 * Logs user out locally and triggers front-channel Keycloak logout
 */
authRoutes.get('/auth/logout', (req: Request, res: any, next: NextFunction) => {
  try {
    if (!req.isAuthenticated || !req.isAuthenticated()) {
      return res.send(renderLogoutSnippet('NOT_LOGGED_IN'));
    }

    const user: any = req.user || {};
    const idToken = user?.tokens?.idToken;
    if (!idToken) {
      logger.warn('No id_token in session; skipping Keycloak SSO logout');
      return endLocalSession(req, res, 'NO_ID_TOKEN');
    }

    const logoutUrl = `${KEYCLOAK_AUTH_SERVER_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/logout`
      + `?id_token_hint=${idToken}`
      + `&post_logout_redirect_uri=${BFF_LOGOUT_CALLBACK_URL}`;

    res.send(`
      <html>
        <body>
          <script>
            window.location.href = '${logoutUrl}';
          </script>
        </body>
      </html>
    `);
  } catch (err: any) {
    logger.error('Logout route error:', { error: err });
    return next(err);
  }
});

/**
 * 5) /auth/logout/callback
 * Keycloak calls this route back after front-channel logout
 */
authRoutes.get('/auth/logout/callback', (req: Request, res: Response) => {
  endLocalSession(req, res, 'KEYCLOAK_LOGOUT_DONE');
});

/**
 * Helper function to end local session
 */
function endLocalSession(req: Request, res: Response, _reason: string) {
  req.logout((err: any) => {
    if (err) {
      logger.error('Error during logout:', { error: err });
      return res.send(renderLogoutSnippet('LOGOUT_ERROR'));
    }
    req.session.destroy((destroyErr: any) => {
      if (destroyErr) {
        logger.error('Error destroying session:', { error: destroyErr });
        return res.send(renderLogoutSnippet('LOGOUT_ERROR'));
      }
      res.clearCookie('angular-session');
      return res.send(renderLogoutSnippet('LOGOUT_SUCCESS'));
    });
  });
}

/**
 * Builds a small snippet of HTML/JS that signals logout to parent window
 */
function renderLogoutSnippet(msgType: string): string {
  return `
    <html>
      <body>
        <script>
          window.opener.postMessage({ type: 'LOGOUT_SUCCESS', reason: '${msgType}' }, '*');
          window.close();
        </script>
      </body>
    </html>
  `;
}
