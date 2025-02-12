/**
 * auth-routes.ts
 * Defines the routes for Keycloak-based authentication:
 *  - /auth/keycloak-init
 *  - /auth/keycloak
 *  - /auth/keycloak/callback
 *  - /auth/logout
 *  - /auth/logout/callback
 * Exports: authRoutes (function returning an Express.Router)
 * 
 * @module routes/auth-routes
 */

import { Router, Request, Response, NextFunction } from 'express';
import passport from 'passport';
import { logger } from '../logger';

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
 * Jst redirecting to /auth/keycloak to let OAuth2Strategy handle PKCE automatically.
 */
authRoutes.get('/auth/keycloak-init', (req: Request, res: Response) => {
  // Save session first
  (req as any).session.save((err) => {
    if (err) {
      logger.error('Session save error:', err);
      return res.status(500).send('Session save error');
    }

    // Use HTML/JS redirect instead of res.redirect
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
 * Passport.js Authentication with KeycloakStrategy
 */
authRoutes.get('/auth/keycloak', (req: Request, res: any, next: NextFunction) => {
  logger.debug('[/auth/keycloak] Request details:', {
    url: req.url,
    method: req.method,
    headers: req.headers,
    cookies: req.headers.cookie || 'missing',
    sessionID: req.sessionID,
  });

  passport.authenticate('keycloak', { 
    scope: ['openid', 'profile', 'email']
  })(req, res, (err: any) => {
    if (err) {
      logger.error('[/auth/keycloak] Error during passport.authenticate:', { error: err });
      return next(err);
    }
    const locationHeader = res.getHeader('Location');
    logger.info(`[/auth/keycloak] Outbound 302 to Keycloak => ${locationHeader}`);
  });
});

/**
 * 3) /auth/keycloak/callback
 * Keycloak redirects here after successful or failed auth.
 */
authRoutes.get('/auth/keycloak/callback', (req: Request, res: Response, next: NextFunction) => {

  logger.debug('[/auth/keycloak/callback] Request details:', {
    url: req.url,
    method: req.method,
    query: req.query,
    headers: req.headers,
    cookies: req.headers.cookie || 'missing',
    sessionID: req.sessionID,
  });

  passport.authenticate('keycloak', (err: any, user: any, info: any) => {
    logger.debug('[/auth/keycloak/callback] Passport authentication result:', {
      error: err ? '*** exists ***' : 'none',
      user: user ? '*** exists ***' : 'missing',
      info: info ? '*** exists ***' : 'none',
    });

    if (err) {
      logger.error('[/auth/keycloak/callback] Authentication pipeline error:', {
        error: err instanceof Error ? err.message : 'Unknown error',
        sessionID: (req as any).sessionID,
        queryState: req.query.state ? '*** exists ***' : 'missing',
      });
      return res.status(500).send('Internal Server Error');
    }

    if (!user) {
      logger.warn('[/auth/keycloak/callback] Authentication failed:', {
        info: info,
        sessionState: (req as any).session?.oauthState ? '*** exists ***' : 'missing',
      });
      return res.redirect('/login');
    }

    req.logIn(user, (err) => {
      if (err) {
        logger.error('[/auth/keycloak/callback] Session login error:', {
          error: err instanceof Error ? err.message : 'Unknown error',
          userId: user.id,
        });
        return res.status(500).send('Login Error');
      }

      logger.info('[/auth/keycloak/callback] User authenticated successfully:', {
        userId: user.id,
        sessionID: (req as any).sessionID,
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

      logger.debug('[/auth/keycloak/callback] Sending login success response:', {
        headers: {
          'set-cookie': res.getHeader('set-cookie') ? '*** exists ***' : 'missing',
        },
      });

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
    (req as any).session.destroy((destroyErr: any) => {
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
