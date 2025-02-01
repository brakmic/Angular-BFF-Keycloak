import express, { Request, Response, NextFunction } from 'express';
import session from 'express-session';
import passport from 'passport';
import KeycloakStrategy from 'passport-keycloak-oauth2-oidc-portable';
import cors from 'cors';
import dotenv from 'dotenv-safe';
import crypto from 'crypto';
import path from 'path';
import { logger, stream } from './logger';
import morgan from 'morgan';
import https from 'https';
import fs from 'fs';
import { MockDataService } from './services/mock-data.service';

// Load environment variables
dotenv.config({
  path: path.join(__dirname, '../.env'),
  example: path.join(__dirname, '../.env.example'),
  allowEmptyValues: true,
});

/**
 * Extend express-session to include PKCE properties.
 */
declare module 'express-session' {
  interface SessionData {
    code_verifier?: string;
    code_challenge?: string;
    oauthState?: string;
    user?: any;
    initTimestamp?: number;
  }
}

declare module 'passport' {
  interface AuthenticateOptions {
    scope?: string | string[];
    code_challenge?: string;
    code_challenge_method?: string;
    state?: string;
  }
}

/**
 * Keycloak Profile Interface
 */
interface Profile {
  provider: string;
  id: string;
  displayName?: string;
  username?: string;
  emails?: { value: string }[];
  _raw?: string;
  _json?: any;
  _id_token?: string | null;
}

// Extract environment variables
const {
  PORT,
  SESSION_SECRET,
  CLIENT_SECRET,
  BFF_LOGOUT_CALLBACK_URL,
  KEYCLOAK_REALM,
  KEYCLOAK_AUTH_SERVER_URL,
  KEYCLOAK_CLIENT_ID,
  KEYCLOAK_CALLBACK_URL,
  COOKIE_ORIGIN,
  SESSION_DOMAIN,
  NODE_ENV,
} = process.env as {
  PORT?: string;
  SESSION_SECRET: string;
  CLIENT_SECRET: string;
  BFF_LOGOUT_CALLBACK_URL: string;
  KEYCLOAK_REALM: string;
  KEYCLOAK_AUTH_SERVER_URL: string;
  KEYCLOAK_CLIENT_ID: string;
  KEYCLOAK_CALLBACK_URL: string;
  COOKIE_ORIGIN: string;
  SESSION_DOMAIN: string;
  NODE_ENV?: string;
};

// Runtime Checks
if (!SESSION_SECRET) {
  logger.error('Error: SESSION_SECRET is not defined in the environment variables.');
  process.exit(1);
}

if (!KEYCLOAK_REALM) {
  logger.error('Error: KEYCLOAK_REALM is not defined in the environment variables.');
  process.exit(1);
}

if (!KEYCLOAK_AUTH_SERVER_URL) {
  logger.error('Error: KEYCLOAK_AUTH_SERVER_URL is not defined in the environment variables.');
  process.exit(1);
}

if (!KEYCLOAK_CLIENT_ID) {
  logger.error('Error: KEYCLOAK_CLIENT_ID is not defined in the environment variables.');
  process.exit(1);
}

if (!KEYCLOAK_CALLBACK_URL) {
  logger.error('Error: KEYCLOAK_CALLBACK_URL is not defined in the environment variables.');
  process.exit(1);
}

// Convert PORT to number
const SERVER_PORT: number = parseInt(PORT || '3000', 10);

// Determine if the environment is production
const isProduction = NODE_ENV === 'production';

// Initialize Express app
const app = express();

app.set('trust proxy', true);

// Integrate morgan with winston for HTTP request logging
app.use(morgan('combined', { stream }));

// CORS Configuration
app.use(
  cors({
    origin: COOKIE_ORIGIN, // Angular app origin
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true, // Allow cookies to be sent
  })
);

// Session Configuration
app.use(
  session({
    name: 'angular-session',
    secret: SESSION_SECRET!,
    resave: false,
    saveUninitialized: true, // Ensures session is saved even if not modified
    rolling: true,
    cookie: {
      secure: isProduction, // true in production, false otherwise
      httpOnly: true,
      sameSite: isProduction ? 'none' : 'lax', // 'none' in production, 'lax' otherwise
      domain: SESSION_DOMAIN, // So it works across bff.testapps.io / myapp.testapps.io
      path: '/',
      maxAge: 15 * 60 * 1000, // 15 minutes
    },
  })
);

// Middleware to log session ID and route
app.use((req: Request, res: Response, next: NextFunction) => {
  logger.debug(`Session ID: ${req.sessionID}`, { route: req.path });
  next();
});

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// Passport Serialization
passport.serializeUser((user: any, done) => {
  done(null, user);
});

passport.deserializeUser((obj: any, done) => {
  done(null, obj);
});

// Configure Keycloak Strategy
passport.use(
  new KeycloakStrategy(
    {
      realm: KEYCLOAK_REALM,
      authServerURL: KEYCLOAK_AUTH_SERVER_URL,
      clientID: KEYCLOAK_CLIENT_ID,
      callbackURL: KEYCLOAK_CALLBACK_URL,
      publicClient: true, // Set to false if using confidential clients
      sslRequired: 'all',
      clientSecret: CLIENT_SECRET,
      scope: 'openid profile email',
      state: true,
      pkce: true,
    },
    (req: Request, accessToken: string, refreshToken: string, profile: Profile, done: Function) => {
      try {
        const idToken = profile._id_token || null;
        const user = {
          ...profile,
          tokens: { accessToken, refreshToken, idToken },
        };
        logger.debug('Keycloak strategy verification success:', {
          userId: user.id,
          hasTokens: !!accessToken,
        });
        return done(null, user);
      } catch (error) {
        logger.error('Keycloak strategy verification error:', {
          error: error instanceof Error ? error.message : 'Unknown error',
          profile: profile ? '*** exists ***' : 'missing',
        });
        return done(error);
      }
    }
  )
);

/**
 * 1) This route is called first (in the popup).
 *    - We make sure the session is created and the cookie is set
 *    - Then we do a client-side redirect to the real /auth/keycloak route
 */
app.get('/auth/keycloak-init', (req: Request, res: Response) => {
  // Generate PKCE parameters
  const code_verifier = generateCodeVerifier();
  const code_challenge = generateCodeChallenge(code_verifier);

  req.session.code_verifier = code_verifier;
  req.session.code_challenge = code_challenge;

  logger.debug('Initializing authentication session and setting PKCE parameters:', {
    sessionID: req.sessionID,
    initTimestamp: req.session.initTimestamp,
    code_verifier: '*** exists ***',
    code_challenge: '*** exists ***',
  });

  // Save the session explicitly
  req.session.save((err) => {
    if (err) {
      logger.error('Could not save session in /auth/keycloak-init:', { error: err });
      return res.status(500).send('Session save error');
    }

    logger.debug('Session saved successfully in /auth/keycloak-init:', {
      sessionID: req.sessionID,
    });

    // Return a simple HTML page that does a JavaScript redirect to /auth/keycloak
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

app.get('/auth/keycloak', (req: Request, res: any, next: NextFunction) => {
  logger.debug('Initiating passport.authenticate in /auth/keycloak:', {
    sessionID: req.sessionID,
    state: req.session.oauthState ? '*** exists ***' : 'missing',
    code_challenge: req.session.code_challenge ? '*** exists ***' : 'missing',
  });

  if (!req.session.code_challenge) {
    logger.error('Missing code_challenge in session:', {
      code_challenge: req.session.code_challenge ? '*** exists ***' : 'missing',
    });
    return res.status(400).send('Invalid authentication request.');
  }

  passport.authenticate('keycloak', {
    scope: ['openid', 'profile', 'email'],
    // Removed 'code_challenge' and 'state' from here
  })(req, res, (err: any) => {
    if (err) {
      logger.error('Error during passport.authenticate:', { error: err });
    }
    const locationHeader = res.getHeader('Location');
    logger.info(`Outbound 302 to Keycloak => ${locationHeader}`);
    next(err);
  });
});

app.get('/auth/keycloak/callback', (req: Request, res: Response, next: NextFunction) => {
  logger.info('Keycloak callback received:', {
    queryParams: {
      state: req.query.state ? '*** exists ***' : 'missing',
      code: req.query.code ? '*** exists ***' : 'missing',
    },
    cookies: req.headers.cookie ? '*** exists ***' : 'missing',
    sessionID: req.sessionID,
  });

  passport.authenticate('keycloak', (err: any, user: any, info: any) => {
    logger.debug('Passport authentication result:', {
      error: err ? '*** exists ***' : 'none',
      user: user ? '*** exists ***' : 'missing',
      info: info ? '*** exists ***' : 'none',
    });

    if (err) {
      logger.error('Authentication pipeline error:', {
        error: err instanceof Error ? err.message : 'Unknown error',
        sessionID: req.sessionID,
        queryState: req.query.state ? '*** exists ***' : 'missing',
      });
      return res.status(500).send('Internal Server Error');
    }

    if (!user) {
      logger.warn('Authentication failed:', {
        info: info,
        sessionState: req.session.oauthState ? '*** exists ***' : 'missing',
        sessionCodeVerifier: req.session.code_verifier ? '*** exists ***' : 'missing',
      });
      return res.redirect('/login');
    }

    req.logIn(user, (err) => {
      if (err) {
        logger.error('Session login error:', {
          error: err instanceof Error ? err.message : 'Unknown error',
          userId: user.id,
        });
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

      logger.debug('Sending login success response:', {
        headers: {
          'set-cookie': res.getHeader('set-cookie') ? '*** exists ***' : 'missing',
        },
      });

      res.send(popupCloseHtml);
    });
  })(req, res, next);
});

app.get('/auth/logout', (req: Request, res: Response, next: Function) => {
  try {
    if (!req.isAuthenticated || !req.isAuthenticated()) {
      // If user not logged in, just close the popup
      return res.send(renderLogoutSnippet('NOT_LOGGED_IN'));
    }

    // Grab idToken from the user object
    const user: any = req.user || {};
    const idToken = user?.tokens?.idToken;
    if (!idToken) {
      logger.warn('No id_token in session; skipping Keycloak SSO logout. Ending local session only.');
      return endLocalSession(req, res, 'NO_ID_TOKEN');
    }

    // Build the Keycloak front-channel logout URL
    const logoutUrl = `${KEYCLOAK_AUTH_SERVER_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/logout`
      + `?id_token_hint=${idToken}`
      + `&post_logout_redirect_uri=${BFF_LOGOUT_CALLBACK_URL}`;

    // Return a snippet that sets window.location.href = logoutUrl in the popup
    res.send(`
      <html>
        <body>
          <script>
            window.location.href = '${logoutUrl}';
          </script>
        </body>
      </html>
    `);
  } catch (err) {
    logger.error('Logout route error:', { error: err });
    return next(err);
  }
});

/**
 * Keycloak calls us back after front-channel logout
 */
app.get('/auth/logout/callback', (req: Request, res: Response, next: NextFunction) => {
  endLocalSession(req, res, 'KEYCLOAK_LOGOUT_DONE');
});

function endLocalSession(req: Request, res: Response, reason: string) {
  req.logout((err) => {
    if (err) {
      logger.error('Error during logout:', {
        error: err instanceof Error ? err.message : 'Unknown error',
      });
      return res.send(renderLogoutSnippet('LOGOUT_ERROR'));
    }
    // Destroy the session
    req.session.destroy((err) => {
      if (err) {
        logger.error('Error destroying session:', { error: err });
        return res.send(renderLogoutSnippet('LOGOUT_ERROR'));
      }

      // Clear the session cookie
      res.clearCookie('angular-session');
      return res.send(renderLogoutSnippet('LOGOUT_SUCCESS'));
    });
  });
}

function renderLogoutSnippet(msgType: string): string {
  return `
    <html>
      <body>
        <script>
          // Notify the parent window that we are done
          window.opener.postMessage({ type: 'LOGOUT_SUCCESS', reason: '${msgType}' }, '*');
          window.close();
        </script>
      </body>
    </html>
  `;
}

/****************************
 * Protected Routes
 ****************************/

// from Keycloak
app.get('/api/profile', isAuthenticated, (req: Request, res: Response) => {
  res.json({
    user: req.user,
  });
});

// faker.js data
app.get('/api/user-details', isAuthenticated, (req: Request, res: Response) => {
  res.json({
    user: req.user,
    ...MockDataService.getUserDetails(),
  });
});

// faker.js data
app.get('/api/transactions', isAuthenticated, (req: Request, res: Response) => {
  res.json({
    transactions: MockDataService.getTransactions(),
  });
});

// faker.js data
app.get('/api/products', isAuthenticated, (req: Request, res: Response) => {
  res.json({
    products: MockDataService.getProducts(6),
  });
});

/****************
 * Public Routes
 ****************/
app.get('/', (_req: Request, res: Response) => {
  res.send('Welcome to the Express.js Backend!');
});

/**
 * Login Failure Route
 */
app.get('/login', (_req: Request, res: Response) => {
  logger.warn('Authentication failed');
  res.status(401).send('Authentication Failed. Please try again.');
});

/**
 * Debug Route to Inspect Session Data
 * Access via http://localhost:3000/debug-session
 */
app.get('/debug-session', (req: Request, res: Response) => {
  res.json(req.session);
});

app.get('/test-echo', (req, res) => {
  res.json({
    urlReceived: req.url, // raw URL as Node sees it
    query: req.query, // parsed query object
  });
});

/**
 * Middleware to Check Authentication
 */
function isAuthenticated(req: Request, res: Response, next: NextFunction) {
  if (req.isAuthenticated && req.isAuthenticated()) {
    return next();
  }
  res.status(401).send('Unauthorized');
}

/**
 * Global Error Handler
 */
app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
  logger.error('Unhandled Error:', { error: err });
  res.status(500).send('Internal Server Error');
});

// Start the HTTPS server for development (recommended)
const BACKEND_CERT = path.join(__dirname, '../certs/backend.cert.pem');
const BACKEND_KEY = path.join(__dirname, '../certs/backend.key.pem');

if (fs.existsSync(BACKEND_CERT) && fs.existsSync(BACKEND_KEY)) {
  const httpsOptions = {
    key: fs.readFileSync(BACKEND_KEY),
    cert: fs.readFileSync(BACKEND_CERT),
  };

  https.createServer(httpsOptions, app).listen(SERVER_PORT, () => {
    logger.info(`Express.js HTTPS server running on https://localhost:${SERVER_PORT}`);
    logger.info(`Open https://localhost:${SERVER_PORT}/auth/keycloak-init to initiate login`);
  });
} else {
  // Fallback to HTTP if certificates are not found (not recommended for production)
  app.listen(SERVER_PORT, () => {
    console.log(`BFF is listening on port ${SERVER_PORT}`);
  });
}

/****************************
 * Helper Functions for PKCE
 ****************************/

/**
 * Generates a random code verifier.
 * @param length - The length of the code verifier.
 * @returns A URL-safe base64-encoded string.
 */
function generateCodeVerifier(length: number = 128): string {
  const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
  let codeVerifier = '';
  for (let i = 0; i < length; i++) {
    codeVerifier += possible.charAt(Math.floor(Math.random() * possible.length));
  }
  return codeVerifier;
}

/**
 * Generates a code challenge from the code verifier using SHA-256.
 * @param codeVerifier - The code verifier string.
 * @returns A base64 URL-encoded SHA-256 hash of the code verifier.
 */
function generateCodeChallenge(codeVerifier: string): string {
  return base64URLEncode(sha256(codeVerifier));
}

/**
 * Helper function to perform SHA-256 hashing.
 * @param str - The input string.
 * @returns A Buffer containing the SHA-256 hash.
 */
function sha256(str: string): Buffer {
  return crypto.createHash('sha256').update(str).digest();
}

/**
 * Encodes a Buffer to a base64 URL-safe string.
 * @param buffer - The Buffer to encode.
 * @returns A base64 URL-safe string.
 */
function base64URLEncode(buffer: Buffer): string {
  return buffer
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}
