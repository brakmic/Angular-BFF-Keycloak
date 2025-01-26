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
 * Extend express-session to include 
 * PKCE properties.
 */
declare module 'express-session' {
  interface SessionData {
    code_verifier?: string;
    oauthState?: string;
    user?: any;
  }
}

/**
 * Keycloak Profile
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
  PORT: PORT_ENV,
  SESSION_SECRET,
  CLIENT_SECRET,
  KEYCLOAK_REALM,
  KEYCLOAK_AUTH_SERVER_URL,
  KEYCLOAK_CLIENT_ID,
  KEYCLOAK_CALLBACK_URL,
} = process.env as {
  PORT?: string;
  SESSION_SECRET: string;
  CLIENT_SECRET: string;
  KEYCLOAK_REALM: string;
  KEYCLOAK_AUTH_SERVER_URL: string;
  KEYCLOAK_CLIENT_ID: string;
  KEYCLOAK_CALLBACK_URL: string;
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
const PORT: number = parseInt(PORT_ENV || '3000', 10);

// Initialize Express app
const app = express();

// Integrate morgan with winston for HTTP request logging
app.use(morgan('combined', { stream }));

// CORS Configuration
app.use(
  cors({
    origin: 'https://localhost:4200', // Angular app origin
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
    saveUninitialized: false,
    cookie: {
      secure: true, // for HTTPS
      httpOnly: true,
      sameSite: 'lax', // 'lax' is sufficient for redirects
    },
  })
);

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

// Determine client type and PKCE usage
const isPublicClient = true;
const usePkce = isPublicClient; // Enable PKCE for public clients
const useState = usePkce; // Enable state for PKCE

// Client Secret (always empty for public clients)
const clientSecret = CLIENT_SECRET;

// Configure Keycloak Strategy
passport.use(
  new KeycloakStrategy(
    {
      realm: KEYCLOAK_REALM,
      authServerURL: KEYCLOAK_AUTH_SERVER_URL,
      clientID: KEYCLOAK_CLIENT_ID,
      callbackURL: KEYCLOAK_CALLBACK_URL,
      publicClient: isPublicClient,
      sslRequired: 'all', // Adjust based on your Keycloak setup
      clientSecret: clientSecret,
      scope: 'openid profile email',
      state: useState,
      pkce: usePkce,
    },
    (req: Request, accessToken: string, refreshToken: string, profile: Profile, done: Function) => {
      // `profile` now has the normal user info (id, displayName, emails, etc.)
      // plus `profile._id_token` if the token endpoint returned it.
      
      // DEBUG:
      // logger.info('Authenticated user profile:', { profile });
      // Alternative handling when no id_token is needed
      // return done(null, profile);

      // Get id_token
      const idToken = (profile && profile._id_token) || null; 
      // Then store everything on the user object in backend's session:
      const user = {
        ...profile,
        tokens: {
          accessToken,
          refreshToken,
          idToken
        }
      };
      return done(null, user);
    }
  )
);

/************************
 * Authentication Routes
 ************************/

/**
 * Initiates authentication with Keycloak, handling PKCE.
 */
app.get(
  '/auth/keycloak',
  (req: Request, res: Response, next: NextFunction) => {
    let code_verifier: string | null = null;
    let code_challenge: string | null = null;

    if (usePkce) {
      code_verifier = generateCodeVerifier();
      code_challenge = generateCodeChallenge(code_verifier);
      req.session.code_verifier = code_verifier;
      logger.debug('Generated code_verifier and stored in session:', { code_verifier });
    }

    // Log session before saving
    logger.debug('Session before save:', { session: req.session });

    // Save the session before redirecting
    req.session.save((err) => {
      if (err) {
        logger.error('Session save error:', { error: err });
        return next(err);
      }

      logger.debug('Session saved successfully:', { session: req.session });
      logger.info('Initiating authentication with Keycloak...');

      passport.authenticate('keycloak', {
        scope: ['openid', 'profile', 'email'],
        ...(usePkce && {
          code_challenge: code_challenge,
          code_challenge_method: 'S256',
        }),
      })(req, res, next);
    });
  }
);

/**
 * Handles the callback from Keycloak after authentication.
 * Uses a custom callback to ensure session is established.
 */
app.get(
  '/auth/keycloak/callback',
  (req: Request, res: Response, next: NextFunction) => {
    logger.info('Handling Keycloak callback...');
    logger.debug('Session at callback start:', { session: req.session });

    passport.authenticate('keycloak', (err: any, user: any, info: any) => {
      if (err) {
        logger.error('Authentication Error:', { error: err });
        return res.status(500).send('Internal Server Error during authentication.');
      }

      if (!user) {
        logger.warn('Authentication Failed:', { info });
        return res.redirect('/login');
      }

      req.logIn(user, (err) => {
        if (err) {
          logger.error('Login Error:', { error: err });
          return res.status(500).send('Internal Server Error during login.');
        }
        logger.info('User successfully authenticated:', { user });
        logger.debug('Session after login:', { session: req.session });
        // return a small HTML snippet that triggers "LOGIN_SUCCESS" in the parent
       const popupCloseHtml = `
         <html>
           <body>
             <script>
               // Notify the parent window that login succeeded
               window.opener.postMessage({ type: 'LOGIN_SUCCESS' }, '*');
               // Close this popup
               window.close();
             </script>
           </body>
         </html>
       `;
       res.send(popupCloseHtml);
      });
    })(req, res, next);
  }
);

app.get('/auth/logout', (req: Request, res: any, next: NextFunction) => {
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
      + `&post_logout_redirect_uri=https://localhost:3000/auth/logout/callback`;

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
      logger.error('Error during logout:', { error: err });
      return res.send(renderLogoutSnippet('LOGOUT_ERROR'));
    }
    req.session.destroy(() => {
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
app.get('/api/user-details', isAuthenticated, (req, res) => {
  res.json({
    user: req.user,
    ...MockDataService.getUserDetails()
  });
});

// faker.js data
app.get('/api/transactions', isAuthenticated, (req, res) => {
  res.json({
    transactions: MockDataService.getTransactions()
  });
});

// faker.js data
app.get('/api/products', isAuthenticated, (req, res) => {
  res.json({
    products: MockDataService.getProducts(6)
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

// Paths to the HTTPS certificates
const BACKEND_CERT = path.join(__dirname, '../certs/backend.cert.pem');
const BACKEND_KEY = path.join(__dirname, '../certs/backend.key.pem');

// Read the certificates
const httpsOptions = {
  key: fs.readFileSync(BACKEND_KEY),
  cert: fs.readFileSync(BACKEND_CERT),
};

// Start the HTTPS server
https.createServer(httpsOptions, app).listen(PORT, () => {
  logger.info(`Express.js HTTPS server running on https://localhost:${PORT}`);
  logger.info(`Open https://localhost:${PORT}/auth/keycloak to initiate login`);
});

// Optionally, redirect HTTP to HTTPS
// const httpApp = express();
// httpApp.use((req: Request, res: Response) => {
//   res.redirect(`https://${req.headers.host}${req.url}`);
// });

// httpApp.listen(80, () => {
//   logger.info('HTTP server running on port 80 and redirecting to HTTPS');
// });


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
