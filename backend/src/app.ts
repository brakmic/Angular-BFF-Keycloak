/**
 * app.ts
 *
 * Configures the Express application:
 *   - Logging (Morgan + Winston)
 *   - CORS
 *   - Sessions & Passport initialization
 *   - Routes
 *
 * Exports:
 *   - createApp(): Configured Express app.
 */

import { Express, Request, Response, NextFunction } from 'express';
import express from 'express';
import morgan from 'morgan';
import cors from 'cors';
import session from 'express-session';
import passport from 'passport';
import { logger, stream } from './logger';
import { 
  SESSION_DOMAIN, 
  COOKIE_ORIGIN, 
  SESSION_SECRET, 
  NODE_ENV, 
  SESSION_STORE 
} from './config/env';
import { initializeKeycloakStrategy } from './auth/keycloak-strategy';
import { isAuthenticated } from './middleware/is-authenticated';
import { keycloakProxyMiddleware } from './middleware/keycloak-proxy';
import { authRoutes } from './routes/auth-routes';
import { protectedRoutes } from './routes/protected-routes';
import { publicRoutes } from './routes/public-routes';
import sessionPublicRoutes from './routes/session-public';
import sessionPrivateRoutes from './routes/session-private';

let sessionStore: session.Store | undefined = undefined;

if (SESSION_STORE === 'redis') {
  const { createRedisStore } = await import('./session/redis-session');
  sessionStore = createRedisStore();
  logger.info('Using Redis session store.');
} else {
  logger.info('Using in-memory session store.');
}

export function createApp(): Express {
  const app = express();
  // Even in development override isProduction: we are running over HTTPS.
  const isProduction = NODE_ENV === 'production';

  // Basic middleware
  app.set('trust proxy', true);
  app.use(morgan('combined', { stream }));

  // 1. CORS configuration FIRST
  app.use(
    cors({
      origin: COOKIE_ORIGIN,
      credentials: true,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS'],
      allowedHeaders: [
        'Content-Type',
        'Authorization'
      ]
    })
  );

  // 2. Session configuration SECOND
  // Force secure cookies and sameSite:'none' so that cookies are sent in cross-site contexts.
  app.use(
    session({
      name: 'angular-session',
      store: sessionStore,
      secret: SESSION_SECRET!,
      resave: true,
      saveUninitialized: true,
      rolling: true,
      cookie: {
        secure: true,           // force HTTPS cookies (required by sameSite='none')
        httpOnly: true,
        sameSite: 'none',       // necessary for cross-site requests
        path: '/',
        maxAge: 15 * 60 * 1000,   // 15 minutes
        // If SESSION_DOMAIN is undefined then cookie defaults to current host
        domain: SESSION_DOMAIN || undefined,
      }
    })
  );

  // Debug middleware (after session config)
  app.use((req: Request, _res: Response, next: NextFunction) => {
    logger.debug('Request details:', {
      url: req.url,
      origin: req.get('origin'),
      referer: req.get('referer'),
      cookies: req.headers.cookie ? 'present' : 'missing',
      sessionID: req.sessionID
    });
    next();
  });

  // 3. Passport initialization THIRD
  app.use(passport.initialize());
  app.use(passport.session());

  // Serialize/deserialize
  passport.serializeUser((user: any, done: Function) => {
    logger.debug('Serializing user:', { userId: user.id });
    done(null, user);
  });
  
  passport.deserializeUser((obj: any, done: Function) => {
    logger.debug('Deserializing user:', { userId: obj.id });
    done(null, obj);
  });

  // 4. Initialize Keycloak strategy FOURTH
  try {
    initializeKeycloakStrategy();
    logger.info('Keycloak strategy initialized successfully');
  } catch (error) {
    logger.error('Failed to initialize Keycloak strategy:', { error });
    throw error;
  }

  // 5. Security headers FIFTH
  app.use((req, res, next) => {
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    next();
  });

  // Mount other middleware and routes
  app.use(keycloakProxyMiddleware);
  app.use(authRoutes);
  app.use(protectedRoutes(isAuthenticated));
  app.use(publicRoutes);
  app.use(sessionPublicRoutes);
  app.use('/internal', sessionPrivateRoutes);

  return app;
}
