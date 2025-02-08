/**
 * app.ts
 * Configures the Express application:
 *  - Logging (Morgan + Winston)
 *  - CORS
 *  - Session and Passport
 *  - Routes
 * Exports the configured Express app.
 */

import express, { Express } from 'express';
import { Request, Response, NextFunction } from 'express';
import morgan from 'morgan';
import cors from 'cors';
import session from 'express-session';
import passport from 'passport';
import { logger, stream } from './logger';
import { SESSION_DOMAIN, COOKIE_ORIGIN, SESSION_SECRET, NODE_ENV } from './config/env';

// Import and register the Keycloak strategy
import './auth/keycloak-strategy';

import { isAuthenticated } from './middleware/is-authenticated';
import { authRoutes } from './routes/auth-routes';
import { protectedRoutes } from './routes/protected-routes';
import { publicRoutes } from './routes/public-routes';

export function createApp(): Express {
  const app = express();
  const isProduction = NODE_ENV === 'production';

  app.set('trust proxy', true);

  app.use(morgan('combined', { stream }));
  app.use(
    cors({
      origin: COOKIE_ORIGIN,
      methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
      allowedHeaders: ['Content-Type', 'Authorization'],
      credentials: true,
    })
  );

  app.use(
    session({
      name: 'angular-session',
      secret: SESSION_SECRET as unknown as string,
      resave: false,
      saveUninitialized: true,
      rolling: true,
      cookie: {
        secure: isProduction,
        httpOnly: true,
        sameSite: isProduction ? 'none' : 'lax',
        domain: SESSION_DOMAIN,
        path: '/',
        maxAge: 15 * 60 * 1000,
      },
    })
  );

  app.use((req: Request, _res: Response, next: NextFunction) => {
    logger.debug(`Session ID: ${req.sessionID}`, { route: req.path });
    next();
  });

  app.use(passport.initialize());
  app.use(passport.session());

  app.use(authRoutes);
  app.use(protectedRoutes(isAuthenticated));
  app.use(publicRoutes);

  app.use((err: any, _req: Request, res: Response, _next: NextFunction) => {
    logger.error('Unhandled Error:', { error: err });
    res.status(500).send('Internal Server Error');
  });

  return app;
}
