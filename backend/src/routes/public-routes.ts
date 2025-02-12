/**
 * public-routes.ts
 * Defines routes that do not require authentication.
 * Exports: publicRoutes (function returning an Express.Router)
 * 
 * @module routes/public-routes
 */

import { Router, Request, Response } from 'express';
import { logger } from '../logger';

export const publicRoutes: Router = Router();

// Home route
publicRoutes.get('/', (_req: Request, res: Response) => {
  res.send('Welcome to the Express.js Backend!');
});

// Failure route
publicRoutes.get('/login', (_req: Request, res: Response) => {
  logger.warn('Authentication failed');
  res.status(401).send('Authentication Failed. Please try again.');
});

// Debug session data
publicRoutes.get('/debug-session', async (req: Request, res: Response) => {
  const sessionID = req.sessionID;
  const sessionData = req.session;
  const isAuthenticated = req.isAuthenticated();
  
  // Get raw session from Redis
  const rawSession = await new Promise((resolve) => {
    (req.sessionStore as any).get(sessionID, (err: any, session: any) => {
      if (err) {
        logger.error('Error getting session from store:', err);
        resolve(null);
      }
      resolve(session);
    });
  });

  res.json({
    sessionID,
    sessionData,
    isAuthenticated,
    rawSession,
    cookies: req.cookies,
    signedCookies: req.signedCookies
  });
});

// Test echo route
publicRoutes.get('/test-echo', (req: Request, res: Response) => {
  res.json({
    urlReceived: req.url,
    query: req.query,
  });
});
