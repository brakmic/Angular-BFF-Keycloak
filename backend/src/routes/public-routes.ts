/**
 * public-routes.ts
 * Defines routes that do not require authentication.
 * Exports: publicRoutes (function returning an Express.Router)
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
publicRoutes.get('/debug-session', (req: Request, res: Response) => {
  res.json(req.session);
});

// Test echo route
publicRoutes.get('/test-echo', (req: Request, res: Response) => {
  res.json({
    urlReceived: req.url,
    query: req.query,
  });
});
