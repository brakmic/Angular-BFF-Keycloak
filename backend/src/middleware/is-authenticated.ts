/**
 * is-authenticated.ts
 * Provides middleware to check if a user is authenticated.
 * Exports: isAuthenticated
 * 
 * @module middleware/is-authenticated
 */

import { Request, Response, NextFunction } from 'express';

export function isAuthenticated(req: Request, res: Response, next: NextFunction) {
  if (req.isAuthenticated && req.isAuthenticated()) {
    return next();
  }
  res.status(401).send('Unauthorized');
}
