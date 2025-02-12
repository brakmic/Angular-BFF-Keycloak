/**
 * protected-routes.ts
 * Defines routes that require an authenticated user.
 * Exports: protectedRoutes (function returning an Express.Router)
 * 
 * @module routes/protected-routes
 */

import { Router, Request, Response } from 'express';
import { MockDataService } from '../services/mock-data.service';

export function protectedRoutes(isAuthenticated: any): Router {
  const router = Router();

  // /api/profile
  router.get('/api/profile', isAuthenticated, (req: Request, res: Response) => {
    res.json({ user: req.user });
  });

  // /api/user-details
  router.get('/api/user-details', isAuthenticated, (req: Request, res: Response) => {
    res.json({
      user: req.user,
      ...MockDataService.getUserDetails(),
    });
  });

  // /api/transactions
  router.get('/api/transactions', isAuthenticated, (_req: Request, res: Response) => {
    res.json({
      transactions: MockDataService.getTransactions(),
    });
  });

  // /api/products
  router.get('/api/products', isAuthenticated, (_req: Request, res: Response) => {
    res.json({
      products: MockDataService.getProducts(6),
    });
  });

  return router;
}
