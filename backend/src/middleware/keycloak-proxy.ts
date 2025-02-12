import { Request, Response, NextFunction } from 'express';
import { logger } from '../logger';

export function keycloakProxyMiddleware(req: Request, res: Response, next: NextFunction) {
  if (req.url.includes('/auth/keycloak')) {
    logger.debug('Keycloak request:', {
      url: req.url,
      headers: {
        origin: req.headers.origin,
        cookie: req.headers.cookie,
        referer: req.headers.referer
      }
    });
  }
  next();
}
