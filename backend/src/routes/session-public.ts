/**
 * session-public.ts
 *
 * Defines public (and managing) endpoints for session management using Redis.
 * Exports:
 *   - sessionPublicRoutes (an Express.Router instance)
 *
 * Endpoints include:
 *   - GET /api/sessions            : List active sessions.
 *   - DELETE /api/sessions/:sessionId : Invalidate a session.
 *   - POST /api/sessions/:sessionId/refresh : Refresh a session’s TTL.
 * 
 @module routes/session-public
 */

import { Router, Request, Response } from 'express';
import { listActiveSessions, invalidateSession, refreshSession } from '../session/redis-session';

const router = Router();

router.get('/api/sessions', async (req: Request, res: Response) => {
  try {
    const sessions = await listActiveSessions();
    res.json({ sessions });
  } catch (error) {
    res.status(500).json({ error: 'Failed to list sessions' });
  }
});

router.delete('/api/sessions/:sessionId', async (req: Request, res: Response) => {
  const { sessionId } = req.params;
  try {
    await invalidateSession(sessionId);
    res.json({ message: `Session ${sessionId} invalidated.` });
  } catch (error) {
    res.status(500).json({ error: 'Failed to invalidate session' });
  }
});

router.post('/api/sessions/:sessionId/refresh', async (req: Request, res: any) => {
  const { sessionId } = req.params;
  const { newTTL } = req.body;
  if (!newTTL || typeof newTTL !== 'number') {
    return res.status(400).json({ error: 'Invalid TTL value' });
  }
  try {
    await refreshSession(sessionId, newTTL);
    res.json({ message: `Session ${sessionId} refreshed for ${newTTL} seconds.` });
  } catch (error) {
    res.status(500).json({ error: 'Failed to refresh session' });
  }
});

export default router;
