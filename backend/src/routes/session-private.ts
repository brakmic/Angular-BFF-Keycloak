/**
 * session-private.ts
 *
 * Defines private (internal) endpoints for session management.
 * Exports:
 *   - sessionPrivateRoutes (an Express.Router instance)
 *
 * Endpoints include:
 *   - GET /internal/sessions            : List active sessions.
 *   - DELETE /internal/sessions/:sessionId : Invalidate a session.
 *
 * These endpoints are not exposed publicly and are intended for administrative purposes.
 * 
 @module routes/session-private
 */

import { Router, Request, Response } from 'express';
import { listActiveSessions, invalidateSession } from '../session/redis-session';

const router = Router();

router.get('/sessions', async (req: Request, res: Response) => {
  try {
    const sessions = await listActiveSessions();
    res.json({ sessions });
  } catch (error) {
    res.status(500).json({ error: 'Failed to list sessions' });
  }
});

router.delete('/sessions/:sessionId', async (req: Request, res: Response) => {
  const { sessionId } = req.params;
  try {
    await invalidateSession(sessionId);
    res.json({ message: `Session ${sessionId} invalidated.` });
  } catch (error) {
    res.status(500).json({ error: 'Failed to invalidate session' });
  }
});

export default router;
