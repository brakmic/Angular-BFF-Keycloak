/**
 * redis-session.ts
 *
 * Provides a Redis-based session store and public API for session management.
 * Exports:
 *   - createRedisStore(): Initializes and returns a RedisStore for express-session.
 *   - listActiveSessions(): Returns all active session keys.
 *   - invalidateSession(sessionId): Deletes a session from Redis.
 *   - refreshSession(sessionId, newTTL): Refreshes a session’s TTL.
 *
 * Requirements:
 *   - A running Redis instance.
 *   - Dependencies: ioredis and connect-redis.
 * 
 * @module session/redis-session
 */
import { RedisStore } from 'connect-redis';
import Redis from 'ioredis';
import { logger } from '../logger';
import { SessionData } from 'express-session';

let redisClient: Redis;

function getRedisClient() {

  try {
    redisClient = new Redis({
      host: process.env.REDIS_HOST || '127.0.0.1',
      port: Number(process.env.REDIS_PORT || 6379),
      password: process.env.REDIS_PASSWORD || undefined,
    });

    redisClient.on('ready', () => {
      logger.info('Redis client ready');
    });
    
    redisClient.on('connect', () => {
      logger.info('Redis client connected');
    });
    
    redisClient.on('error', (err) => {
      logger.error('Redis client error:', err);
    });
    
    redisClient.on('end', () => {
      logger.warn('Redis client connection ended');
    });
    return redisClient;
  } catch (error) {
    logger.error('Error initializing Redis client:', error);
    throw error;
  }
}

// Create a custom store class that extends RedisStore
class DebugRedisStore extends RedisStore {
  constructor(opts: any) {
    super(opts);
    
    // Wrap the original get method with proper types
    const originalGet = this.get.bind(this);
    this.get = (sid: string, cb: (err: any, session?: SessionData | null) => void): Promise<void> => {
      return new Promise((resolve) => {
        logger.debug('Redis GET operation:', { sid });
        originalGet(sid, (err: any, session: SessionData | null) => {
          if (err) {
            logger.error('Redis GET error:', { sid, error: err });
            cb(err, null);
          } else {
            logger.debug('Redis GET result:', { 
              sid, 
              hasData: !!session,
              sessionData: session
            });
            cb(null, session);
          }
          resolve();
        });
      });
    };

    // Wrap the original set method with proper types
    const originalSet = this.set.bind(this);
    this.set = (sid: string, session: SessionData, cb?: (err?: any) => void): Promise<void> => {
      return new Promise((resolve) => {
        logger.debug('Redis SET operation:', { 
          sid,
          sessionData: session
        });
        originalSet(sid, session, (err?: any) => {
          if (err) {
            logger.error('Redis SET error:', { sid, error: err });
            cb?.(err);
          } else {
            logger.debug('Redis SET success:', { sid });
            cb?.();
          }
          resolve();
        });
      });
    };
  }
}

export function createRedisStore() {
  const store = new RedisStore({
    client: getRedisClient(),
    prefix: 'myapp:',
    ttl: 15 * 60,
    disableTouch: false,
    serializer: JSON
  });

  store.on('error', (error) => {
    logger.error('Redis store error:', error);
  });

  store.on('connect', () => {
    logger.info('Redis store connected');
  });

  return store;
}

/**
 * Lists active session keys (using the specified key prefix "myapp").
 */
export async function listActiveSessions(): Promise<string[]> {
  try {
    const keys = await redisClient.keys('myapp:*');
    return keys;
  } catch (error) {
    logger.error('Error listing active sessions:', error);
    throw error;
  }
}

/**
 * Invalidate an active session by session ID.
 */
export async function invalidateSession(sessionId: string): Promise<void> {
  try {
    await redisClient.del(`myapp:${sessionId}`);
  } catch (error) {
    logger.error('Error invalidating session:', error);
    throw error;
  }
}

/**
 * Refreshes a session’s TTL (in seconds).
 */
export async function refreshSession(sessionId: string, newTTL: number): Promise<void> {
  try {
    await redisClient.expire(`myapp:${sessionId}`, newTTL);
  } catch (error) {
    logger.error('Error refreshing session:', error);
    throw error;
  }
}
