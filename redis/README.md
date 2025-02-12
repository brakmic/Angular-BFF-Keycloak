# Redis Session Store

This project provides a Redis server and Redis Commander UI for session management in the BFF (Backend-for-Frontend) application.

## Overview

Redis is used as a session store for the Express.js backend, providing:
- Persistent session storage across server restarts
- Session monitoring via Redis Commander
- Configurable session TTL (Time To Live)
- Debug logging for session operations

## Quick Start

1. Start Redis and Redis Commander:
```bash
docker compose up -d
```

2. Access Redis Commander UI:
- URL: http://localhost:8081
- Connection details:
  - Host: redis_server
  - Port: 6379
  - Password: changeit

## Configuration

### Enabling Redis Session Store

To use Redis for session storage, update your backend's `.env` file:

```ini
# Session store can be "redis" or "in-memory"
SESSION_STORE=redis

# Redis Configuration
REDIS_HOST=redis_server
REDIS_PORT=6379
REDIS_PASSWORD=changeit
```

## Session Management Features

The Redis session store implementation (`redis-session.ts`) provides:

1. **Session Storage**
   - Prefix: 'myapp:'
   - Default TTL: 15 minutes
   - Automatic session serialization/deserialization

2. **Debug Logging**
   - Session GET/SET operations
   - Connection status
   - Error reporting

3. **Session Management API**
   ```typescript
   // List all active sessions
   listActiveSessions(): Promise<string[]>
   
   // Invalidate a specific session
   invalidateSession(sessionId: string): Promise<void>
   
   // Refresh session TTL
   refreshSession(sessionId: string, newTTL: number): Promise<void>
   ```

## Security Considerations

1. Redis server is password protected
2. Network access is restricted to the devnetwork
3. Session data is stored with a unique prefix
4. Sessions expire after 15 minutes of inactivity

## Troubleshooting

1. **Connection Issues**
   ```bash
   # Test Redis connectivity
   redis-cli -h redis_server -a changeit ping
   ```

2. **Session Monitor**
   - Use Redis Commander to inspect active sessions
   - Filter by prefix: 'myapp:'
   - View session content and TTL

3. **Common Issues**
   - If sessions aren't persisting, verify SESSION_STORE=redis in .env
   - If Redis Commander can't connect, check the REDIS_HOSTS environment variable
   - For connection refused errors, ensure redis_server is running and on the correct network

## Development Notes

- The Redis store automatically handles session serialization
- Session data is logged in debug mode for development
- Redis persistence is enabled (appendonly yes)
- Sessions are automatically cleared on expiration
