# Development Guide

## Project Structure

### Backend Architecture

| Directory | Purpose |
|-----------|---------|
| `routes/` | API endpoints and route handlers |
| `middleware/` | Custom middleware (auth, logging) |
| `auth/` | Authentication strategies and utils |
| `session/` | Session management and Redis store |
| `config/` | Environment and app configuration |
| `utils/` | Helper functions and utilities |
| `types/` | TypeScript type definitions |

### Key Files

```plaintext
backend/
├── src/
│   ├── app.ts                 # Application setup
│   ├── auth/
│   │   └── keycloak-strategy.ts
│   ├── routes/
│   │   ├── auth-routes.ts
│   │   └── protected-routes.ts
│   ├── session/
│   │   └── redis-session.ts
│   └── middleware/
│       └── is-authenticated.ts
└── .env                      # Environment configuration
```

## Environment Setup

### Prerequisites
- Node.js 18.x
- Docker 20.10+
- OpenSSL
- Git

### Environment Variables

```ini
# backend/.env
# Domain Configuration
SESSION_DOMAIN=.local.com
COOKIE_ORIGIN=https://frontend.local.com:4200

# Keycloak Settings
KEYCLOAK_REALM=TestRealm
KEYCLOAK_AUTH_SERVER_URL=https://keycloak:8443
KEYCLOAK_CLIENT_ID=angular-public-client
KEYCLOAK_CALLBACK_URL=https://backend.local.com:3000/auth/keycloak/callback

# Session Configuration
SESSION_STORE=redis
REDIS_HOST=redis_server
REDIS_PORT=6379
REDIS_PASSWORD=changeit
```

## Local Development

### Starting Services

```bash
# Start required services
cd keycloak && docker compose up -d
cd ../redis && docker compose up -d

# Start backend
cd ../backend
npm install
npm run dev

# Start frontend
cd ../frontend
npm install
npm start
```

### Hot Reloading
Both frontend and backend support hot reloading:
- Frontend: Angular CLI's built-in HMR
- Backend: Nodemon for automatic restart

### State Management

- Token handling by BFF
- Local session management
- Reactive authentication state

### Development URLs
- Frontend: https://frontend.local.com:4200
- Backend: https://backend.local.com:3000
- Keycloak: https://keycloak.local.com:8443
- Redis Commander: http://localhost:8081

## Testing

### Running Tests
```bash
# Backend tests
cd backend
npm test

# Frontend tests
cd frontend
npm test
```

### Debugging

1. **VS Code Launch Configurations**
   ```json
   {
     "type": "node",
     "request": "launch",
     "name": "Debug Backend",
     "program": "${workspaceFolder}/backend/src/index.ts",
     "preLaunchTask": "tsc: build - backend/tsconfig.json"
   }
   ```

2. **Browser Developer Tools**
   - Network tab for API calls
   - Application tab for cookies
   - Console for frontend logs

## Docker Development

### Container Management
```bash
# Build specific service
docker compose build backend

# Rebuild without cache
docker compose build --no-cache

# View logs
docker compose logs -f backend
```

### Workspace Variable
```bash
# Set workspace path
export HOST_WORKSPACE=/path/to/project

# Or create .env in project root
HOST_WORKSPACE=/path/to/project
```

## Best Practices

### Code Style
- Use TypeScript strict mode
- Follow Angular style guide
- Document public APIs
- Use meaningful commit messages

### Security
- Never commit secrets
- Use environment variables
- Keep dependencies updated
- Follow OWASP guidelines

### Performance
- Enable production mode in builds
- Optimize bundle sizes
- Use lazy loading
- Implement caching strategies

## VS Code Extensions

Recommended extensions for development:
- Docker
- ESLint
- Angular Language Service
- REST Client
- Debug Tools

## Common Development Tasks

### Adding New Routes
1. Create route handler in `routes/`
2. Add middleware if needed
3. Register in `app.ts`
4. Update TypeScript types

### Modifying Auth Flow
1. Update `keycloak-strategy.ts`
2. Modify `auth-routes.ts`
3. Test with Redis Commander
4. Update frontend services
