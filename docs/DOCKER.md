# Docker Configuration Guide

## Environment Setup

### Workspace Configuration

The Docker Compose files use `${HOST_WORKSPACE}` to locate project files:

```bash
# Option 1: Set environment variable
export HOST_WORKSPACE=/path/to/your/project

# Option 2: Create .env in project root
HOST_WORKSPACE=/path/to/your/project

# Windows PowerShell
$env:HOST_WORKSPACE = $(Get-Location)
```

### Alternative: Relative Paths

If you prefer not to use environment variables, modify docker-compose.yaml:
```yaml
volumes:
  # Instead of:
  - ${HOST_WORKSPACE}/backend:/app
  
  # Use:
  - ./backend:/app
```

## Component Services

### Available Services

| Service | Image | Port | Purpose |
|---------|-------|------|---------|
| Frontend | node:18-alpine | 4200 | Angular SPA |
| Backend | node:18-alpine | 3000 | Express.js BFF |
| Keycloak | quay.io/keycloak/keycloak:26.1.0 | 8443 | Identity Provider |
| PostgreSQL | postgres:15 | 5432 | Keycloak Database |
| Redis | redis:7.0-alpine | 6379 | Session Store |
| Redis Commander | rediscommander/redis-commander | 8081 | Redis UI |

### Service Configuration

```yaml
// filepath: /host_workspace/docker-compose.yaml
services:
  frontend:
    build:
      context: ./frontend
      dockerfile: Dockerfile
    volumes:
      - type: bind
        source: ${HOST_WORKSPACE}/frontend
        target: /app
      - type: volume
        source: frontend_node_modules
        target: /app/node_modules

  backend:
    build:
      context: ./backend
      dockerfile: Dockerfile
    volumes:
      - type: bind
        source: ${HOST_WORKSPACE}/backend
        target: /app
      - type: volume
        source: backend_node_modules
        target: /app/node_modules

  # Other services...
```

## Development Workflow

### Starting Services

```bash
# Start all services
docker compose up -d

# Start specific service
docker compose up -d backend

# Build and start
docker compose up -d --build
```

### Monitoring

```bash
# View all logs
docker compose logs -f

# View specific service
docker compose logs -f backend

# Check service status
docker compose ps
```

### Hot Reloading

Both frontend and backend support hot reloading:
- Source directories mounted as volumes
- node_modules in named volumes
- Automatic restart on file changes

### Container Management

```bash
# Restart service
docker compose restart backend

# Stop all services
docker compose down

# Remove volumes
docker compose down -v

# Clean rebuild
docker compose build --no-cache
```

## Volume Management

### Named Volumes

```yaml
volumes:
  postgres_data:    # Keycloak database
  test_data:       # Keycloak test data
  redis_data:      # Redis persistence
  frontend_node_modules:  # Frontend dependencies
  backend_node_modules:   # Backend dependencies
```

### Bind Mounts

```yaml
volumes:
  - ${HOST_WORKSPACE}/frontend:/app   # Source code
  - ${HOST_WORKSPACE}/backend:/app    # Source code
  - ${HOST_WORKSPACE}/certs:/app/certs:ro  # Certificates
```

## Network Configuration

```yaml
networks:
  devnetwork:
    external: true
```

All services share the same network for:
- Internal DNS resolution
- Service discovery
- Secure communication

## Security Configuration

### Redis Commander

```yaml
environment:
  - HTTP_USER=admin
  - HTTP_PASSWORD=admin
  - HTTP_AUTH_ENABLED=1
```

### Keycloak

```yaml
environment:
  KC_DB: postgres
  KC_DB_USERNAME: keycloak
  KC_DB_PASSWORD: keycloakpassword
  KC_HTTPS_KEY_STORE_PASSWORD: changeit
```

## Troubleshooting

### Common Issues

1. **Mount Denied**
```bash
# Check workspace variable
echo $HOST_WORKSPACE

# Verify directory permissions
ls -la ${HOST_WORKSPACE}
```

2. **Container Fails to Start**
```bash
# Check detailed logs
docker compose logs --tail=100 backend

# Inspect container
docker compose exec backend sh
```

3. **Network Issues**
```bash
# Test internal DNS
docker compose exec backend ping redis_server

# Check network
docker network inspect devnetwork
```

### Debug Tools

```bash
# Shell access
docker compose exec backend sh

# Process list
docker compose top

# Resource usage
docker compose stats
```

## Production Considerations

1. **Security**
   - Remove development tools
   - Use production Docker images
   - Implement proper secrets management
   - Enable health checks

2. **Performance**
   - Optimize build contexts
   - Use multi-stage builds
   - Implement proper caching
   - Configure resource limits

3. **Monitoring**
   - Add logging solutions
   - Implement metrics collection
   - Configure container health checks
   - Set up alerts
