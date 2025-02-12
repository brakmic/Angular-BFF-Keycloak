# Troubleshooting Guide

## Authentication Issues

### Cookie Problems

1. **Cookie Not Being Set**
   ```bash
   # Check domain configuration
   grep "local.com" /etc/hosts

   # Verify SSL certificates
   openssl x509 -in certs/frontend.cert.pem -text -noout | grep DNS
   ```

2. **Cross-Domain Cookie Sharing**
   - Verify SESSION_DOMAIN=.local.com in `.env`
   - Check browser's cookie settings
   - Ensure HTTPS is working

3. **Session Not Persisting**
   ```bash
   # Check Redis connection
   redis-cli -h redis_server -a changeit ping

   # View session in Redis Commander
   http://localhost:8081
   ```

## SSL Certificate Issues

### Browser Warnings

1. **Install CA Certificate**
   ```bash
   # Linux
   sudo cp certs/ca.cert.pem /usr/local/share/ca-certificates/mydevca.crt
   sudo update-ca-certificates

   # macOS
   sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain certs/ca.cert.pem
   ```

2. **Certificate Verification**
   ```bash
   # Check certificate details
   openssl x509 -in certs/frontend.cert.pem -text -noout

   # Verify domain names
   openssl x509 -in certs/frontend.cert.pem -text -noout | grep DNS
   ```

3. **Permission Issues**
   ```bash
   # Fix certificate permissions
   chmod 600 certs/*.key.pem
   chmod 644 certs/*.cert.pem
   ```

## Docker Issues

### Container Problems

1. **Service Won't Start**
   ```bash
   # Check logs
   docker compose logs -f [service_name]

   # Verify network
   docker network inspect devnetwork
   ```

2. **Mount Issues**
   ```bash
   # Check workspace variable
   echo $HOST_WORKSPACE

   # Verify paths
   ls -la ${HOST_WORKSPACE}/backend/certs
   ```

3. **Network Connectivity**
   ```bash
   # Test internal DNS
   docker compose exec backend ping redis_server

   # Check ports
   docker compose ps
   ```

## Redis Issues

### Connection Problems

1. **Redis Server Unreachable**
   ```bash
   # Test connection
   nc -vz redis_server 6379

   # Check Redis logs
   docker compose logs redis_server
   ```

2. **Authentication Failed**
   ```bash
   # Verify password
   redis-cli -h redis_server -a changeit ping

   # Check Redis Commander
   docker compose logs redis-commander
   ```

3. **Session Data Missing**
   ```bash
   # List all sessions
   redis-cli -h redis_server -a changeit keys "myapp:*"

   # Check TTL
   redis-cli -h redis_server -a changeit ttl "myapp:[session-id]"
   ```

## Keycloak Issues

### Authentication Flow

1. **Login Failed**
   - Check Keycloak logs
   ```bash
   docker compose logs -f keycloak
   ```
   - Verify realm configuration
   - Check client settings

2. **Callback Errors**
   - Verify callback URLs in client settings
   - Check HTTPS certificates
   - Confirm hostname resolution

3. **Database Connection**
   ```bash
   # Check PostgreSQL logs
   docker compose logs postgres

   # Verify database
   docker compose exec postgres psql -U keycloak -d keycloak -c "\dt"
   ```

## Application Issues

### Frontend Problems

1. **Hot Reload Not Working**
   ```bash
   # Check Angular logs
   docker compose logs -f frontend

   # Verify volume mounts
   docker compose exec frontend ls -la /app
   ```

2. **Network Errors**
   - Check browser console
   - Verify proxy configuration
   - Test API endpoints

### Backend Problems

1. **Server Not Starting**
   ```bash
   # Check Node.js logs
   docker compose logs backend

   # Verify environment
   docker compose exec backend env
   ```

2. **API Errors**
   - Check express.js logs
   - Verify route configuration
   - Test endpoints with curl

## System Issues

### Resource Problems

1. **Container Performance**
   ```bash
   # Check resource usage
   docker stats

   # View logs
   docker compose logs --tail=100
   ```

2. **Disk Space**
   ```bash
   # Check Docker disk usage
   docker system df

   # Clean up
   docker system prune
   ```

### Development Environment

1. **VSCode Integration**
   - Verify Docker extension
   - Check workspace settings
   - Update devcontainer config

2. **Git Issues**
   ```bash
   # Check ignored files
   git check-ignore *

   # Verify certificates not tracked
   git status certs/
   ```
