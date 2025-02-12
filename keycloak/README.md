# Keycloak Development Setup

This guide explains how to set up Keycloak for development in different environments, particularly focusing on container-based development scenarios.

## Quick Start

1. Deploy Keycloak and its database:
   ```bash
   docker compose up -d
   ```

2. Access the admin console at:
   - Local development: https://keycloak.local.com:8443
   - Inside VSCode DevContainer: https://keycloak:8443

## Configuration Details

### Environment Types

#### 1. Local Development
- Uses hostname: `keycloak.local.com`
- Requires hosts entry:
  ```
  127.0.0.1 keycloak.local.com
  ```

#### 2. VSCode DevContainer
- Uses hostname: keycloak
- Important: Remove any hosts entries for keycloak to allow Docker DNS resolution
- Applications inside devcontainer should use `https://keycloak:8443` as the auth server URL

### Database Configuration

PostgreSQL is used as the persistent store with the following defaults:
- Database: keycloak
- Username: keycloak
- Password: `keycloakpassword`

### Security Configuration

- HTTPS is enforced (HTTP disabled)
- Default port: `8443`
- Uses PKCS12 keystore for TLS
- Certificate location: `/opt/keycloak/conf/certificates/keycloak.p12`

### Networks

The setup uses an external Docker network named `devnetwork`. This allows:
- Communication between containers
- DNS resolution of container names
- Shared network context for development tools

## Troubleshooting

### Common Issues

1. **Connection Refused (Port 8443)**
   - Check if Keycloak container is running
   - Verify the correct hostname is used for your environment
   - Inside devcontainer, ensure no conflicting hosts entries exist

2. **Certificate Errors**
   - For development, you may need to accept self-signed certificates
   - Verify certificate's Common Name matches the hostname you're using

3. **DNS Resolution Problems**
   - Inside devcontainer:
     ```bash
     # Should return container IP, not 127.0.0.1
     getent hosts keycloak
     ```
   - Check Docker network:
     ```bash
     docker network inspect devnetwork
     ```

### Environment-Specific Configuration

#### Backend Applications

```typescript
// For devcontainer
const config = {
  authServerURL: 'https://keycloak:8443',
  realm: 'TestRealm',
  // ... other settings
};

// For local development
const config = {
  authServerURL: 'https://keycloak.local.com:8443',
  realm: 'TestRealm',
  // ... other settings
};
```

## Important Notes

- The `KC_HOSTNAME` setting in docker-compose.yml must match the hostname used by your applications
- When developing inside a devcontainer, use the container name (keycloak) instead of DNS names
- Self-signed certificates are used for development; configure proper certificates for production
- The setup includes automatic realm import from *test-realm.json*

## Security Considerations

- Default admin credentials are set for development only (user: **admin** / pwd: **admin**)
- HTTPS is enforced with TLS
- Proxy mode is set to `edge`
- Strict hostname validation is disabled for development
