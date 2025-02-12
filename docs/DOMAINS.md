# Domain Configuration Guide

## Overview

This project uses custom domain names (*.local.com) to ensure secure communication between components and proper cookie handling in modern browsers.

## Why Custom Domain Names?

### Security Requirements

1. **Cookie Security**
   - HTTPS-only cookie transmission
   - Cross-domain cookie sharing
   - Strict same-origin policy compliance

2. **SSL/TLS Setup**
   - Individual SSL certificates per component
   - Shared parent domain (.local.com) for cookie sharing
   - Custom Certificate Authority for development

3. **Cross-Origin Communication**
   - Mutual certificate trust between components
   - Secure session cookie sharing
   - Compliant OAuth2/OIDC flows

## Configuration Steps

### 1. Host File Setup

Add these entries to your hosts file:

```bash
# Linux/macOS: /etc/hosts
# Windows: C:\Windows\System32\drivers\etc\hosts

127.0.0.1 frontend.local.com
127.0.0.1 backend.local.com
127.0.0.1 keycloak.local.com
```

> **Note**: Windows users need administrator privileges to modify the hosts file.

### 2. Certificate Generation

```bash
# Generate all certificates
./scripts/setup_ssl.sh
```

Generated files structure:
```
certs/
├── ca.cert.pem          # CA certificate
├── ca.key.pem          # CA private key
├── frontend.cert.pem   # Frontend certificate
├── frontend.key.pem    # Frontend private key
├── backend.cert.pem    # Backend certificate
├── backend.key.pem     # Backend private key
├── keycloak.cert.pem   # Keycloak certificate
├── keycloak.key.pem    # Keycloak private key
└── keycloak.p12        # Keycloak PKCS12 keystore
```

### 3. Custom Domain Configuration

To use different domain names:

1. Update `setup_ssl.sh`:
```bash
FRONTEND_DOMAIN_NAME="your-frontend.domain"
BACKEND_DOMAIN_NAME="your-backend.domain"
KEYCLOAK_DOMAIN_NAME="your-keycloak.domain"
```

2. Update environment configurations in `backend/.env`:
```ini
SESSION_DOMAIN=.domain
COOKIE_ORIGIN=https://your-frontend.domain:4200
KEYCLOAK_AUTH_SERVER_URL=https://your-keycloak.domain:8443
KEYCLOAK_CALLBACK_URL=https://your-backend.domain:3000/auth/keycloak/callback
```

3. Regenerate certificates:
```bash
rm -rf ./certs/* ./frontend/certs/* ./backend/certs/* ./keycloak/certs/*
./scripts/setup_ssl.sh
```

## Security Considerations

### Certificate Trust

- Import CA certificate into system trust store
- Required for browser security
- Must be done on each development machine

### Private Keys

- Set 600 permissions (owner read/write only)
- Store in respective component directories
- Never commit to version control

### Development Only

- Self-signed certificates for development only
- Use proper CA-signed certificates in production
- Secure CA private key storage

## Troubleshooting

### Browser Trust Issues

```bash
# Import CA certificate
sudo cp certs/ca.cert.pem /usr/local/share/ca-certificates/mydevca.crt
sudo update-ca-certificates
```

### Certificate Verification

```bash
# Verify domain names
openssl x509 -in certs/frontend.cert.pem -text -noout | grep DNS
```

### Common Problems

- Clear browser cache after importing CA
- Verify certificate dates
- Check file permissions
- Confirm hosts file entries
