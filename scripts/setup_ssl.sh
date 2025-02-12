#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Define directories
ROOT_DIR=$(pwd)
CERTS_DIR="${ROOT_DIR}/certs"
FRONTEND_CERTS_DIR="${ROOT_DIR}/frontend/certs"
BACKEND_CERTS_DIR="${ROOT_DIR}/backend/certs"
KEYCLOAK_CERTS_DIR="${ROOT_DIR}/keycloak/certs"

# Define Keycloak keystore variables
KEYCLOAK_KEYSTORE_FILE="keycloak.p12"
KEYCLOAK_KEYSTORE_PASSWORD="changeit"

# Define domain names
FRONTEND_DOMAIN_NAME="frontend.local.com"
BACKEND_DOMAIN_NAME="backend.local.com"
KEYCLOAK_DOMAIN_NAME="keycloak.local.com"

# Create certs directories
mkdir -p "${CERTS_DIR}"
mkdir -p "${FRONTEND_CERTS_DIR}"
mkdir -p "${BACKEND_CERTS_DIR}"
mkdir -p "${KEYCLOAK_CERTS_DIR}"

echo "=============================="
echo "1. Generating Certificate Authority (CA)"
echo "=============================="

# Check if CA key already exists to avoid regeneration
if [ -f "${CERTS_DIR}/ca.key.pem" ] && [ -f "${CERTS_DIR}/ca.cert.pem" ]; then
    echo "CA key and certificate already exist. Skipping CA generation."
else
    # Generate CA private key
    openssl genrsa -out "${CERTS_DIR}/ca.key.pem" 4096

    # Generate CA self-signed certificate
    openssl req -x509 -new -nodes -key "${CERTS_DIR}/ca.key.pem" -sha256 -days 3650 \
        -out "${CERTS_DIR}/ca.cert.pem" \
        -subj "/C=US/ST=State/L=City/O=Organization/OU=OrgUnit/CN=MyDevCA"

    echo "CA Certificate and Key generated at ${CERTS_DIR}"
fi

echo "=============================="
echo "2. Generating Frontend Certificate"
echo "=============================="

# Check if Frontend key already exists to avoid regeneration
if [ -f "${CERTS_DIR}/frontend.key.pem" ] && [ -f "${CERTS_DIR}/frontend.cert.pem" ]; then
    echo "Frontend key and certificate already exist. Skipping Frontend certificate generation."
else
    # Generate Frontend private key
    openssl genrsa -out "${CERTS_DIR}/frontend.key.pem" 2048

    # Generate Frontend CSR
    openssl req -new -key "${CERTS_DIR}/frontend.key.pem" \
        -out "${CERTS_DIR}/frontend.csr.pem" \
        -subj "/C=US/ST=State/L=City/O=Organization/OU=OrgUnit/CN=${FRONTEND_DOMAIN_NAME}"

    # Create Frontend certificate signed by CA
    openssl x509 -req -in "${CERTS_DIR}/frontend.csr.pem" \
        -CA "${CERTS_DIR}/ca.cert.pem" -CAkey "${CERTS_DIR}/ca.key.pem" -CAcreateserial \
        -out "${CERTS_DIR}/frontend.cert.pem" -days 365 -sha256 \
        -extfile <(printf "subjectAltName=DNS:${FRONTEND_DOMAIN_NAME}")

    echo "Frontend Certificate and Key generated at ${CERTS_DIR}"
fi

echo "=============================="
echo "3. Generating Backend Certificate"
echo "=============================="

# Check if Backend key already exists to avoid regeneration
if [ -f "${CERTS_DIR}/backend.key.pem" ] && [ -f "${CERTS_DIR}/backend.cert.pem" ]; then
    echo "Backend key and certificate already exist. Skipping Backend certificate generation."
else
    # Generate Backend private key
    openssl genrsa -out "${CERTS_DIR}/backend.key.pem" 2048

    # Generate Backend CSR
    openssl req -new -key "${CERTS_DIR}/backend.key.pem" \
        -out "${CERTS_DIR}/backend.csr.pem" \
        -subj "/C=US/ST=State/L=City/O=Organization/OU=OrgUnit/CN=${BACKEND_DOMAIN_NAME}"

    # Create Backend certificate signed by CA
    openssl x509 -req -in "${CERTS_DIR}/backend.csr.pem" \
        -CA "${CERTS_DIR}/ca.cert.pem" -CAkey "${CERTS_DIR}/ca.key.pem" -CAcreateserial \
        -out "${CERTS_DIR}/backend.cert.pem" -days 365 -sha256 \
        -extfile <(printf "subjectAltName=DNS:${BACKEND_DOMAIN_NAME}")

    echo "Backend Certificate and Key generated at ${CERTS_DIR}"
fi

echo "=============================="
echo "4. Generating Keycloak Certificate and Keystore"
echo "=============================="

# Check if Keycloak keystore already exists to avoid regeneration
if [ -f "${CERTS_DIR}/keycloak.key.pem" ] && \
   [ -f "${CERTS_DIR}/keycloak.cert.pem" ] && \
   [ -f "${CERTS_DIR}/keycloak.p12" ]; then
    echo "Keycloak key, certificate, and keystore already exist. Skipping Keycloak certificate generation."
else
    # Generate Keycloak private key
    openssl genrsa -out "${CERTS_DIR}/keycloak.key.pem" 2048

    # Generate Keycloak CSR
    openssl req -new -key "${CERTS_DIR}/keycloak.key.pem" \
        -out "${CERTS_DIR}/keycloak.csr.pem" \
        -subj "/C=US/ST=State/L=City/O=Organization/OU=OrgUnit/CN=${KEYCLOAK_DOMAIN_NAME}"

    # Create Keycloak certificate signed by CA
    openssl x509 -req -in "${CERTS_DIR}/keycloak.csr.pem" \
        -CA "${CERTS_DIR}/ca.cert.pem" -CAkey "${CERTS_DIR}/ca.key.pem" -CAcreateserial \
        -out "${CERTS_DIR}/keycloak.cert.pem" -days 365 -sha256 \
        -extfile <(printf "subjectAltName=DNS:${KEYCLOAK_DOMAIN_NAME}")

    echo "Keycloak Certificate and Key generated at ${CERTS_DIR}"

    # Create PKCS12 Keystore for Keycloak
    openssl pkcs12 -export \
        -inkey "${CERTS_DIR}/keycloak.key.pem" \
        -in "${CERTS_DIR}/keycloak.cert.pem" \
        -certfile "${CERTS_DIR}/ca.cert.pem" \
        -out "${CERTS_DIR}/keycloak.p12" \
        -name keycloak \
        -passout pass:${KEYCLOAK_KEYSTORE_PASSWORD}

    echo "Keycloak PKCS12 Keystore created at ${CERTS_DIR}/keycloak.p12"
fi

echo "=============================="
echo "5. Copying Frontend, Backend, and Keycloak Certificates"
echo "=============================="

# Copy frontend cert and key
cp "${CERTS_DIR}/frontend.cert.pem" "${FRONTEND_CERTS_DIR}/"
cp "${CERTS_DIR}/frontend.key.pem" "${FRONTEND_CERTS_DIR}/"
echo "Frontend Certificates copied to ${FRONTEND_CERTS_DIR}"

# Copy backend cert and key
cp "${CERTS_DIR}/backend.cert.pem" "${BACKEND_CERTS_DIR}/"
cp "${CERTS_DIR}/backend.key.pem" "${BACKEND_CERTS_DIR}/"
echo "Backend Certificates copied to ${BACKEND_CERTS_DIR}"

# Copy Keycloak keystore
cp "${CERTS_DIR}/keycloak.p12" "${KEYCLOAK_CERTS_DIR}/"
echo "Keycloak Keystore copied to ${KEYCLOAK_CERTS_DIR}"

echo "=============================="
echo "6. Setting Permissions"
echo "=============================="

# Set appropriate permissions
chmod 600 "${CERTS_DIR}"/*.key.pem
chmod 600 "${CERTS_DIR}"/*.p12

echo "Permissions set for private keys and keystores."

echo "=============================="
echo "7. Optional: Importing CA Certificate to Trusted Store"
echo "=============================="

read -p "Do you want to import the CA certificate to your system's trusted store? [y/N]: " TRUST_CA

if [[ "$TRUST_CA" =~ ^[Yy]$ ]]; then
    sudo cp "${CERTS_DIR}/ca.cert.pem" /usr/local/share/ca-certificates/mydevca.crt
    sudo update-ca-certificates
    echo "CA certificate imported and trusted."
    echo "Please restart your browser to apply changes."
else
    echo "Skipping CA certificate import."
fi

echo "=============================="
echo "SSL Setup Completed Successfully!"
echo "=============================="
