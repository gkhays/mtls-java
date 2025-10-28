# Mutual TLS Scenarios in Java

This project demonstrates various mutual TLS (mTLS) scenarios in Java, including certificate validation and Extended Key Usage (EKU) restrictions.

## Features

### Single-Use Client Certificates

The project supports creating and testing single-use client certificates with `serverAuth` Extended Key Usage (EKU) instead of the standard `clientAuth` EKU. This demonstrates certificate-based access control scenarios.

#### Creating Single-Use Certificates

Use the `-single-use` flag with the keystore creation script:

```bash
# Create a single-use client certificate with serverAuth EKU
cd scripts
./create-keystore.sh -client -single-use
```

#### Using Single-Use Mode in Java Application

The Java application recognizes the `-single-use` flag:

```bash
# Run with single-use mode awareness
java -cp target/classes com.github.tls.App -single-use
```

When `-single-use` flag is used:
- The application indicates it expects serverAuth EKU in the client certificate
- Certificate extensions are inspected and displayed
- The TLS handshake will fail as expected (serverAuth EKU cannot be used for client authentication)

#### Keystore Creation Options

```bash
./create-keystore.sh [-all|-client|-server] [-single-use]
```

- `-all`: Create both client.jks and server.jks keystores plus truststore.jks (default)
- `-client`: Create client.jks keystore with client certificate only  
- `-server`: Create server.jks keystore with server certificate only
- `-single-use`: Set serverAuth EKU in client certificate for single-use scenarios

#### Demo Script

Run the complete demonstration:

```bash
cd scripts
./demo-single-use.sh
```

This script demonstrates:
1. Normal mTLS with clientAuth EKU (works)
2. Single-use certificate with serverAuth EKU (fails as expected)
3. Application recognition of single-use mode

## Troubleshooting

```bash
Starting client communication...
Client keystore loaded successfully (CA-signed certificate)
Client truststore loaded successfully (contains CA certificate)

--- Common Extensions (Parsed) ---
Basic Constraints: CA: false
Key Usage:
  Digital Signature
  Non Repudiation
  Key Encipherment
  Data Encipherment
Extended Key Usage:
  Server Authentication (1.3.6.1.5.5.7.3.1)
Subject Alternative Names:
  DNS Name: localhost
  IP Address: 127.0.0.1
Client connected: /127.0.0.1
Error handling client connection: Extended key usage does not permit use for TLS client authentication
Server is waiting for connection...
java.net.SocketException: An established connection was aborted by the software in your host machine
```

