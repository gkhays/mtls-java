# Mutual TLS Scenarios in Java

This project demonstrates various mutual TLS (mTLS) scenarios in Java, including certificate validation and Extended Key Usage (EKU) restrictions.

## Features

### Single-Use Client Certificates

The project supports creating and testing single-use client certificates with `serverAuth` Extended Key Usage (EKU) instead of the standard `clientAuth` EKU. This demonstrates certificate-based access control scenarios.

### Dual-Use Certificates

The project also supports creating dual-use certificates that have both `clientAuth` and `serverAuth` Extended Key Usage (EKU), allowing certificates to be used for both client and server authentication scenarios.

#### Creating Single-Use Certificates

Use the `-single-use` flag with the keystore creation script:

```bash
# Create a single-use client certificate with serverAuth EKU
cd scripts
./create-keystore.sh -client -single-use
```

#### Creating Dual-Use Certificates

Use the `-dual-use` flag with the keystore creation script:

```bash
# Create certificates with both clientAuth and serverAuth EKU
cd scripts
./create-keystore.sh -all -dual-use
```

#### Cleaning Generated Files

Remove all generated JKS files:

```bash
# Clean all JKS files from script directory and src/main/resources
cd scripts
./create-keystore.sh -clean
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
./create-keystore.sh [-all|-client|-server|-clean] [-single-use|-dual-use]
```

- `-all`: Create both client.jks and server.jks keystores plus truststore.jks (default)
- `-client`: Create client.jks keystore with client certificate plus truststore.jks  
- `-server`: Create server.jks keystore with server certificate plus truststore.jks
- `-clean`: Remove all JKS files from script directory and src/main/resources
- `-single-use`: Set serverAuth EKU in client certificate for single-use scenarios
- `-dual-use`: Set both clientAuth and serverAuth EKU in both client and server certificates

**Note:** The `-single-use` and `-dual-use` options are mutually exclusive.

#### Examples

```bash
# Create complete mTLS setup with standard certificates (default)
./create-keystore.sh

# Create only client certificate and truststore
./create-keystore.sh -client

# Create only server certificate and truststore  
./create-keystore.sh -server

# Create single-use client certificate (serverAuth EKU only)
./create-keystore.sh -client -single-use

# Create dual-use certificates (both clientAuth and serverAuth EKU)
./create-keystore.sh -all -dual-use

# Clean all generated JKS files
./create-keystore.sh -clean
```

All keystores are automatically copied to `src/main/resources` for use by the Java application.

#### Test Script

Run the complete demonstration:

```bash
cd scripts
./test-single-use.sh
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

