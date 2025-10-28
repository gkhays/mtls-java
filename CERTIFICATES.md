# CertificateManager - X.509 Certificate Inspector

## Overview

The `CertificateManager` class is a comprehensive utility for inspecting X.509 certificates and their v3 extensions. It can read certificates from keystores (JKS format) or PEM files and provides detailed analysis of their properties and security extensions.

## Features

- **Certificate Information**: Subject, Issuer, Serial Number, Validity Period, Version, Signature Algorithm
- **X.509 v3 Extensions Analysis**: 
  - Both critical and non-critical extensions
  - Raw extension data in hexadecimal format
  - Human-readable interpretation of common extensions
- **Common Extensions Parsed**:
  - Basic Constraints (CA flag, path length)
  - Key Usage (Digital Signature, Key Encipherment, etc.)
  - Extended Key Usage (Server Auth, Client Auth, etc.)
  - Subject Alternative Names (DNS, IP, Email, etc.)
  - Issuer Alternative Names
- **Flexible Input**: Supports JKS keystores and PEM certificate files
- **Multiple Certificate Support**: Can inspect all certificates in a keystore or specific ones by alias

## Usage

### Command Line Usage

```bash
# Inspect default project certificates
java com.github.tls.CertificateManager

# Inspect all certificates in a specific keystore
java com.github.tls.CertificateManager /path/to/keystore.jks password

# Inspect a specific certificate by alias
java com.github.tls.CertificateManager /path/to/keystore.jks password alias_name
```

### Programmatic Usage

```java
CertificateManager manager = new CertificateManager();

// Inspect from keystore
manager.inspectCertificateFromKeystore("server.jks", "changeit", "server");

// Inspect from PEM file
manager.inspectCertificateFromFile("certificate.pem");

// Inspect X509Certificate object directly
X509Certificate cert = // ... obtain certificate
manager.inspectX509Certificate(cert);
```

## Extension Support

The class recognizes and provides human-readable names for common X.509 extension OIDs:

- **2.5.29.19**: Basic Constraints
- **2.5.29.15**: Key Usage
- **2.5.29.37**: Extended Key Usage
- **2.5.29.17**: Subject Alternative Name
- **2.5.29.18**: Issuer Alternative Name
- **2.5.29.14**: Subject Key Identifier
- **2.5.29.35**: Authority Key Identifier
- **2.5.29.31**: CRL Distribution Points
- **1.3.6.1.5.5.7.1.1**: Authority Information Access
- And more...

## Output Example

```
=== Certificate: server ===
Subject: C=US, ST=State, L=City, O=MyOrg, OU=Development, CN=localhost
Issuer: C=US, O=MyOrg, CN=MyCA
Serial Number: 400823768977980261989860927194680880506532747541
Valid From: Tue Oct 28 12:36:37 CDT 2025
Valid Until: Wed Oct 28 12:36:37 CDT 2026
Version: 3
Signature Algorithm: SHA256withRSA

--- X.509 v3 Extensions ---

Non-Critical Extensions:
  Subject Key Identifier (2.5.29.14)
    Critical: false
    Length: 24 bytes
    Raw Value: 04 160414f2870fef61d1955afbb23397f7766de881a11b50

--- Common Extensions (Parsed) ---
Basic Constraints: CA: false
Key Usage:
  Digital Signature
  Key Encipherment
Subject Alternative Names:
  DNS Name: localhost
  IP Address: 127.0.0.1
```

## Integration with mTLS Project

This utility is specifically designed to work with the mTLS Java project and can inspect:
- Server certificates (`server.jks`)
- Client certificates (`client.jks`) 
- Trust store certificates (`truststore.jks`)

Use the `CertificateInspectorDemo` class for a comprehensive demonstration of the certificate inspection capabilities across all project keystores.