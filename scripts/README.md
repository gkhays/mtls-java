## Scripts

### show-cert-extensions.sh

A utility script to display X.509v3 extension characteristics of certificates stored in Java keystores (JKS format).

**Usage:**
```bash
# Show extensions for all certificates in all keystores in current directory
./show-cert-extensions.sh

# Show extensions for all certificates in a specific keystore
./show-cert-extensions.sh client.jks

# Show extensions for a specific certificate alias in a keystore
./show-cert-extensions.sh server.jks myserver

# Display help
./show-cert-extensions.sh --help
```

**Features:**
- Displays basic certificate information (subject, issuer, serial number, validity period)
- Shows X.509v3 extensions including:
  - Authority Key Identifier
  - Basic Constraints (CA flag, path length)
  - Key Usage (digital signature, key encipherment, etc.)
  - Extended Key Usage (client auth, server auth)
  - Subject Alternative Names (DNS names, IP addresses)
  - Subject Key Identifier
- Supports both keytool and OpenSSL analysis methods
- Color-coded output for better readability
- Works with client.jks, server.jks, and truststore.jks files