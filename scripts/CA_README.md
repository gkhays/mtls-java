# Certificate Authority (CA) Creation Script

## Overview

The `create-ca.sh` script creates a complete Certificate Authority (CA) infrastructure for mutual TLS authentication. This script generates all necessary files to establish a root CA that can be used to sign client and server certificates.

## Generated Files

When you run the script, it creates the following files:

- **ca-key.pem** - CA private key (keep secure!)
- **ca-cert.pem** - CA certificate (distribute to clients)
- **ca.conf** - OpenSSL CA configuration file
- **index.txt** - CA database for tracking issued certificates
- **ca-cert.srl** - Serial number file for certificate generation
- **crlnumber** - Certificate Revocation List number file

## Usage

### Basic Usage
```bash
./create-ca.sh
```

### Advanced Usage with Custom Parameters
```bash
./create-ca.sh \
  --org "MyCompany Inc." \
  --cn "MyCompany Root CA" \
  --country "US" \
  --state "California" \
  --city "San Francisco" \
  --validity 7300 \
  --keysize 4096
```

### Force Overwrite Existing Files
```bash
./create-ca.sh --force
```

## Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-h, --help` | Show help message | - |
| `-f, --force` | Force overwrite existing CA files | false |
| `-v, --validity DAYS` | Set CA certificate validity in days | 3650 (10 years) |
| `-k, --keysize SIZE` | Set RSA key size (2048, 4096, 8192) | 4096 |
| `-o, --org ORG` | Set organization name | MyOrg |
| `-c, --country CODE` | Set country code (2 letters) | US |
| `--state STATE` | Set state/province | State |
| `--city CITY` | Set city/locality | City |
| `--ou OU` | Set organizational unit | Development |
| `--cn CN` | Set common name | MyOrg Root CA |

## Security Considerations

1. **Private Key Protection**: The CA private key (`ca-key.pem`) is created with restrictive permissions (600) and should be kept secure.

2. **Backup Strategy**: Always backup the CA private key and certificate in a secure location.

3. **Key Size**: The default 4096-bit RSA key provides strong security. Consider your security requirements vs. performance trade-offs.

4. **Validity Period**: The default 10-year validity is reasonable for development. Production CAs might use shorter periods.

5. **Passphrase Protection**: For production use, consider adding passphrase protection to the CA private key.

## Integration with Existing Scripts

This script is designed to work seamlessly with the existing `create-keystore.sh` script:

1. **First**: Run `./create-ca.sh` to create the CA infrastructure
2. **Then**: Run `./create-keystore.sh` to create client/server certificates signed by your CA

## Workflow Example

```bash
# 1. Create the Certificate Authority
./create-ca.sh --org "MyCompany" --cn "MyCompany Root CA"

# 2. Create client and server keystores using the CA
./create-keystore.sh -all

# 3. Verify the certificates
./show-cert-extensions.sh server.jks
```

## Certificate Information

The generated CA certificate includes:

- **Basic Constraints**: CA:TRUE (identifies this as a Certificate Authority)
- **Key Usage**: digitalSignature, cRLSign, keyCertSign
- **Subject Key Identifier**: Hash of the public key
- **Authority Key Identifier**: Self-referencing (self-signed)

## Troubleshooting

### Script Won't Run
- Ensure the script is executable: `chmod +x create-ca.sh`
- Check for required tools: `openssl --version`

### Files Already Exist
- Use `--force` flag to overwrite existing files
- Or manually remove existing files: `rm ca-*.pem ca.conf index.txt crlnumber`

### Permission Errors
- Ensure you have write permissions in the scripts directory
- The script automatically sets proper permissions on generated files

## File Locations

All files are created in the current directory (typically the `scripts/` folder). The existing `create-keystore.sh` script expects the CA files to be in the same directory.

## Development vs Production

### Development (Default)
- 10-year validity period
- No passphrase protection
- Standard subject information

### Production Recommendations
- Shorter validity periods (1-5 years)
- Passphrase-protected private keys
- Hardware Security Module (HSM) storage
- Proper backup and disaster recovery procedures
- Certificate transparency logging