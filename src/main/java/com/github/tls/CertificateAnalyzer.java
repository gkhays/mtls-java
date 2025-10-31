package com.github.tls;

import com.github.tls.utils.CertificateUtils;
import com.github.tls.utils.KeyUsageConstants;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * CertificateManager provides utilities for inspecting X.509 certificates
 * and extracting their v3 extension properties.
 */
public class CertificateAnalyzer {

    private static final Logger LOGGER = LoggerFactory.getLogger(CertificateAnalyzer.class);

    /** Minimum version for X.509 v3 certificates. */
    private static final int CERTIFICATE_V3 = 3;
    /** Maximum path length constraint value. */
    private static final int MAX_PATH_LENGTH = Integer.MAX_VALUE;
    /** Number of characters per hex line for formatting. */
    private static final int HEX_CHARS_PER_LINE = 32;
    /** Number of characters between hex bytes. */
    private static final int HEX_SPACING = 2;
    /** Separator length for visual formatting. */
    private static final int SEPARATOR_LENGTH = 80;

    // Subject Alternative Name type constants
    /** Other Name SAN type. */
    private static final int SAN_OTHER_NAME = 0;
    /** RFC 822 Name (Email) SAN type. */
    private static final int SAN_RFC822_NAME = 1;
    /** DNS Name SAN type. */
    private static final int SAN_DNS_NAME = 2;
    /** X.400 Address SAN type. */
    private static final int SAN_X400_ADDRESS = 3;
    /** Directory Name SAN type. */
    private static final int SAN_DIRECTORY_NAME = 4;
    /** EDI Party Name SAN type. */
    private static final int SAN_EDI_PARTY_NAME = 5;
    /** URI SAN type. */
    private static final int SAN_URI = 6;
    /** IP Address SAN type. */
    private static final int SAN_IP_ADDRESS = 7;
    /** Registered ID SAN type. */
    private static final int SAN_REGISTERED_ID = 8;

    /**
     * Inspects a certificate from a keystore and outputs its v3 extension properties.
     *
     * @param keystorePath Path to the keystore file
     * @param keystorePassword Password for the keystore
     * @param alias Alias of the certificate to inspect (null to inspect all certificates)
     * @throws Exception if an error occurs during certificate inspection
     */
    public void inspectCertificateFromKeystore(String keystorePath, String keystorePassword, String alias)
            throws java.security.GeneralSecurityException, java.io.IOException {
        KeyStore keyStore = KeyStore.getInstance("JKS");

        try (FileInputStream fis = new FileInputStream(keystorePath)) {
            keyStore.load(fis, keystorePassword.toCharArray());
        }

        if (alias != null) {
            Certificate cert = keyStore.getCertificate(alias);
            if (cert instanceof X509Certificate) {
                LOGGER.info("=== Certificate: {} ===", alias);
                inspectX509Certificate((X509Certificate) cert);
            } else {
                LOGGER.warn("Certificate with alias '{}' is not an X.509 certificate or does not exist", alias);
            }
        } else {
            // Inspect all certificates in the keystore
            CertificateUtils.enumerateCertificates(keyStore, (currentAlias, x509Cert) -> {
                LOGGER.info("=== Certificate: {} ===", currentAlias);
                inspectX509Certificate(x509Cert);
                LOGGER.info("");
            });
        }
    }

    /**
     * Inspects a certificate from a keystore resource and outputs its v3 extension properties.
     * This method loads the keystore from the classpath resources.
     *
     * @param keystoreResourceName Name of the keystore resource (e.g., "server.jks")
     * @param keystorePassword Password for the keystore
     * @param alias Alias of the certificate to inspect (null to inspect all certificates)
     * @throws Exception if an error occurs during certificate inspection
     */
    public void inspectCertificateFromKeystoreResource(String keystoreResourceName, String keystorePassword,
            String alias) throws java.security.GeneralSecurityException, java.io.IOException {
        KeyStore keyStore = KeyStore.getInstance("JKS");

        try (java.io.InputStream inputStream = this.getClass().getClassLoader()
                .getResourceAsStream(keystoreResourceName)) {
            if (inputStream == null) {
                throw new java.io.IOException("Keystore resource not found: " + keystoreResourceName);
            }
            keyStore.load(inputStream, keystorePassword.toCharArray());
        }

        if (alias != null) {
            Certificate cert = keyStore.getCertificate(alias);
            if (cert instanceof X509Certificate) {
                LOGGER.info("=== Certificate: {} ===", alias);
                inspectX509Certificate((X509Certificate) cert);
            } else {
                LOGGER.warn("Certificate with alias '{}' is not an X.509 certificate or does not exist", alias);
            }
        } else {
            // Inspect all certificates in the keystore
            CertificateUtils.enumerateCertificates(keyStore, (currentAlias, x509Cert) -> {
                LOGGER.info("=== Certificate: {} ===", currentAlias);
                inspectX509Certificate(x509Cert);
                LOGGER.info("");
            });
        }
    }

    /**
     * Inspects a certificate from a PEM file and outputs its v3 extension properties.
     *
     * @param certPath Path to the certificate file (PEM format)
     * @throws Exception if an error occurs during certificate inspection
     */
    public void inspectCertificateFromFile(String certPath)
            throws java.security.GeneralSecurityException, java.io.IOException {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");

        try (FileInputStream fis = new FileInputStream(certPath)) {
            Collection<? extends Certificate> certificates = factory.generateCertificates(fis);

            int count = 0;
            for (Certificate cert : certificates) {
                if (cert instanceof X509Certificate) {
                    LOGGER.info("=== Certificate " + (++count) + " ===");
                    inspectX509Certificate((X509Certificate) cert);
                    LOGGER.info("");
                }
            }
        }
    }

    /**
     * Inspects an X.509 certificate and outputs detailed information about its v3 extensions.
     *
     * @param cert The X.509 certificate to inspect
     */
    public void inspectX509Certificate(X509Certificate cert) {
        LOGGER.info("Subject: {}", cert.getSubjectX500Principal());
        LOGGER.info("Issuer: {}", cert.getIssuerX500Principal());
        LOGGER.info("Serial Number: {}", cert.getSerialNumber());
        LOGGER.debug("Valid From: {}", cert.getNotBefore());
        LOGGER.debug("Valid Until: {}", cert.getNotAfter());
        LOGGER.debug("Version: {}", cert.getVersion());
        LOGGER.debug("Signature Algorithm: {}", cert.getSigAlgName());

        // Check if this is a v3 certificate (version 3)
        if (cert.getVersion() >= CERTIFICATE_V3) {
            LOGGER.info("\n--- X.509 v3 Extensions ---");

            Set<String> criticalExtensions = cert.getCriticalExtensionOIDs();
            Set<String> nonCriticalExtensions = cert.getNonCriticalExtensionOIDs();

            if (criticalExtensions != null && !criticalExtensions.isEmpty()) {
                LOGGER.info("\nCritical Extensions:");
                for (String oid : criticalExtensions) {
                    inspectExtension(cert, oid, true);
                }
            }

            if (nonCriticalExtensions != null && !nonCriticalExtensions.isEmpty()) {
                LOGGER.info("\nNon-Critical Extensions:");
                for (String oid : nonCriticalExtensions) {
                    inspectExtension(cert, oid, false);
                }
            }

            // Inspect common extensions with specific methods
            inspectCommonExtensions(cert);
        } else {
            LOGGER.info("\nThis is not a v3 certificate. No extensions available.");
        }
    }

    /**
    /**
     * Inspects a specific extension by OID.
     *
     * @param cert The X.509 certificate
     * @param oid The OID of the extension
     * @param isCritical Whether the extension is critical
     */
    private void inspectExtension(X509Certificate cert, String oid, boolean isCritical) {
        String extensionName = getExtensionName(oid);
        byte[] extensionValue = cert.getExtensionValue(oid);

        LOGGER.info("  " + extensionName + " (" + oid + ")");
        LOGGER.info("    Critical: " + isCritical);
        LOGGER.info("    Length: " + (extensionValue != null ? extensionValue.length : 0) + " bytes");

        if (extensionValue != null && extensionValue.length > 0) {
            LOGGER.info("    Raw Value: " + bytesToHex(extensionValue));
        }
    }

    /**
     * Inspects common X.509 v3 extensions with human-readable output.
     *
     * @param cert The X.509 certificate
     */
    public void inspectCommonExtensions(X509Certificate cert) {
        if (cert == null) {
            LOGGER.info("\n--- Common Extensions (Parsed) ---");
            LOGGER.info("Error: Certificate is null");
            return;
        }

        LOGGER.info("\n--- Common Extensions (Parsed) ---");

        // Basic Constraints
        int basicConstraints = cert.getBasicConstraints();
        if (basicConstraints != -1) {
            LOGGER.info("Basic Constraints:");
            LOGGER.info("  CA: true");
            LOGGER.info("  Path Length: " + (basicConstraints == MAX_PATH_LENGTH
                    ? "unlimited" : basicConstraints));
        } else {
            LOGGER.info("Basic Constraints: CA: false");
        }

        // Key Usage
        boolean[] keyUsage = cert.getKeyUsage();
        if (keyUsage != null) {
            LOGGER.info("Key Usage:");
            for (int i = 0; i < Math.min(keyUsage.length, KeyUsageConstants.KEY_USAGE_NAMES.length); i++) {
                if (keyUsage[i]) {
                    LOGGER.info("  " + KeyUsageConstants.getKeyUsageName(i));
                }
            }
        }

        // Extended Key Usage
        try {
            List<String> extendedKeyUsage = cert.getExtendedKeyUsage();
            if (extendedKeyUsage != null && !extendedKeyUsage.isEmpty()) {
                LOGGER.info("Extended Key Usage:");
                for (String eku : extendedKeyUsage) {
                    LOGGER.info("  " + getExtendedKeyUsageName(eku) + " (" + eku + ")");
                }
            }
        } catch (CertificateException e) {
            LOGGER.info("Extended Key Usage: Error parsing - " + e.getMessage());
        }

        // Subject Alternative Names
        try {
            Collection<List<?>> subjectAltNames = cert.getSubjectAlternativeNames();
            if (subjectAltNames != null && !subjectAltNames.isEmpty()) {
                LOGGER.info("Subject Alternative Names:");
                for (List<?> san : subjectAltNames) {
                    if (san.size() >= 2) {
                        Integer type = (Integer) san.get(0);
                        Object value = san.get(1);
                        LOGGER.info("  " + getSubjectAltNameType(type) + ": " + value);
                    }
                }
            }
        } catch (CertificateException e) {
            LOGGER.info("Subject Alternative Names: Error parsing - " + e.getMessage());
        }

        // Issuer Alternative Names
        try {
            Collection<List<?>> issuerAltNames = cert.getIssuerAlternativeNames();
            if (issuerAltNames != null && !issuerAltNames.isEmpty()) {
                LOGGER.info("Issuer Alternative Names:");
                for (List<?> ian : issuerAltNames) {
                    if (ian.size() >= 2) {
                        Integer type = (Integer) ian.get(0);
                        Object value = ian.get(1);
                        LOGGER.info("  " + getSubjectAltNameType(type) + ": " + value);
                    }
                }
            }
        } catch (CertificateException e) {
            LOGGER.info("Issuer Alternative Names: Error parsing - " + e.getMessage());
        }
    }

    /**
     * Gets a human-readable name for an extension OID.
     *
     * @param oid The extension OID
     * @return Human-readable extension name
     */
    private String getExtensionName(String oid) {
        switch (oid) {
            case "2.5.29.19": return "Basic Constraints";
            case "2.5.29.15": return "Key Usage";
            case "2.5.29.37": return "Extended Key Usage";
            case "2.5.29.17": return "Subject Alternative Name";
            case "2.5.29.18": return "Issuer Alternative Name";
            case "2.5.29.14": return "Subject Key Identifier";
            case "2.5.29.35": return "Authority Key Identifier";
            case "2.5.29.31": return "CRL Distribution Points";
            case "1.3.6.1.5.5.7.1.1": return "Authority Information Access";
            case "2.5.29.32": return "Certificate Policies";
            case "2.5.29.36": return "Policy Constraints";
            case "2.5.29.54": return "Inhibit Any Policy";
            case "2.5.29.9": return "Subject Directory Attributes";
            default: return "Unknown Extension";
        }
    }

    /**
     * Gets a human-readable name for an Extended Key Usage OID.
     *
     * @param oid The EKU OID
     * @return Human-readable EKU name
     */
    private String getExtendedKeyUsageName(String oid) {
        switch (oid) {
            case "1.3.6.1.5.5.7.3.1": return "Server Authentication";
            case "1.3.6.1.5.5.7.3.2": return "Client Authentication";
            case "1.3.6.1.5.5.7.3.3": return "Code Signing";
            case "1.3.6.1.5.5.7.3.4": return "Email Protection";
            case "1.3.6.1.5.5.7.3.8": return "Time Stamping";
            case "1.3.6.1.5.5.7.3.9": return "OCSP Signing";
            case "1.3.6.1.4.1.311.10.3.3": return "Microsoft Server Gated Crypto";
            case "2.16.840.1.113730.4.1": return "Netscape Server Gated Crypto";
            default: return "Unknown EKU";
        }
    }

    /**
     * Gets a human-readable name for a Subject Alternative Name type.
     *
     * @param type The SAN type integer
     * @return Human-readable SAN type name
     */
    private String getSubjectAltNameType(Integer type) {
        switch (type) {
            case SAN_OTHER_NAME: return "Other Name";
            case SAN_RFC822_NAME: return "RFC 822 Name (Email)";
            case SAN_DNS_NAME: return "DNS Name";
            case SAN_X400_ADDRESS: return "X.400 Address";
            case SAN_DIRECTORY_NAME: return "Directory Name";
            case SAN_EDI_PARTY_NAME: return "EDI Party Name";
            case SAN_URI: return "URI";
            case SAN_IP_ADDRESS: return "IP Address";
            case SAN_REGISTERED_ID: return "Registered ID";
            default: return "Unknown Type (" + type + ")";
        }
    }

    /**
     * Converts a byte array to a hexadecimal string.
     *
     * @param bytes The byte array to convert
     * @return Hexadecimal string representation
     */
    private String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
            if (result.length() % HEX_CHARS_PER_LINE == 0) {
                result.append("\n    ");
            } else if (result.length() % HEX_SPACING == 0) {
                result.append(" ");
            }
        }
        return result.toString().trim();
    }

    /**
     * Main method for testing the CertificateManager functionality.
     *
     * @param args Command line arguments
     */
    public static void main(String[] args) {
        CertificateAnalyzer manager = new CertificateAnalyzer();

        try {
            if (args.length == 0) {
                // Default behavior - inspect certificates from classpath resources
                LOGGER.info("Inspecting server certificate from classpath resource...");
                manager.inspectCertificateFromKeystoreResource("server.jks", "changeit", "server");

                LOGGER.info("\n" + "=".repeat(SEPARATOR_LENGTH) + "\n");

                LOGGER.info("Inspecting client certificate from classpath resource...");
                manager.inspectCertificateFromKeystoreResource("client.jks", "changeit", "client");

            } else if (args.length >= 2) {
                String keystorePath = args[0];
                String password = args[1];
                String alias = args.length > 2 ? args[2] : null;

                LOGGER.info("Inspecting certificate(s) from: " + keystorePath);
                manager.inspectCertificateFromKeystore(keystorePath, password, alias);

            } else {
                LOGGER.info("Usage:");
                LOGGER.info("  java CertificateAnalyzer                              "
                        + "- Inspect default keystores from classpath");
                LOGGER.info("  java CertificateAnalyzer <keystore> <password>       "
                        + "- Inspect all certs in keystore file");
                LOGGER.info("  java CertificateAnalyzer <keystore> <password> <alias> "
                        + "- Inspect specific cert from keystore file");
            }

        } catch (java.security.GeneralSecurityException | java.io.IOException e) {
            System.err.println("Error inspecting certificate: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
