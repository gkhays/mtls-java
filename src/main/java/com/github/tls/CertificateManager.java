package com.github.tls;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;
import java.util.Set;

/**
 * CertificateManager provides utilities for inspecting X.509 certificates
 * and extracting their v3 extension properties.
 */
public class CertificateManager {

    /** Minimum version for X.509 v3 certificates. */
    private static final int X509_V3_MINIMUM_VERSION = 3;
    /** Maximum path length constraint value. */
    private static final int MAX_PATH_LENGTH = Integer.MAX_VALUE;
    /** Number of key usage types. */
    private static final int KEY_USAGE_COUNT = 9;
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
                System.out.println("=== Certificate: " + alias + " ===");
                inspectX509Certificate((X509Certificate) cert);
            } else {
                System.out.println("Certificate with alias '" + alias
                        + "' is not an X.509 certificate or does not exist.");
            }
        } else {
            // Inspect all certificates in the keystore
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String currentAlias = aliases.nextElement();
                Certificate cert = keyStore.getCertificate(currentAlias);
                if (cert instanceof X509Certificate) {
                    System.out.println("=== Certificate: " + currentAlias + " ===");
                    inspectX509Certificate((X509Certificate) cert);
                    System.out.println();
                }
            }
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
                    System.out.println("=== Certificate " + (++count) + " ===");
                    inspectX509Certificate((X509Certificate) cert);
                    System.out.println();
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
        System.out.println("Subject: " + cert.getSubjectX500Principal());
        System.out.println("Issuer: " + cert.getIssuerX500Principal());
        System.out.println("Serial Number: " + cert.getSerialNumber());
        System.out.println("Valid From: " + cert.getNotBefore());
        System.out.println("Valid Until: " + cert.getNotAfter());
        System.out.println("Version: " + cert.getVersion());
        System.out.println("Signature Algorithm: " + cert.getSigAlgName());

        // Check if this is a v3 certificate (version 3)
        if (cert.getVersion() >= X509_V3_MINIMUM_VERSION) {
            System.out.println("\n--- X.509 v3 Extensions ---");

            Set<String> criticalExtensions = cert.getCriticalExtensionOIDs();
            Set<String> nonCriticalExtensions = cert.getNonCriticalExtensionOIDs();

            if (criticalExtensions != null && !criticalExtensions.isEmpty()) {
                System.out.println("\nCritical Extensions:");
                for (String oid : criticalExtensions) {
                    inspectExtension(cert, oid, true);
                }
            }

            if (nonCriticalExtensions != null && !nonCriticalExtensions.isEmpty()) {
                System.out.println("\nNon-Critical Extensions:");
                for (String oid : nonCriticalExtensions) {
                    inspectExtension(cert, oid, false);
                }
            }

            // Inspect common extensions with specific methods
            inspectCommonExtensions(cert);
        } else {
            System.out.println("\nThis is not a v3 certificate. No extensions available.");
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

        System.out.println("  " + extensionName + " (" + oid + ")");
        System.out.println("    Critical: " + isCritical);
        System.out.println("    Length: " + (extensionValue != null ? extensionValue.length : 0) + " bytes");

        if (extensionValue != null && extensionValue.length > 0) {
            System.out.println("    Raw Value: " + bytesToHex(extensionValue));
        }
    }

    /**
     * Inspects common X.509 v3 extensions with human-readable output.
     *
     * @param cert The X.509 certificate
     */
    public void inspectCommonExtensions(X509Certificate cert) {
        if (cert == null) {
            System.out.println("\n--- Common Extensions (Parsed) ---");
            System.out.println("Error: Certificate is null");
            return;
        }

        System.out.println("\n--- Common Extensions (Parsed) ---");

        // Basic Constraints
        int basicConstraints = cert.getBasicConstraints();
        if (basicConstraints != -1) {
            System.out.println("Basic Constraints:");
            System.out.println("  CA: true");
            System.out.println("  Path Length: " + (basicConstraints == MAX_PATH_LENGTH
                    ? "unlimited" : basicConstraints));
        } else {
            System.out.println("Basic Constraints: CA: false");
        }

        // Key Usage
        boolean[] keyUsage = cert.getKeyUsage();
        if (keyUsage != null) {
            System.out.println("Key Usage:");
            String[] keyUsageNames = {
                "Digital Signature", "Non Repudiation", "Key Encipherment", "Data Encipherment",
                "Key Agreement", "Key Cert Sign", "CRL Sign", "Encipher Only", "Decipher Only"
            };

            for (int i = 0; i < Math.min(keyUsage.length, keyUsageNames.length); i++) {
                if (keyUsage[i]) {
                    System.out.println("  " + keyUsageNames[i]);
                }
            }
        }

        // Extended Key Usage
        try {
            List<String> extendedKeyUsage = cert.getExtendedKeyUsage();
            if (extendedKeyUsage != null && !extendedKeyUsage.isEmpty()) {
                System.out.println("Extended Key Usage:");
                for (String eku : extendedKeyUsage) {
                    System.out.println("  " + getExtendedKeyUsageName(eku) + " (" + eku + ")");
                }
            }
        } catch (CertificateException e) {
            System.out.println("Extended Key Usage: Error parsing - " + e.getMessage());
        }

        // Subject Alternative Names
        try {
            Collection<List<?>> subjectAltNames = cert.getSubjectAlternativeNames();
            if (subjectAltNames != null && !subjectAltNames.isEmpty()) {
                System.out.println("Subject Alternative Names:");
                for (List<?> san : subjectAltNames) {
                    if (san.size() >= 2) {
                        Integer type = (Integer) san.get(0);
                        Object value = san.get(1);
                        System.out.println("  " + getSubjectAltNameType(type) + ": " + value);
                    }
                }
            }
        } catch (CertificateException e) {
            System.out.println("Subject Alternative Names: Error parsing - " + e.getMessage());
        }

        // Issuer Alternative Names
        try {
            Collection<List<?>> issuerAltNames = cert.getIssuerAlternativeNames();
            if (issuerAltNames != null && !issuerAltNames.isEmpty()) {
                System.out.println("Issuer Alternative Names:");
                for (List<?> ian : issuerAltNames) {
                    if (ian.size() >= 2) {
                        Integer type = (Integer) ian.get(0);
                        Object value = ian.get(1);
                        System.out.println("  " + getSubjectAltNameType(type) + ": " + value);
                    }
                }
            }
        } catch (CertificateException e) {
            System.out.println("Issuer Alternative Names: Error parsing - " + e.getMessage());
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
        CertificateManager manager = new CertificateManager();

        try {
            if (args.length == 0) {
                // Default behavior - inspect certificates in the project's keystore
                System.out.println("Inspecting server certificate from default keystore...");
                manager.inspectCertificateFromKeystore("target/classes/server.jks", "changeit", "server");

                System.out.println("\n" + "=".repeat(SEPARATOR_LENGTH) + "\n");

                System.out.println("Inspecting client certificate from default keystore...");
                manager.inspectCertificateFromKeystore("target/classes/client.jks", "changeit", "client");

            } else if (args.length >= 2) {
                String keystorePath = args[0];
                String password = args[1];
                String alias = args.length > 2 ? args[2] : null;

                System.out.println("Inspecting certificate(s) from: " + keystorePath);
                manager.inspectCertificateFromKeystore(keystorePath, password, alias);

            } else {
                System.out.println("Usage:");
                System.out.println("  java CertificateManager                              "
                        + "- Inspect default keystores");
                System.out.println("  java CertificateManager <keystore> <password>       "
                        + "- Inspect all certs in keystore");
                System.out.println("  java CertificateManager <keystore> <password> <alias> "
                        + "- Inspect specific cert");
            }

        } catch (java.security.GeneralSecurityException | java.io.IOException e) {
            System.err.println("Error inspecting certificate: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
