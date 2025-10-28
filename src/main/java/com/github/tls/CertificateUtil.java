package com.github.tls;

import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

/**
 * Comprehensive certificate utility that combines demo functionality with direct certificate testing.
 * This utility provides both high-level keystore inspection and low-level certificate extension analysis.
 */
public final class CertificateUtil {

    /** Length of separator line for visual formatting. */
    private static final int SEPARATOR_LENGTH = 80;

    /**
     * Private constructor to prevent instantiation of utility class.
     */
    private CertificateUtil() {
        // Utility class
    }

    /**
     * Main method to demonstrate comprehensive certificate inspection.
     * Combines both high-level keystore inspection and direct certificate testing.
     * @param args command line arguments
     */
    public static void main(String[] args) {
        System.out.println("=== mTLS Certificate Inspector & Direct Test Utility ===\n");

        // Part 1: Original demo functionality
        runKeystoreDemo();

        System.out.println("\n" + "=".repeat(SEPARATOR_LENGTH));
        System.out.println("=".repeat(SEPARATOR_LENGTH) + "\n");

        // Part 2: Direct certificate testing functionality
        runDirectCertificateTests();

        System.out.println("\n✅ Complete certificate inspection and testing finished!");
        System.out.println("\nℹ️  This utility provides comprehensive certificate analysis including:");
        System.out.println("   • High-level keystore inspection with detailed output");
        System.out.println("   • Direct certificate extension testing from embedded resources");
        System.out.println("   • X.509 v3 extension analysis for security properties");
    }

    /**
     * Runs the original keystore demo functionality.
     */
    private static void runKeystoreDemo() {
        System.out.println("🔍 PART 1: KEYSTORE DEMO INSPECTION");
        System.out.println("=".repeat(SEPARATOR_LENGTH));

        CertificateManager manager = new CertificateManager();

        try {
            System.out.println("📜 Inspecting mTLS certificates used by the application...\n");

            // Inspect server certificate
            System.out.println("🔒 SERVER CERTIFICATE:");
            System.out.println("─".repeat(SEPARATOR_LENGTH));
            manager.inspectCertificateFromKeystore("target/classes/server.jks", "changeit", "server");

            System.out.println("\n\n👤 CLIENT CERTIFICATE:");
            System.out.println("─".repeat(SEPARATOR_LENGTH));
            manager.inspectCertificateFromKeystore("target/classes/client.jks", "changeit", "client");

            System.out.println("\n\n🏛️ TRUSTSTORE (CA Certificates):");
            System.out.println("─".repeat(SEPARATOR_LENGTH));
            manager.inspectCertificateFromKeystore("target/classes/truststore.jks", "changeit", null);

        } catch (java.security.GeneralSecurityException | java.io.IOException e) {
            System.err.println("❌ Error inspecting certificates: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Runs direct certificate testing from embedded resources.
     */
    private static void runDirectCertificateTests() {
        System.out.println("🧪 PART 2: DIRECT CERTIFICATE EXTENSION TESTING");
        System.out.println("=".repeat(SEPARATOR_LENGTH));

        // Test client keystore directly from resources
        try {
            System.out.println("Testing CLIENT keystore from embedded resources:");
            KeyStore clientKeyStore = KeyStore.getInstance("JKS");
            clientKeyStore.load(
                CertificateUtil.class.getResourceAsStream("/com/github/tls/resources/client.jks"),
                "changeit".toCharArray()
            );

            Certificate clientCert = clientKeyStore.getCertificate("server");
            if (clientCert instanceof X509Certificate) {
                System.out.println("=== Client Certificate v3 Extensions ===");
                CertificateManager manager = new CertificateManager();
                manager.inspectCommonExtensions((X509Certificate) clientCert);
            } else {
                System.out.println("Client certificate is not X.509 or not found");
            }

        } catch (java.security.GeneralSecurityException | java.io.IOException e) {
            System.err.println("Error with client keystore: " + e.getMessage());
            e.printStackTrace();
        }

        System.out.println("\n" + "=".repeat(SEPARATOR_LENGTH) + "\n");

        // Test server keystore directly from resources
        try {
            System.out.println("Testing SERVER keystore from embedded resources:");
            KeyStore serverKeyStore = KeyStore.getInstance("JKS");
            serverKeyStore.load(
                CertificateUtil.class.getResourceAsStream("/com/github/tls/resources/server.jks"),
                "changeit".toCharArray()
            );

            Certificate serverCert = serverKeyStore.getCertificate("server");
            if (serverCert instanceof X509Certificate) {
                System.out.println("=== Server Certificate v3 Extensions ===");
                CertificateManager manager = new CertificateManager();
                manager.inspectCommonExtensions((X509Certificate) serverCert);
            } else {
                System.out.println("Server certificate is not X.509 or not found");
            }

        } catch (java.security.GeneralSecurityException | java.io.IOException e) {
            System.err.println("Error with server keystore: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
