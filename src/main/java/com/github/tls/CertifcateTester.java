package com.github.tls;

import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Comprehensive certificate utility that combines demo functionality with direct certificate testing.
 * This utility provides both high-level keystore inspection and low-level certificate extension analysis.
 */
public final class CertifcateTester {

    private static final Logger LOGGER = LoggerFactory.getLogger(CertifcateTester.class);

    /** Length of separator line for visual formatting. */
    private static final int SEPARATOR_LENGTH = 80;

    /**
     * Private constructor to prevent instantiation of utility class.
     */
    private CertifcateTester() {
        // Utility class
    }

    /**
     * Main method to demonstrate comprehensive certificate inspection.
     * Combines both high-level keystore inspection and direct certificate testing.
     * @param args command line arguments
     */
    public static void main(String[] args) {
        LOGGER.info("=== mTLS Certificate Inspector & Direct Test Utility ===\n");

        // Part 1: Original demo functionality
        runKeystoreTest();

        LOGGER.info("\n" + "=".repeat(SEPARATOR_LENGTH));
        LOGGER.info("=".repeat(SEPARATOR_LENGTH) + "\n");

        // Part 2: Direct certificate testing functionality
        runDirectCertificateTests();

        LOGGER.info("\n✅ Complete certificate inspection and testing finished!");
        LOGGER.info("\nℹ️  This utility provides comprehensive certificate analysis including:");
        LOGGER.info("   • High-level keystore inspection with detailed output");
        LOGGER.info("   • Direct certificate extension testing from embedded resources");
        LOGGER.info("   • X.509 v3 extension analysis for security properties");
    }

    /**
     * Runs the original keystore demo functionality.
     */
    private static void runKeystoreTest() {
        LOGGER.info("🔍 PART 1: KEYSTORE TEST INSPECTION");
        LOGGER.info("=".repeat(SEPARATOR_LENGTH));

        CertificateAnalyzer manager = new CertificateAnalyzer();

        try {
            LOGGER.info("📜 Inspecting mTLS certificates used by the application...\n");

            // Inspect server certificate
            LOGGER.info("🔒 SERVER CERTIFICATE:");
            LOGGER.info("─".repeat(SEPARATOR_LENGTH));
            manager.inspectCertificateFromKeystore("target/classes/server.jks", "changeit", "server");

            LOGGER.info("\n\n👤 CLIENT CERTIFICATE:");
            LOGGER.info("─".repeat(SEPARATOR_LENGTH));
            manager.inspectCertificateFromKeystore("target/classes/client.jks", "changeit", "client");

            LOGGER.info("\n\n🏛️ TRUSTSTORE (CA Certificates):");
            LOGGER.info("─".repeat(SEPARATOR_LENGTH));
            manager.inspectCertificateFromKeystore("target/classes/truststore.jks", "changeit", null);

        } catch (java.security.GeneralSecurityException | java.io.IOException e) {
            LOGGER.error("❌ Error inspecting certificates: {}", e.getMessage(), e);
        }
    }

    /**
     * Runs direct certificate testing from embedded resources.
     */
    private static void runDirectCertificateTests() {
        LOGGER.info("🧪 PART 2: DIRECT CERTIFICATE EXTENSION TESTING");
        LOGGER.info("=".repeat(SEPARATOR_LENGTH));

        // Test client keystore directly from resources
        try {
            LOGGER.info("Testing CLIENT keystore from embedded resources:");
            KeyStore clientKeyStore = KeyStore.getInstance("JKS");
            clientKeyStore.load(
                CertifcateTester.class.getResourceAsStream("/client.jks"),
                "changeit".toCharArray()
            );

            Certificate clientCert = clientKeyStore.getCertificate("server");
            if (clientCert instanceof X509Certificate) {
                LOGGER.info("=== Client Certificate v3 Extensions ===");
                CertificateAnalyzer manager = new CertificateAnalyzer();
                manager.inspectCommonExtensions((X509Certificate) clientCert);
            } else {
                LOGGER.warn("Client certificate is not X.509 or not found");
            }

        } catch (java.security.GeneralSecurityException | java.io.IOException e) {
            LOGGER.error("Error with client keystore: {}", e.getMessage(), e);
        }

        LOGGER.info("\n" + "=".repeat(SEPARATOR_LENGTH) + "\n");

        // Test server keystore directly from resources
        try {
            LOGGER.info("Testing SERVER keystore from embedded resources:");
            KeyStore serverKeyStore = KeyStore.getInstance("JKS");
            serverKeyStore.load(
                CertifcateTester.class.getResourceAsStream("/server.jks"),
                "changeit".toCharArray()
            );

            Certificate serverCert = serverKeyStore.getCertificate("server");
            if (serverCert instanceof X509Certificate) {
                LOGGER.info("=== Server Certificate v3 Extensions ===");
                CertificateAnalyzer manager = new CertificateAnalyzer();
                manager.inspectCommonExtensions((X509Certificate) serverCert);
            } else {
                LOGGER.warn("Server certificate is not X.509 or not found");
            }

        } catch (java.security.GeneralSecurityException | java.io.IOException e) {
            LOGGER.error("Error with server keystore: {}", e.getMessage(), e);
        }
    }
}
