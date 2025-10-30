package com.github.tls;

import java.security.cert.X509Certificate;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for CertificateAnalyzer class.
 */
@ExtendWith(MockitoExtension.class)
class CertificateAnalyzerTest {

    private static final int X509_VERSION_3 = 3;

    private CertificateAnalyzer certificateAnalyzer;

    @BeforeEach
    void setUp() {
        certificateAnalyzer = new CertificateAnalyzer();
    }

    /**
     * Test CertificateAnalyzer constructor.
     */
    @Test
    void testCertificateAnalyzerConstructor() {
        assertNotNull(certificateAnalyzer);
        assertTrue(certificateAnalyzer instanceof CertificateAnalyzer);
    }

    /**
     * Test inspectCommonExtensions with null certificate.
     */
    @Test
    void testInspectCommonExtensionsWithNullCertificate() {
        assertDoesNotThrow(() -> {
            certificateAnalyzer.inspectCommonExtensions(null);
        });
    }

    /**
     * Test inspectCommonExtensions with mock certificate.
     */
    @Test
    void testInspectCommonExtensionsWithMockCertificate() {
        X509Certificate mockCert = mock(X509Certificate.class);
        when(mockCert.getVersion()).thenReturn(X509_VERSION_3);

        assertDoesNotThrow(() -> {
            certificateAnalyzer.inspectCommonExtensions(mockCert);
        });
    }

    /**
     * Test CertificateAnalyzer class structure.
     */
    @Test
    void testCertificateAnalyzerClassStructure() {
        // Verify that CertificateAnalyzer has the required methods
        assertDoesNotThrow(() -> {
            CertificateAnalyzer.class.getDeclaredMethod("inspectCommonExtensions", X509Certificate.class);
        });
    }

    /**
     * Test CertificateAnalyzer package and class accessibility.
     */
    @Test
    void testCertificateAnalyzerPackageAndAccess() {
        assertEquals("com.github.tls", CertificateAnalyzer.class.getPackage().getName());
        assertTrue(java.lang.reflect.Modifier.isPublic(CertificateAnalyzer.class.getModifiers()));
    }

    /**
     * Test multiple CertificateAnalyzer instances.
     */
    @Test
    void testMultipleCertificateAnalyzerInstances() {
        CertificateAnalyzer analyzer1 = new CertificateAnalyzer();
        CertificateAnalyzer analyzer2 = new CertificateAnalyzer();

        assertNotNull(analyzer1);
        assertNotNull(analyzer2);
        assertNotSame(analyzer1, analyzer2);
    }

    /**
     * Test CertificateAnalyzer constants and static elements.
     */
    @Test
    void testCertificateAnalyzerConstants() {
        // Test that the CertificateAnalyzer class has proper structure
        assertNotNull(CertificateAnalyzer.class);
        assertEquals("CertificateAnalyzer", CertificateAnalyzer.class.getSimpleName());
    }

    /**
     * Test that CertificateAnalyzer can handle various certificate types.
     */
    @Test
    void testCertificateAnalyzerWithDifferentCertificateVersions() {
        // Test with version 1 certificate
        X509Certificate mockCertV1 = mock(X509Certificate.class);
        when(mockCertV1.getVersion()).thenReturn(1);

        assertDoesNotThrow(() -> {
            certificateAnalyzer.inspectCommonExtensions(mockCertV1);
        });

        // Test with version 3 certificate
        X509Certificate mockCertV3 = mock(X509Certificate.class);
        when(mockCertV3.getVersion()).thenReturn(X509_VERSION_3);

        assertDoesNotThrow(() -> {
            certificateAnalyzer.inspectCommonExtensions(mockCertV3);
        });
    }
}
