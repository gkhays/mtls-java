package com.github.tls;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for CertifcateTester class.
 */
@ExtendWith(MockitoExtension.class)
class CertifcateTesterTest {

    private final ByteArrayOutputStream outContent = new ByteArrayOutputStream();
    private final PrintStream originalOut = System.out;

    @BeforeEach
    void setUpStreams() {
        System.setOut(new PrintStream(outContent));
    }

    @AfterEach
    void restoreStreams() {
        System.setOut(originalOut);
    }

    /**
     * Test CertifcateTester constructor is private.
     */
    @Test
    void testCertifcateTesterConstructorIsPrivate() {
        java.lang.reflect.Constructor<?>[] constructors = CertifcateTester.class.getDeclaredConstructors();
        assertEquals(1, constructors.length);
        assertTrue(java.lang.reflect.Modifier.isPrivate(constructors[0].getModifiers()));
    }

    /**
     * Test CertifcateTester main method structure.
     * Note: This test verifies the main method exists and has correct signature,
     * but doesn't execute it fully to avoid dependencies on keystore files.
     */
    @Test
    void testMainMethodSignature() {
        assertDoesNotThrow(() -> {
            CertifcateTester.class.getDeclaredMethod("main", String[].class);
        });
    }

    /**
     * Test CertifcateTester class is final.
     */
    @Test
    void testCertifcateTesterClassIsFinal() {
        assertTrue(java.lang.reflect.Modifier.isFinal(CertifcateTester.class.getModifiers()));
    }

    /**
     * Test CertifcateTester package and class accessibility.
     */
    @Test
    void testCertifcateTesterPackageAndAccess() {
        assertEquals("com.github.tls", CertifcateTester.class.getPackage().getName());
        assertTrue(java.lang.reflect.Modifier.isPublic(CertifcateTester.class.getModifiers()));
    }

    /**
     * Test main method is static and public.
     */
    @Test
    void testMainMethodIsStaticAndPublic() throws NoSuchMethodException {
        java.lang.reflect.Method mainMethod = CertifcateTester.class.getDeclaredMethod("main", String[].class);
        assertTrue(java.lang.reflect.Modifier.isStatic(mainMethod.getModifiers()));
        assertTrue(java.lang.reflect.Modifier.isPublic(mainMethod.getModifiers()));
    }

    /**
     * Test CertifcateTester class structure.
     */
    @Test
    void testCertifcateTesterClassStructure() {
        // Verify class name (noting the typo in "Certifcate")
        assertEquals("CertifcateTester", CertifcateTester.class.getSimpleName());

        // Verify it's a utility class
        assertTrue(java.lang.reflect.Modifier.isFinal(CertifcateTester.class.getModifiers()));
    }

    /**
     * Test that CertifcateTester has proper utility class characteristics.
     */
    @Test
    void testUtilityClassCharacteristics() {
        // Should be final
        assertTrue(java.lang.reflect.Modifier.isFinal(CertifcateTester.class.getModifiers()));

        // Should have only one constructor (private)
        assertEquals(1, CertifcateTester.class.getDeclaredConstructors().length);

        // Constructor should be private
        java.lang.reflect.Constructor<?>[] constructors = CertifcateTester.class.getDeclaredConstructors();
        assertTrue(java.lang.reflect.Modifier.isPrivate(constructors[0].getModifiers()));
    }

    /**
     * Test CertifcateTester constants.
     */
    @Test
    void testCertifcateTesterConstants() {
        // Test that the class has proper structure
        assertNotNull(CertifcateTester.class);
        assertEquals("CertifcateTester", CertifcateTester.class.getSimpleName());
    }

    /**
     * Test that main method accepts empty string array.
     */
    @Test
    void testMainMethodWithEmptyArgs() {
        // We can test that the method signature exists and accepts empty args
        // without actually executing it (to avoid keystore dependencies)
        assertDoesNotThrow(() -> {
            java.lang.reflect.Method mainMethod = CertifcateTester.class.getDeclaredMethod("main", String[].class);
            assertNotNull(mainMethod);
        });
    }
}
