package com.github.tls;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for MyHandshakeListener class.
 */
@ExtendWith(MockitoExtension.class)
class MyHandshakeListenerTest {

    @Mock
    private HandshakeCompletedEvent mockEvent;

    private MyHandshakeListener listener;

    @BeforeEach
    void setUp() {
        listener = new MyHandshakeListener();
    }

    /**
     * Test MyHandshakeListener constructor.
     */
    @Test
    void testMyHandshakeListenerConstructor() {
        assertNotNull(listener);
        assertTrue(listener instanceof HandshakeCompletedListener);
    }

    /**
    }

    /**
     * Test handshakeCompleted method.
     */
    @Test
    void testHandshakeCompleted() {
        when(mockEvent.getCipherSuite()).thenReturn("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");

        assertDoesNotThrow(() -> {
            listener.handshakeCompleted(mockEvent);
        });

        verify(mockEvent).getCipherSuite();
    }

    /**
     * Test handshakeCompleted with null event.
     */
    @Test
    void testHandshakeCompletedWithNullEvent() {
        assertThrows(NullPointerException.class, () -> {
            listener.handshakeCompleted(null);
        });
    }

    /**
     * Test handshakeCompleted with different cipher suites.
     */
    @Test
    void testHandshakeCompletedWithDifferentCipherSuites() {
        String[] cipherSuites = {
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_RSA_WITH_AES_256_CBC_SHA256"
        };

        for (String cipherSuite : cipherSuites) {
            when(mockEvent.getCipherSuite()).thenReturn(cipherSuite);

            assertDoesNotThrow(() -> {
                listener.handshakeCompleted(mockEvent);
            });
        }

        verify(mockEvent, times(cipherSuites.length)).getCipherSuite();
    }

    /**
     * Test that MyHandshakeListener implements HandshakeCompletedListener.
     */
    @Test
    void testMyHandshakeListenerImplementsInterface() {
        assertTrue(HandshakeCompletedListener.class.isAssignableFrom(MyHandshakeListener.class));
    }

    /**
     * Test MyHandshakeListener package and class accessibility.
     */
    @Test
    void testMyHandshakeListenerPackageAndAccess() {
        assertEquals("com.github.tls", MyHandshakeListener.class.getPackage().getName());
        // Note: MyHandshakeListener has package-private access (not public)
        assertFalse(java.lang.reflect.Modifier.isPublic(MyHandshakeListener.class.getModifiers()));
    }

    /**
     * Test handshakeCompleted method signature.
     */
    @Test
    void testHandshakeCompletedMethodSignature() {
        assertDoesNotThrow(() -> {
            MyHandshakeListener.class.getDeclaredMethod("handshakeCompleted", HandshakeCompletedEvent.class);
        });
    }

    /**
     * Test multiple listener instances.
     */
    @Test
    void testMultipleListenerInstances() {
        MyHandshakeListener listener1 = new MyHandshakeListener();
        MyHandshakeListener listener2 = new MyHandshakeListener();

        assertNotNull(listener1);
        assertNotNull(listener2);
        assertNotSame(listener1, listener2);
    }

    /**
     * Test handshakeCompleted with empty cipher suite.
     */
    @Test
    void testHandshakeCompletedWithEmptyCipherSuite() {
        when(mockEvent.getCipherSuite()).thenReturn("");

        assertDoesNotThrow(() -> {
            listener.handshakeCompleted(mockEvent);
        });

        verify(mockEvent).getCipherSuite();
    }
}
