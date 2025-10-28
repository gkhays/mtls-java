package com.github.tls;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;

/**
 * Handshake completion listener for SSL connections.
 */
class MyHandshakeListener implements HandshakeCompletedListener {

    @Override
    public void handshakeCompleted(HandshakeCompletedEvent e) {
        System.out.println("Handshake successful!");
        System.out.println("Using cipher suite: " + e.getCipherSuite());
    }
}
