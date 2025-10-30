package com.github.tls;

import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Handshake completion listener for SSL connections.
 */
class MyHandshakeListener implements HandshakeCompletedListener {

    private static final Logger LOGGER = LoggerFactory.getLogger(MyHandshakeListener.class);

    @Override
    public void handshakeCompleted(HandshakeCompletedEvent e) {
        LOGGER.info("Handshake successful!");
        LOGGER.info("Using cipher suite: {}", e.getCipherSuite());
    }
}
