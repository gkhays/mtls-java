package com.github.tls;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * SSL Server for mTLS communication.
 */
public class Server implements Runnable {

    private static final Logger LOGGER = LoggerFactory.getLogger(Server.class);

    /** Default SSL port for secure connections. */
    private static final int SSL_PORT = 8443;

    private KeyStore keyStore;
    private SSLContext context;
    private SSLServerSocket serverSocket;

    /**
     * Constructor that initializes SSL context and server socket.
     * @param password password for keystores
     */
    public Server(String password) {
        KeyManagerFactory kmf;
        TrustManagerFactory tmf;
        try {
            kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());

            // Load server keystore with CA-signed server certificate
            keyStore = KeyStore.getInstance("JKS");
            keyStore.load(getClass().getResourceAsStream("/server.jks"), password.toCharArray());
            LOGGER.info("Server keystore loaded successfully (CA-signed certificate)");
            kmf.init(keyStore, password.toCharArray());

            // Load truststore containing CA certificate to trust CA-signed certificates
            KeyStore trustStore = KeyStore.getInstance("JKS");
            trustStore.load(getClass().getResourceAsStream("/truststore.jks"), "changeit".toCharArray());
            LOGGER.info("Server truststore loaded successfully (contains CA certificate)");
            tmf.init(trustStore);

            context = SSLContext.getInstance("TLSv1.2");
            context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

            // Debug: List all aliases in the keystore
            LOGGER.debug("Available aliases in keystore:");
            java.util.Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                LOGGER.debug("  - {}", alias);
            }

            X509Certificate cert = (X509Certificate) keyStore.getCertificate("server");
            if (cert != null) {
                (new CertificateAnalyzer()).inspectCommonExtensions(cert);
            } else {
                LOGGER.warn("Warning: Certificate with alias 'server' not found in keystore");
            }

            SSLServerSocketFactory factory = context.getServerSocketFactory();
            serverSocket = (SSLServerSocket) factory.createServerSocket(SSL_PORT);

            // Enable client authentication for mTLS
            serverSocket.setWantClientAuth(true);
            serverSocket.setNeedClientAuth(true);

            TLSCompatibilityAnalyzer viewer = new TLSCompatibilityAnalyzer(keyStore, context);
            LOGGER.info("=== TLS Compatibility Analyzer Information ===");
            viewer.displayTLSInfo();
            viewer.displayCertificates();
        } catch (java.security.GeneralSecurityException | java.io.IOException e) {
            LOGGER.error("Error initializing server", e);
        }
    }

    @Override
    public void run() {
        try {
            while (true) {
                LOGGER.info("Server is waiting for connection...");
                Socket socket = serverSocket.accept();
                LOGGER.info("Client connected: {}", socket.getInetAddress());

                handleClientConnection(socket);
            }
        } catch (java.io.IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Handle client connection and communication.
     * @param socket the client socket
     */
    private void handleClientConnection(Socket socket) {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
             PrintWriter writer = new PrintWriter(socket.getOutputStream(), true)) {

            String line;
            while ((line = reader.readLine()) != null) {
                LOGGER.info("Received: {}", line);

                if ("quit".equalsIgnoreCase(line) || "exit".equalsIgnoreCase(line)) {
                    LOGGER.info("Client requested to close connection");
                    writer.println("Goodbye!");
                    break;
                }

                // Echo the message back to client
                writer.println("Echo: " + line);
            }
        } catch (IOException e) {
            LOGGER.error("Error handling client connection: {}", e.getMessage());
        } finally {
            try {
                socket.close();
            } catch (IOException e) {
                LOGGER.error("Error closing socket: {}", e.getMessage());
            }
        }
    }

}
