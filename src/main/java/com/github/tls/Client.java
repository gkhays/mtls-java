package com.github.tls;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

/**
 * SSL Client for mTLS communication.
 */
public class Client {

    /** Default SSL port for secure connections. */
    private static final int SSL_PORT = 8443;

    private SSLContext context;
    private SSLSocket socket;
    private PrintWriter writer;
    private BufferedReader reader;
    private boolean singleUseMode;

    /**
     * Constructor that initializes SSL context with client certificate and truststore.
     * @param password password for keystores
     */
    public Client(String password) {
        this(password, false);
    }

    /**
     * Constructor that initializes SSL context with client certificate and truststore.
     * @param password password for keystores
     * @param singleUseMode whether to expect serverAuth EKU in client certificate
     */
    public Client(String password, boolean singleUseMode) {
        this.singleUseMode = singleUseMode;
        KeyManagerFactory kmf;
        TrustManagerFactory tmf;
        try {
            kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());

            // Load client keystore with CA-signed client certificate for client authentication
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(getClass().getResourceAsStream("/client.jks"), password.toCharArray());
            System.out.println("Client keystore loaded successfully (CA-signed certificate)");
            kmf.init(keyStore, password.toCharArray());

            // Load truststore containing CA certificate to trust CA-signed server certificate
            KeyStore trustStore = KeyStore.getInstance("JKS");
            trustStore.load(getClass().getResourceAsStream("/truststore.jks"), password.toCharArray());
            System.out.println("Client truststore loaded successfully (contains CA certificate)");
            tmf.init(trustStore);

            context = SSLContext.getInstance("TLSv1.2");
            context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

            // Inspect the client certificate
            X509Certificate cert = (X509Certificate) keyStore.getCertificate("client");
            if (this.singleUseMode) {
                System.out.println("Single-use mode: Client certificate should have serverAuth EKU");
            }
            (new CertificateManager()).inspectCommonExtensions(cert);
        } catch (java.security.GeneralSecurityException | java.io.IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Connect to the SSL server.
     */
    public void connect() {
        try {
            socket = (SSLSocket) context.getSocketFactory().createSocket("localhost", SSL_PORT);
            socket.addHandshakeCompletedListener(new MyHandshakeListener());
            socket.setUseClientMode(true);
            socket.startHandshake();

            // Initialize the streams after successful handshake
            writer = new PrintWriter(socket.getOutputStream(), true);
            reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Send a string message to the server.
     * @param message The message to send
     */
    public void sendMessage(String message) {
        if (socket == null || socket.isClosed() || writer == null) {
            System.err.println("Socket is not connected. Call connect() first.");
            return;
        }

        try {
            // Send the message
            System.out.println("Sending message: " + message);
            writer.println(message);

            // Read the response from server
            String response = reader.readLine();
            if (response != null) {
                System.out.println("Server response: " + response);
            }

        } catch (IOException e) {
            System.err.println("Error sending message: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Send a simple "Hello World" message to the server.
     */
    public void sendHelloWorld() {
        sendMessage("Hello World from Java Client!");
    }

    /**
     * Close the socket connection.
     */
    public void close() {
        try {
            if (writer != null) {
                writer.close();
            }
            if (reader != null) {
                reader.close();
            }
            if (socket != null && !socket.isClosed()) {
                socket.close();
                System.out.println("Connection closed.");
            }
        } catch (IOException e) {
            System.err.println("Error closing connection: " + e.getMessage());
        }
    }
}
