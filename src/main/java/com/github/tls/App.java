package com.github.tls;

/**
 * Hello world!
 */
public final class App {

    /** Server startup delay in milliseconds. */
    private static final int SERVER_STARTUP_DELAY = 2000;

    private App() {
    }

    /**
     * Starts a server thread and demonstrates client communication.
     * @param args The arguments of the program. Supports -single-use flag.
     */
    public static void main(String[] args) {
        System.out.println("Starting mTLS Server Application...");

        // Parse command line arguments
        boolean singleUseMode = false;
        for (String arg : args) {
            if ("-single-use".equals(arg)) {
                singleUseMode = true;
                System.out.println("Single-use mode enabled - using serverAuth EKU in client certificate");
                break;
            }
        }

        try {
            // Create a server instance
            Server server = new Server("changeit");

            // Start the server in a new thread
            Thread serverThread = new Thread(server, "mTLS-Server");
            serverThread.setDaemon(true);  // Allow program to exit when main thread ends
            serverThread.start();

            System.out.println("Server thread started.");

            // Give the server a moment to start up
            Thread.sleep(SERVER_STARTUP_DELAY);

            // Create and use a client to send messages
            System.out.println("\nStarting client communication...");
            Client client = new Client("changeit", singleUseMode);
            client.connect();

            // Send some messages to the server
            client.sendHelloWorld();
            client.sendMessage("This is a test message from the client!");
            client.sendMessage("Testing mTLS communication...");

            // Send quit message to close connection gracefully
            client.sendMessage("quit");

            // Close the client connection
            client.close();

            System.out.println("\nClient communication completed. Press Ctrl+C to stop the server.");

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            System.err.println("Application interrupted: " + e.getMessage());
        }
    }

}
