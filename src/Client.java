import java.net.Socket;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

public abstract class Client {

    /* protected keyword is like private but subclasses have access
     * Socket and input/output streams
     */
    protected Socket sock;
    protected ObjectOutputStream output;
    protected ObjectInputStream input;
    protected UserToken token;

    public boolean connect(final String server, final int port) {
        System.out.println("Attempting to connect...");

        try {
            sock = new Socket(server, port);
            System.out.printf(
                "Connection succeeded in connecting to %s at port %d\n",
                server,
                port
            );

            output = new ObjectOutputStream(sock.getOutputStream());
            input = new ObjectInputStream(sock.getInputStream());

            return true;
        } catch(Exception e) {
            System.err.println("Unable to Connect");
            return false;
        }
    }

    public boolean isConnected() {
        if (sock == null || sock.isClosed()) {
            return false;
        } else {
            return true;
        }
    }

    public void disconnect() {
        if (isConnected()) {
            try {
                Envelope message = new Envelope("DISCONNECT");
                output.writeObject(message);

                sock.close();
                output.close();
                input.close();
            } catch(Exception e) {
                System.err.println("Error: " + e.getMessage());
                e.printStackTrace(System.err);
            }
        }
    }

    public boolean verify(String sign) {
        try {
            Envelope server_type = (Envelope)input.readObject();
            if (!server_type.getMessage().equals(sign)) {
                System.out.printf("Server is not a %s server\n", sign);
                disconnect();
                return false;
            }

            return true;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }
}
