import java.net.Socket;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.List;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Base64;
import java.nio.ByteBuffer;

// Crypto Libraries
import org.bouncycastle.*;
import org.bouncycastle.jce.provider.*;
import org.bouncycastle.jce.*;
import java.security.*;
import java.security.spec.ECParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.interfaces.ECPublicKey;

import javax.crypto.KeyAgreement;

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

    public KeyPair generateRSA() {
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator keyPair;
        
        try {
            keyPair = KeyPairGenerator.getInstance("RSA");
        } catch(Exception e) {
            e.printStackTrace();
            return null;
        }

        keyPair.initialize(2048);

        return keyPair.generateKeyPair();
    }
    
    public Key keyExchange(String username, String sign) {
        try {
            Envelope message = new Envelope(username);
            KeyPairGenerator kpg;
            
            kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(256);
            KeyPair kp = kpg.generateKeyPair();
            byte[] ourPk = kp.getPublic().getEncoded();
            
            String encodedPk = Base64.getEncoder().encodeToString(ourPk);
            System.out.println("Public Key: " + encodedPk);

            message.addObject(encodedPk);
            output.writeObject(message);

            message = (Envelope)input.readObject();
            if (!message.getMessage().equals(sign)) {
                System.out.printf("Server is not a %s server\n", sign);
                disconnect();
                return null;
            }

            String ecc_pub_key_str = (String)message.getObjContents().get(0);
            System.out.println("ECC Public Key: " + ecc_pub_key_str);

            byte[] ecc_pub_key = Base64.getDecoder().decode(ecc_pub_key_str);

            KeyFactory kf = KeyFactory.getInstance("EC");
            X509EncodedKeySpec pkSpec = new X509EncodedKeySpec(ecc_pub_key);
            PublicKey otherPublicKey = kf.generatePublic(pkSpec);

            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(kp.getPrivate());
            ka.doPhase(otherPublicKey, true);

            byte[] sharedSecret = ka.generateSecret();
            System.out.println("Shared Secret: " + Base64.getEncoder().encodeToString(sharedSecret));
            
            MessageDigest hash = MessageDigest.getInstance("SHA-256");
            hash.update(sharedSecret);

            List<ByteBuffer> keys = Arrays.asList(ByteBuffer.wrap(ourPk), ByteBuffer.wrap(ecc_pub_key));
            Collections.sort(keys);
            hash.update(keys.get(0));
            hash.update(keys.get(1)); 

            byte[] derivedKey = hash.digest();
            System.out.println("derived key: " + Base64.getEncoder().encodeToString(derivedKey));
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

        return null;
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
