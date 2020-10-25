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
import java.security.*;
import java.security.spec.*;

import javax.crypto.*;
import javax.crypto.spec.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public abstract class Client {

    /* protected keyword is like private but subclasses have access
     * Socket and input/output streams
     */
    protected Socket sock;
    protected ObjectOutputStream output;
    protected ObjectInputStream input;
    protected UserToken token;

    private SecureRandom secureRandom = null;
    private final int TAG_LENGTH_BIT = 128;

    protected SecretKeySpec k;
    protected byte[] IVk;

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

    public Key keyExchange(String username, String sign, KeyPair rsa_key) {
        try {
            Envelope message = new Envelope(username);
            KeyPairGenerator kpg;
            
            kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(256);
            KeyPair kp = kpg.generateKeyPair();
            byte[] ourPk = kp.getPublic().getEncoded();
            
            addSignature(message, ourPk, rsa_key);
            output.writeObject(message);

            message = (Envelope)input.readObject();
            if (!verify(message, sign)) {
                disconnect();
                return null;
            }

            String ecc_pub_key_str = (String)message.getObjContents().get(0);
            String ivEncoded = (String)message.getObjContents().get(3);
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

            // AES Test
            byte[] iv = Base64.getDecoder().decode(ivEncoded);
            IvParameterSpec ivParams = new IvParameterSpec(iv);


            byte[] test = "AES Test String".getBytes("UTF-8");
            SecretKeySpec aesSpec = new SecretKeySpec(derivedKey, "AES");
            Cipher aes = Cipher.getInstance("AES/CBC/PKCS7Padding");
            aes.init(Cipher.ENCRYPT_MODE, aesSpec, ivParams);
            byte[] result = aes.doFinal(test);
            String resultEncoded = Base64.getEncoder().encodeToString(result);
            System.out.println("---------------------------------------");
            System.out.println("Result: " + resultEncoded);

        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

        return null;
    }

    private void addSignature(Envelope message, byte[] ourPk, KeyPair rsa_key) {
        byte[] rsaSign;
        byte[] rsaPubK;
        String encodedPk = Base64.getEncoder().encodeToString(ourPk);
        System.out.println("Public Key: " + encodedPk);

        try {
            Signature rsa_signature = Signature.getInstance("RSA");

            rsa_signature.initSign(rsa_key.getPrivate(), secureRandom);
            rsa_signature.update(ourPk);

            rsaSign = rsa_signature.sign();
            rsaPubK = rsa_key.getPublic().getEncoded();
        } catch(Exception e) {
            e.printStackTrace();
            return;
        }
        
        message.addObject(encodedPk);
        message.addObject(Base64.getEncoder().encodeToString(rsaSign));
        message.addObject(Base64.getEncoder().encodeToString(rsaPubK));
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

    private boolean verify(Envelope message, String server_type) {
        if (!message.getMessage().equals(server_type)) {
            System.out.printf("Server is not a %s server\n", server_type);
            return false;
        }

        ArrayList<Object> contents = message.getObjContents();
        if (contents.size() != 4) {
            System.out.println("Invalid establishing connection");
            return false;
        }

        // Extract the crypto values
        byte[] eccKey    = Base64.getDecoder().decode((String)contents.get(0));
        byte[] eccSign = Base64.getDecoder().decode((String)contents.get(1));
        byte[] publicKey = Base64.getDecoder().decode((String)contents.get(2));

        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec pkSpec = new X509EncodedKeySpec(publicKey);
            PublicKey serverPubKey = kf.generatePublic(pkSpec);

            Signature rsa_signature = Signature.getInstance("RSA");

            rsa_signature.initVerify(serverPubKey);
            rsa_signature.update(eccKey);

            boolean verified = rsa_signature.verify(eccSign);
            
            if (verified) {
                // Signature matches
                System.out.println("Success: Verified key");
                return true;
            } else {
                // Signature DOES NOT match
                System.out.println("Invalid session establishment (Unverified key)");
                return false;
            }
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }
}
