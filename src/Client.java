import java.net.Socket;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
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
    protected EncryptedObjectOutputStream output;
    protected EncryptedObjectInputStream input;
    protected UserToken token;

    private SecureRandom secureRandom = null;
    private final int TAG_LENGTH_BIT = 128;

    protected SecretKeySpec k;
    protected byte[] IVk;
    protected PublicKeyList publicKeyList = null;

    public boolean connect(final String server, final int port) {
        System.out.println("Attempting to connect...");

        try {
            sock = new Socket(server, port);
            System.out.printf(
                "Connection succeeded in connecting to %s at port %d\n",
                server,
                port
            );

            output = new EncryptedObjectOutputStream(sock.getOutputStream());
            input = new EncryptedObjectInputStream(sock.getInputStream());

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

    public Key keyExchange(String sign, KeyPair rsa_key) {
        try {
            Envelope message = new Envelope(sign);
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

            byte[] ecc_pub_key = Base64.getDecoder().decode(ecc_pub_key_str);

            KeyFactory kf = KeyFactory.getInstance("EC");
            X509EncodedKeySpec pkSpec = new X509EncodedKeySpec(ecc_pub_key);
            PublicKey otherPublicKey = kf.generatePublic(pkSpec);

            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(kp.getPrivate());
            ka.doPhase(otherPublicKey, true);

            byte[] sharedSecret = ka.generateSecret();
            MessageDigest hash = MessageDigest.getInstance("SHA-256");
            hash.update(sharedSecret);

            List<ByteBuffer> keys = Arrays.asList(ByteBuffer.wrap(ourPk), ByteBuffer.wrap(ecc_pub_key));
            Collections.sort(keys);
            hash.update(keys.get(0));
            hash.update(keys.get(1));

            byte[] derivedKey = hash.digest();
            SecretKeySpec aesSpec = new SecretKeySpec(derivedKey, "AES");
            byte[] iv = Base64.getDecoder().decode(ivEncoded);

            k = aesSpec;
            IVk = iv;

            output.setEncryption(k, iv);
            input.setEncryption(k, iv);
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

        if (publicKeyList == null) {
            readPublicKeyList();
        }

        // Extract the crypto values
        byte[] eccKey    = Base64.getDecoder().decode((String)contents.get(0));
        byte[] eccSign = Base64.getDecoder().decode((String)contents.get(1));
        byte[] publicKey = Base64.getDecoder().decode((String)contents.get(2));

        String s = new String("The authenticity of host '" + sock.getInetAddress().getHostName() + " (" + sock.getInetAddress().getHostAddress() + ")' can't be established.\nRSA key fingerprint is " + Base64.getEncoder().encodeToString(publicKey).substring(0,50) + ".\n");

        System.out.printf("The authenticity of host '%s (%s)' can't be established.\n", sock.getInetAddress().getHostName(), sock.getInetAddress().getHostAddress());
        System.out.printf("RSA key fingerprint is %s.\n", Base64.getEncoder().encodeToString(publicKey).substring(0,50));

        boolean checked = false;
        while(!checked){
            System.out.printf("Are you sure you want to continue connecting (yes/no)?");
            String input = "";
            try{
                if(gui == null){
                    BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
                    input =  in.readLine();
                } else{
                    input = JOptionPane.showInputDialog("");
                }
            } catch(Exception e){
                // Uh oh...
                System.err.println("Buffer Reader Error");
                e.printStackTrace();
            }

        try {
            MessageDigest hash = MessageDigest.getInstance("SHA-256");
            hash.update(publicKey);
            byte[] rsaHash = hash.digest();
            rsaHashEncoded = Base64.getEncoder().encodeToString(rsaHash);
        } catch(Exception e) {
            e.printStackTrace();
            rsaHashEncoded = Base64.getEncoder().encodeToString(publicKey);
        }

        if (!publicKeyList.checkKey(rsaHashEncoded)) {
            System.out.printf(
                "The authenticity of host '%s (%s)' can't be established.\n",
                sock.getInetAddress().getHostName(),
                sock.getInetAddress().getHostAddress()
            );
            System.out.printf("RSA key fingerprint is %s.\n", rsaHashEncoded);

            boolean checked = false;
            while(!checked){
                System.out.printf("Are you sure you want to continue connecting (yes/no)?");
                String input = "";
                try{
                    BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
                    input =  in.readLine();
                } catch(Exception e){
                    // Uh oh...
                    System.err.println("Buffer Reader Error");
                    e.printStackTrace();
                }

                if(input.equals("yes")){
                    checked = true;
                    publicKeyList.addKey(
                        sock.getInetAddress().getHostName(),
                        sock.getInetAddress().getHostAddress(),
                        rsaHashEncoded
                    );
                    writePublicKeyList();
                }else if(input.equals("no")){
                    return false;
                }
            }
        }

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

    public void readPublicKeyList() {
        // Get the saved public keys
        String publicKeyListFile = "PublicKeyList.bin";
        ObjectInputStream fileStream;

        try {
            FileInputStream fis = new FileInputStream(publicKeyListFile);
            fileStream = new ObjectInputStream(fis);
            publicKeyList = (PublicKeyList)fileStream.readObject();
        } catch(FileNotFoundException e) {
            System.out.println("PublicKeyList Does Not Exist. Creating PublicKeyList...");

            publicKeyList = new PublicKeyList();

        } catch(IOException e) {
            System.out.println("Error reading from FileList file");
            System.exit(-1);
        } catch(ClassNotFoundException e) {
            System.out.println("Error reading from FileList file");
            System.exit(-1);
        }
    }

    private void writePublicKeyList() {
        try {
            ObjectOutputStream outStream;
            try {
                outStream = new ObjectOutputStream(new FileOutputStream("PublicKeyList.bin"));
                outStream.writeObject(publicKeyList);
            } catch(Exception e) {
                System.err.println("Error: " + e.getMessage());
                e.printStackTrace(System.err);
            }
        } catch(Exception e) {
            System.out.println("PublicKey Save Interrupted");
        }
    }

    public boolean verifyServer(String sign) {
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
