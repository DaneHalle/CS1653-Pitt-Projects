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
import javax.swing.JOptionPane;

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
    // private final int TAG_LENGTH_BIT = 128;

    protected SecretKeySpec aes_k;
    protected SecretKeySpec hmac_k;
    protected byte[] IVk;
    protected PublicKeyList publicKeyList = null;

    protected String fsPubKey = null;

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
            // Establish I/O Connection
            input.setOutputReference(output);
            output.setInputReference(input);

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

    public Key keyExchange(String sign, KeyPair rsa_key, boolean gui) {
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
            if (!verify(message, sign, gui)) {
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
            deriveKeys(sharedSecret, ourPk, ecc_pub_key);

            byte[] iv = Base64.getDecoder().decode(ivEncoded);
            IVk = iv;

            output.setEncryption(aes_k, hmac_k, iv);
            input.setEncryption(aes_k, hmac_k, iv);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

        return null;
    }

    protected void deriveKeys(byte[] sharedSecret, byte[] ourPk, byte[] otherPk) {
        try {
            // Derive the aes Confidentiality Key
            MessageDigest hash = MessageDigest.getInstance("SHA-256");
            hash.update("Confidentiality".getBytes("UTF-8"));
            hash.update(sharedSecret);
            List<ByteBuffer> keys = Arrays.asList(ByteBuffer.wrap(ourPk), ByteBuffer.wrap(otherPk));
            Collections.sort(keys);
            hash.update(keys.get(0));
            hash.update(keys.get(1));
            byte[] derivedKey = hash.digest();
            SecretKeySpec derived = new SecretKeySpec(derivedKey, "AES");
            aes_k = derived;

            // Derive the aes Integrity Key
            hash = MessageDigest.getInstance("SHA-256");
            hash.update("Integrity".getBytes("UTF-8"));
            hash.update(sharedSecret);
            keys = Arrays.asList(ByteBuffer.wrap(ourPk), ByteBuffer.wrap(otherPk));
            Collections.sort(keys);
            hash.update(keys.get(0));
            hash.update(keys.get(1));
            derivedKey = hash.digest();
            derived = new SecretKeySpec(derivedKey, "HmacSHA256");
            hmac_k = derived;
        } catch(Exception e) {
            e.printStackTrace();
        }
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

    private boolean verify(Envelope message, String server_type, boolean gui) {
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

        String rsaHashEncoded = "";

        try {
            MessageDigest hash = MessageDigest.getInstance("SHA-256");
            hash.update(publicKey);
            byte[] rsaHash = hash.digest();
            rsaHashEncoded = Base64.getEncoder().encodeToString(rsaHash);
        } catch(Exception e) {
            e.printStackTrace();
            rsaHashEncoded = Base64.getEncoder().encodeToString(publicKey);
        }

        String s = new String("The authenticity of host '" 
                                + sock.getInetAddress().getHostName()
                                + " (" + sock.getInetAddress().getHostAddress()
                                + ")' can't be established.\nRSA key fingerprint is "
                                + rsaHashEncoded 
                                + ".\nAre you sure you want to continue connecting (yes/no)?");

        if (!publicKeyList.checkKey(rsaHashEncoded)) {
            if(!gui){
                System.out.printf(
                    "The authenticity of host '%s (%s)' can't be established.\n",
                    sock.getInetAddress().getHostName(),
                    sock.getInetAddress().getHostAddress()
                );
                System.out.printf("RSA key fingerprint is %s.\n", rsaHashEncoded);
            }
            
            boolean checked = false;
            while(!checked){
                System.out.printf("Are you sure you want to continue connecting (yes/no)? ");
                String input = "";
                try{
                    if(!gui){
                        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
                        input =  in.readLine();
                    }else{
                        input = JOptionPane.showInputDialog(s);
                    }	
                    
                } catch(Exception e){
                    // Uh oh...
                    System.err.println("Buffer Reader Error");
                    e.printStackTrace();
                }

                if(input.toLowerCase().equals("yes") || input.toLowerCase().equals("y")){
                    checked = true;
                    publicKeyList.addKey(
                        sock.getInetAddress().getHostName(),
                        sock.getInetAddress().getHostAddress(),
                        rsaHashEncoded
                    );
                    writePublicKeyList();
                    fsPubKey = rsaHashEncoded;
                    // fsPubKey = "oc4JnOVY+3pxuOTy56Qpq3UjwI4BduSb86vxvns8Pgs=";
                }else if(input.toLowerCase().equals("no") || input.toLowerCase().equals("n")){
                    return false;
                }
            }
        }else{
            fsPubKey = rsaHashEncoded;
            // fsPubKey = "oc4JnOVY+3pxuOTy56Qpq3UjwI4BduSb86vxvns8Pgs=";
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

    public void fsPubKeyCheck(){
        if(fsPubKey == null){
            System.out.println("FsPubKey is NULL");
        }else{
            System.out.println("FsPubKey is " + fsPubKey);
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
            Envelope response;

            if (!server_type.getMessage().equals(sign)) {
                System.out.printf("Server is not a %s server\n", sign);

                response = new Envelope("FAIL");
                response.addObject(null);
                output.writeObject(response);

                disconnect();
                return false;
            }

            String puzzle = (String)server_type.getObjContents().get(0);
            String target = ComputationPuzzle.solvePuzzle(puzzle);

            response = new Envelope("GROUP");
            response.addObject(target);
            output.writeObject(response);

            response = (Envelope)input.readObject();
            if (server_type.getMessage().equals("FAIL")) {
                System.out.println("Failed Computational Puzzle");
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
