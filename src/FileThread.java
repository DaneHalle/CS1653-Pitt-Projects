/* File worker thread handles the business of uploading, downloading, and removing files for clients with valid tokens */

import java.lang.Thread;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

// Crypto libraries
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.KeyAgreement;
import javax.crypto.Cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.io.UnsupportedEncodingException;

import java.security.Security;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Timestamp;
import java.security.spec.ECParameterSpec;
import java.security.interfaces.ECPublicKey;

import java.util.Date;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;
import java.util.logging.LogRecord;
import java.util.logging.ConsoleHandler;

public class FileThread extends Thread {
    private final Socket socket;
    private FileServer my_fs;

    private SecretKeySpec aes_k;
    private SecretKeySpec hmac_k;
    private byte[] IVk;

    public FileThread(Socket _socket, FileServer _fs) {
        socket = _socket;
        my_fs = _fs;
    }

    public void run() {
        boolean proceed = true;

        Security.addProvider(new BouncyCastleProvider());

        try {


            Logger logging = Logger.getLogger("fileLog_"+socket.getPort());  
            FileHandler fh;  

            try {  

                // This block configure the logger with handler and formatter  
                fh = new FileHandler("./file_logs/log_"+socket.getInetAddress().toString().substring(1)+"-"+socket.getPort()+".log", true);  
                logging.addHandler(fh);
                ConsoleHandler handler = new ConsoleHandler();
                fh.setFormatter(new SimpleFormatter() {
                      private static final String format = "[%1$tF %1$tT] [%2$s] %3$s %n";

                      @Override
                      public synchronized String format(LogRecord lr) {
                          return String.format(format,
                                  new Date(lr.getMillis()),
                                  lr.getLevel().getLocalizedName(),
                                  lr.getMessage()
                          );
                      }
                  }); 
                handler.setFormatter(new SimpleFormatter() {
                      private static final String format = "[%1$tF %1$tT] [%2$s] %3$s %n";

                      @Override
                      public synchronized String format(LogRecord lr) {
                          return String.format(format,
                                  new Date(lr.getMillis()),
                                  lr.getLevel().getLocalizedName(),
                                  lr.getMessage()
                          );
                      }
                  }); 
                logging.addHandler(handler);

                // the following statement is used to log any messages  

            } catch (SecurityException e) {  
                e.printStackTrace();  
            } catch (IOException e) {  
                e.printStackTrace();  
            }  

            logging.info("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
            final EncryptedObjectInputStream input = new EncryptedObjectInputStream(socket.getInputStream());
            final EncryptedObjectOutputStream output = new EncryptedObjectOutputStream(socket.getOutputStream());
            // Establish I/O Connection
            input.setOutputReference(output);
            output.setInputReference(input);
            Envelope response;

            response = new Envelope("FILE");

            if (!establishConnection(input, output)) {
                socket.close();
                proceed = false;
            }

            do {
                Envelope e = (Envelope) input.readObject();
                output.reset();

                logging.info(socket.getInetAddress() + ":" + socket.getPort() + " | Request received: " + e.getMessage());
                String action = "";
                // Handler to list files that this user is allowed to see
                if (e.getMessage().equals("LFILES")) {
                    /* TODO: Write this handler */
                    if (e.getObjContents().size() != 1) {
                        response = new Envelope("FAIL-BADCONTENTS");
                        action = "\tFAIL-LFILES | as request has bad contents.\n";
                        response.addObject(action.substring(1, action.length() - 1));
                        logging.info(String.format("%s", action));
                    } else {
                        UserToken t = (UserToken)e.getObjContents().get(0);
                        if(t == null || !t.verify()) {
                            response = new Envelope("FAIL-BADTOKEN");
                            action = "\tFAIL-LFILES | as request has bad token.\n";
                            response.addObject(action.substring(1, action.length() - 1));
                            logging.info(String.format("%s", action));
                        } else if(!checkToken((Token)t)){
                            response = new Envelope("FAIL-INVALIDTOKEN");
                            action = "\tFAIL-LFILES | as request has an invalid token.\n";
                            response.addObject(action.substring(1, action.length() - 1));
                            logging.info(String.format("%s", action));
                        }else {
                            UserToken token = (UserToken) e.getObjContents().get(0);
                            String requester = token.getSubject();

                            logging.info(String.format("\tLFILES by %s", requester));

                            response = new Envelope("OK");

                            List<String> requesterGroups = token.getShownGroups();
                            List<ShareFile> filesInServer = my_fs.fileList.getFiles();
                            for (int index = 0; index < filesInServer.size(); index++) {
                                if (requesterGroups.contains(filesInServer.get(index).getGroup())) {
                                    response.addObject(filesInServer.get(index).getPath());
                                }
                            }

                        }
                    }
                    output.writeObject(response);
                } else if (e.getMessage().equals("LFORGROUP")) {
                    // Added
                    if (e.getObjContents().size() != 2) {
                        response = new Envelope("FAIL-BADCONTENTS");
                        action = "\tFAIL-LFORGROUP | as request has bad contents.\n";
                        response.addObject(action.substring(1, action.length() - 1));
                        logging.info(String.format("%s", action));
                    } else {
                        if (e.getObjContents().get(0) == null) {
                            response = new Envelope("FAIL-BADGROUP");
                            action = "\tFAIL-LFORGROUP | as request has bad group.\n";
                            response.addObject(action.substring(1, action.length() - 1));
                            logging.info(String.format("%s", action));
                        } 
                        UserToken t = (UserToken)e.getObjContents().get(1);
                        if(t == null || !t.verify()) {
                            response = new Envelope("FAIL-BADTOKEN");
                            action = "\tFAIL-LFORGROUP | as request has bad token.\n";
                            response.addObject(action.substring(1, action.length() - 1));
                            logging.info(String.format("%s", action));
                        } else {
                            String group = (String) e.getObjContents().get(0);
                            UserToken token = (UserToken) e.getObjContents().get(1);
                            String requester = token.getSubject();

                            logging.info(String.format("\tLFORGROUP %s by %s", group, requester));


                            if (token.getGroups().contains(group)) {
                                if (token.getShownGroups().contains(group)) {
                                    response = new Envelope("OK");
                                    List<ShareFile> filesInServer = my_fs.fileList.getFiles();
                                    for (int index = 0; index < filesInServer.size(); index++) {
                                        if (filesInServer.get(index).getGroup().equals(group)) {
                                            response.addObject(filesInServer.get(index).getPath());
                                        }
                                    }
                                } else {
                                    response = new Envelope("FAIL-PRIVILEGE");
                                    action = "\tFAIL-LFORGROUP | " + requester
                                            + " has not escalated permissions for group " + group + "\n";
                                    response.addObject(action.substring(1, action.length() - 1));
                                    logging.info(String.format("%s", action));
                                }
                            } else {
                                response = new Envelope("FAIL-UNAUTHORIZED");
                                action = "\tFAIL-LFORGROUP | " + requester + " is not a user within group " + group
                                        + "\n";
                                response.addObject(action.substring(1, action.length() - 1));
                                logging.info(String.format("%s", action));
                            }

                        }
                    }
                    output.writeObject(response);
                } else if (e.getMessage().equals("UPLOADF")) {

                    if (e.getObjContents().size() != 4) {
                        response = new Envelope("FAIL-BADCONTENTS");
                        action = "\tFAIL-UPLOADF | as request has bad contents.\n";
                        response.addObject(action.substring(1, action.length() - 1));
                        logging.info(String.format("%s", action));
                    } else {
                        String remotePath = (String)e.getObjContents().get(0);
                        String group = (String)e.getObjContents().get(1);
                        UserToken yourToken = (UserToken)e.getObjContents().get(2);
                        String id = (String)e.getObjContents().get(3);
                        if (remotePath == null) {
                            response = new Envelope("FAIL-BADPATH");
                            action = "\tFAIL-UPLOADF | as request has bad path.\n";
                            response.addObject(action.substring(1, action.length() - 1));
                            logging.info(String.format("%s", action));
                        } else if (group == null) {
                            response = new Envelope("FAIL-BADGROUP");
                            action = "\tFAIL-UPLOADF | as request has bad group.\n";
                            response.addObject(action.substring(1, action.length() - 1));
                            logging.info(String.format("%s", action));
                        } else if (id == null) {
                            response = new Envelope("FAIL-BADID");
                            action = "\tFAIL-UPLOADF | request has bad ID.\n";
                            response.addObject(action.substring(1, action.length() - 1));
                            logging.info(String.format("%s", action));                          
                        } else if(yourToken == null || !yourToken.verify()) {
                            response = new Envelope("FAIL-BADTOKEN");
                            action = "\tFAIL-UPLOADF | as request has bad token.\n";
                            response.addObject(action.substring(1, action.length() - 1));
                            logging.info(String.format("%s", action));
                        } else {

                            logging.info(String.format("\tUPLOADF %s %s by %s", remotePath, group, yourToken.getSubject()));

                            if (FileServer.fileList.checkFile(remotePath)) {
                                response = new Envelope("FAIL-FILEEXISTS"); // Success
                                action = "\tError: file already exists at " + remotePath + "\n";
                                response.addObject(action.substring(1, action.length() - 1));
                                logging.info(String.format("%s", action));
                            } else if (!yourToken.getGroups().contains(group)) {
                                response = new Envelope("FAIL-UNAUTHORIZED"); // Success
                                action = "\tError: user missing valid token for group " + group + "\n";
                                response.addObject(action.substring(1, action.length() - 1));
                                logging.info(String.format("%s", action));
                            } else if (!yourToken.getShownGroups().contains(group)) {
                                response = new Envelope("FAIL-PRIVILEGE"); // Success
                                action = "\t" + yourToken.getSubject() + " has not escalated permissions for group "
                                        + group + "\n";
                                response.addObject(action.substring(1, action.length() - 1));
                                logging.info(String.format("%s", action));
                            } else {
                                File file = new File("shared_files/" + remotePath.replace('/', '_'));
                                file.createNewFile();
                                FileOutputStream fos = new FileOutputStream(file);
                                logging.info(String.format("Successfully created file %s\n", remotePath.replace('/', '_')));

                                response = new Envelope("READY"); // Success
                                output.writeObject(response);

                                e = (Envelope) input.readObject();
                                while (e.getMessage().compareTo("CHUNK") == 0) {
                                    fos.write((byte[]) e.getObjContents().get(0), 0,
                                            (Integer) e.getObjContents().get(1));
                                    response = new Envelope("READY"); // Success
                                    output.writeObject(response);
                                    e = (Envelope) input.readObject();
                                }

                                if (e.getMessage().compareTo("EOF") == 0) {
                                    logging.info(String.format("Transfer successful file %s\n", remotePath));
                                    FileServer.fileList.addFile(yourToken.getSubject(), group, remotePath, id);
                                    response = new Envelope("OK"); // Success
                                } else if (
                                    e.getMessage().equals("FAIL-MSGCOUNT") ||
                                    e.getMessage().equals("FAIL-HMAC")
                                ) {
                                    response = e;
                                    logging.info(String.format("\t%s\n", e.getObjContents()));
                                } else {
                                    response = new Envelope("ERROR-TRANSFER"); // Success
                                    action = "\tError reading file " + remotePath + " from client\n";
                                    response.addObject(action.substring(1, action.length() - 1));
                                    logging.info(String.format("%s", action));
                                }
                                fos.close();
                            }
                        }
                    }

                    output.writeObject(response);
                } else if (e.getMessage().compareTo("DOWNLOADF") == 0) {
                    String remotePath = (String)e.getObjContents().get(0);
                    Token t = (Token)e.getObjContents().get(1);
                    ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
                    if (t == null || !t.verify()) {
                        e = new Envelope("FAIL-BADTOKEN");
                        action="\tFAIL-DELETEF | as request has bad token.\n";
                        e.addObject(action.substring(1,action.length()-1));
                        logging.info(String.format("%s", action));
                        output.writeObject(response);
                    } else if (sf == null) {
                        e = new Envelope("ERROR_FILEMISSING");
                        action = "\tError: File " + remotePath + " doesn't exist\n";
                        response.addObject(action.substring(1, action.length() - 1));
                        logging.info(String.format("%s", action));
                        output.writeObject(e);

                    } else if (!t.getGroups().contains(sf.getGroup())) {
                        e = new Envelope("ERROR_PERMISSION");
                        action = "\tError user " + t.getSubject() + " doesn't have permission\n";
                        response.addObject(action.substring(1, action.length() - 1));
                        logging.info(String.format("%s", action));
                        output.writeObject(e);
                    } else if (!t.getShownGroups().contains(sf.getGroup())) {
                        e = new Envelope("ERROR_PRIVILEGE");
                        action = "\t" + t.getSubject() + " has not escalated permissions for group " + sf.getGroup()
                                + "\n";
                        response.addObject(action.substring(1, action.length() - 1));
                        logging.info(String.format("%s", action));
                        output.writeObject(e);
                    } else {

                        logging.info(String.format("\tDOWNLOADF %s by %s", remotePath, t.getSubject()));

                        try {
                            File f = new File("shared_files/_" + remotePath.replace('/', '_'));
                            if (!f.exists()) {
                                e = new Envelope("ERROR_NOTONDISK");
                                action = "\tError file _" + remotePath.replace('/', '_') + " missing from disk\n";
                                response.addObject(action.substring(1, action.length() - 1));
                                logging.info(String.format("%s", action));
                                output.writeObject(e);

                            } else {
                                FileInputStream fis = new FileInputStream(f);

                                do {
                                    byte[] buf = new byte[4096];
                                    if (e.getMessage().compareTo("DOWNLOADF") != 0) {
                                        action = "\tServer error: " + e.getMessage() + "\n";
                                        response.addObject(action.substring(1, action.length() - 1));
                                        logging.info(String.format("%s", action));
                                        break;
                                    }
                                    e = new Envelope("CHUNK");
                                    int n = fis.read(buf); // can throw an IOException
                                    if (n > 0) {
                                        logging.info(String.format("."));
                                    } else if (n < 0) {
                                        action = "\tRead error\n";
                                        response.addObject(action.substring(1, action.length() - 1));
                                        logging.info(String.format("%s", action));

                                    }

                                    e.addObject(buf);
                                    e.addObject(Integer.valueOf(n));

                                    output.writeObject(e);

                                    e = (Envelope) input.readObject();

                                } while (fis.available() > 0);

                                // If server indicates success, return the member list
                                if (e.getMessage().compareTo("DOWNLOADF") == 0) {

                                    e = new Envelope("EOF");
                                    e.addObject(sf.getID());
                                    e.addObject(sf.getGroup());
                                    output.writeObject(e);

                                    e = (Envelope) input.readObject();
                                    if (e.getMessage().compareTo("OK") == 0) {
                                        logging.info(String.format("File data upload successful\n"));
                                    } else {
                                        action = "\tUpload failed: " + e.getMessage() + "\n";
                                        response.addObject(action.substring(1, action.length() - 1));
                                        logging.info(String.format("%s", action));
                                    }
                                } else {
                                    action = "\tUpload failed: " + e.getMessage() + "\n";
                                    response.addObject(action.substring(1, action.length() - 1));
                                    logging.info(String.format("%s", action));
                                }
                            }
                        } catch (Exception e1) {
                            System.err.println("Error: " + e.getMessage());
                            e1.printStackTrace(System.err);
                        }
                    }
                } else if (e.getMessage().compareTo("DELETEF") == 0) {
                    String remotePath = (String)e.getObjContents().get(0);
                    Token t = (Token)e.getObjContents().get(1);
                    ShareFile sf = FileServer.fileList.getFile("/"+remotePath);
                    if (t == null || !t.verify()) {
                        e = new Envelope("FAIL-BADTOKEN");
                        action="\tFAIL-DELETEF | as request has bad token.\n";
                        e.addObject(action.substring(1,action.length()-1));
                        logging.info(String.format("%s", action));
                    } else if (sf == null) {
                        e = new Envelope("ERROR_DOESNTEXIST");
                        action = "\tError: File " + remotePath + " doesn't exist\n";
                        response.addObject(action.substring(1, action.length() - 1));
                        logging.info(String.format("%s", action));
                    } else if (!t.getGroups().contains(sf.getGroup())) {
                        e = new Envelope("ERROR_PERMISSION");
                        action = "\tError user " + t.getSubject() + " doesn't have permission\n";
                        response.addObject(action.substring(1, action.length() - 1));
                        logging.info(String.format("%s", action));
                    } else if (!t.getShownGroups().contains(sf.getGroup())) {
                        e = new Envelope("ERROR-PRIVILEGE"); // Success
                        action = "\t" + t.getSubject() + " has not escalated permissions for group " + sf.getGroup()
                                + "\n";
                        response.addObject(action.substring(1, action.length() - 1));
                        logging.info(String.format("%s", action));
                    } else {

                        logging.info(String.format("\tDELETEF %s by %s", remotePath, t.getSubject()));

                        try {

                            File f = new File("shared_files/" + "_" + remotePath.replace('/', '_'));

                            if (!f.exists()) {
                                e = new Envelope("ERROR_FILEMISSING");
                                action = "\tError file _" + remotePath.replace('/', '_') + " missing from disk\n";
                                response.addObject(action.substring(1, action.length() - 1));
                                logging.info(String.format("%s", action));
                            } else if (f.delete()) {
                                logging.info(String.format("File %s deleted from disk\n", "_" + remotePath.replace('/', '_')));
                                FileServer.fileList.removeFile("/" + remotePath);
                                e = new Envelope("OK");
                            } else {
                                e = new Envelope("ERROR_DELETE");
                                action = "\tError deleting file _" + remotePath.replace('/', '_') + " from disk\n";
                                response.addObject(action.substring(1, action.length() - 1));
                                logging.info(String.format("%s", action));
                            }

                        } catch (Exception e1) {
                            System.err.println("Error: " + e1.getMessage());
                            e1.printStackTrace(System.err);
                            e = new Envelope(e1.getMessage());
                        }
                    }
                    output.writeObject(e);

                } else if (e.getMessage().equals("DISCONNECT")) {
                    socket.close();
                    proceed = false;
                } else if (e.getObjContents().size() == 1) {
                    logging.info(String.format("\t%s\n", e.getObjContents().get(0)));
                    output.writeObject(e);
                }
            } while (proceed);
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }


    private boolean checkToken(Token t) {
        String actualPubKey = Base64.getEncoder().encodeToString(my_fs.getPublicKey().getEncoded());

        try {
            MessageDigest hash = MessageDigest.getInstance("SHA-256");
            hash.update(my_fs.getPublicKey().getEncoded());
            byte[] rsaHash = hash.digest();
            actualPubKey = Base64.getEncoder().encodeToString(rsaHash);
        } catch(Exception e) {
            e.printStackTrace();
        }


        String tokenPubKey = t.getFsPubKey();

        // logging.info("actual pub key: " + actualPubKey);
        // logging.info("token pub key: " + tokenPubKey);

        Timestamp curTimestamp = new Timestamp(System.currentTimeMillis());
        Timestamp tokTimestamp = Timestamp.valueOf(t.getTimestamp());

        long curTimestamp_value = curTimestamp.getTime();
        long tokTimestamp_value = tokTimestamp.getTime();

        long timeDif = curTimestamp_value - tokTimestamp_value;
        // logging.info("####### Timestamp dif(milliseconds): " + timeDif);

        timeDif = TimeUnit.MILLISECONDS.toMinutes(timeDif);
        // logging.info("####### Timestamp dif(minutes): " + timeDif);

        boolean check = true;

        //check that the token's pub key matches our own
        if(actualPubKey.compareTo(tokenPubKey) != 0){
            check = false;
            // logging.info("Check Token Fails Because Bad Public Key");
        }
        //check that the token's timestamp is not older than ten minutes
        if(timeDif > 10){
            check = false;
            // logging.info("Check Token Fails Because Bad Timestamp");
        }

        return check;
    }

    boolean establishConnection(EncryptedObjectInputStream input, EncryptedObjectOutputStream output) throws Exception {
        Envelope response;

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        KeyPair kp = kpg.generateKeyPair();
        byte[] ourPk = kp.getPublic().getEncoded();

        String encodedPubKey = Base64.getEncoder().encodeToString(ourPk);
        String encodedSig = Base64.getEncoder().encodeToString(my_fs.signData(ourPk));
        
        byte[] rsaPublicKeyByte = my_fs.getPublicKey().getEncoded();
        String encodedRSAPk = Base64.getEncoder().encodeToString(rsaPublicKeyByte);

        response = (Envelope)input.readObject();
        // String username = response.getMessage();

        String ecc_pub_key_str = (String)response.getObjContents().get(0);

        // AES Test Part 1

        // Derive the initialization vector to be shared
        Cipher aes = Cipher.getInstance("AES/CBC/PKCS7Padding");
        SecureRandom rnd = new SecureRandom();
        byte[] iv = new byte[aes.getBlockSize()];
        rnd.nextBytes(iv);
        IvParameterSpec ivParams = new IvParameterSpec(iv);
        IVk = iv;
        
        String ivEncoded = Base64.getEncoder().encodeToString(iv);

        response = new Envelope("FILE");
        response.addObject(encodedPubKey);
        response.addObject(encodedSig);
        response.addObject(encodedRSAPk);
        response.addObject(ivEncoded);
        output.writeObject(response);

        byte[] ecc_pub_key = Base64.getDecoder().decode(ecc_pub_key_str);

        KeyFactory kf = KeyFactory.getInstance("EC");
        X509EncodedKeySpec pkSpec = new X509EncodedKeySpec(ecc_pub_key);
        PublicKey otherPublicKey = kf.generatePublic(pkSpec);

        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(kp.getPrivate());
        ka.doPhase(otherPublicKey, true);

        byte[] sharedSecret = ka.generateSecret();
        deriveKeys(sharedSecret, ourPk, ecc_pub_key);

        output.setEncryption(aes_k, hmac_k, iv);
        input.setEncryption(aes_k, hmac_k, iv);

        return true;
    }

    private void deriveKeys(byte[] sharedSecret, byte[] ourPk, byte[] otherPk) {
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
}
