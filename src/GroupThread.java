/* This thread does all the work. It communicates with the client through Envelopes.
 *
 */
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.IOException;
import java.lang.Thread;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Base64;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.Scanner;
import java.io.File;

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
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.ECParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.interfaces.ECPublicKey;

import java.sql.Timestamp;

import java.util.Date;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;
import java.util.logging.LogRecord;
import java.util.logging.ConsoleHandler;

public class GroupThread extends Thread {
    private final Socket socket;
    private GroupServer my_gs;

    private SecretKeySpec aes_k;
    private SecretKeySpec hmac_k;
    private byte[] IVk;

    public GroupThread(Socket _socket, GroupServer _gs) {
        socket = _socket;
        my_gs = _gs;
        aes_k = null;
        hmac_k = null;
        IVk = null;
    }

    public void run() {
        boolean proceed = true;
        Security.addProvider(new BouncyCastleProvider());
        try {            
            Logger logging = Logger.getLogger("groupLog_"+socket.getPort());  
            logging.setUseParentHandlers(false);
            FileHandler fh;  

            try {  

                // This block configure the logger with handler and formatter  
                fh = new FileHandler("./group_logs/log_"+socket.getInetAddress().toString().substring(1)+"-"+socket.getPort()+".log", true);  
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
            //Announces connection and opens object streams
            logging.info("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
            final EncryptedObjectInputStream input = new EncryptedObjectInputStream(socket.getInputStream());
            final EncryptedObjectOutputStream output = new EncryptedObjectOutputStream(socket.getOutputStream());
            // Establish I/O Connection
            input.setOutputReference(output);
            output.setInputReference(input);
            Envelope response;

            // response = new Envelope("GROUP");
            // response.addObject(null);
            // output.writeObject(response);
            if (!verifyServer(input, output)) {
                socket.close();
                return;
            }

            do {
                Envelope message = (Envelope)input.readObject();
                output.reset();
                logging.info(socket.getInetAddress()+":"+socket.getPort()+" | Request received: " + message.getMessage());

                String action="";

                if (message.getMessage().equals("GET")) { //Client wants a token
                    if (message.getObjContents().size() != 4) {
                        aes_k = null;
                        hmac_k = null;
                        IVk = null;
                        response = new Envelope("FAIL-BADCONTENTS");
                        action="\tFAIL-GET | as request has bad contents.\n";
                        response.addObject(action.substring(1,action.length()-1));
                        logging.info(String.format("%s", action));
                    } else {
                        String username = (String)message.getObjContents().get(0); //Get the username

                        if (username == null) {
                            aes_k = null;
                            hmac_k = null;
                            IVk = null;
                            response = new Envelope("FAIL");
                            action="\tFAIL-GET | as given username was null\n";
                            response.addObject(action.substring(1,action.length()-1));
                            logging.info(String.format("%s", action));
                        } else if (!my_gs.userList.checkUser(username)) {
                            aes_k = null;
                            hmac_k = null;
                            IVk = null;
                            response = new Envelope("FAIL");
                            action="\tFAIL-GET | User is not in system\n";
                            response.addObject(action.substring(1,action.length()-1));
                            logging.info(String.format("%s", action));                         
                        }else {

                            String encrypted = (String)message.getObjContents().get(1);
                            if (encrypted == null) {
                                aes_k = null;
                                hmac_k = null;
                                IVk = null;
                                response = new Envelope("FAIL");
                                action="\tFAIL-GET | encryption was null\n";
                                response.addObject(action.substring(1,action.length()-1));
                                logging.info(String.format("%s", action));
                            } else {

                                IvParameterSpec ivSpec = new IvParameterSpec((byte[])message.getObjContents().get(2));
                                if (ivSpec == null) {
                                    aes_k = null;
                                    hmac_k = null;
                                    IVk = null;
                                    response = new Envelope("FAIL");
                                    action="\tFAIL-GET | IV was null\n";
                                    response.addObject(action.substring(1,action.length()-1));
                                    logging.info(String.format("%s", action));
                                } else {
                                    logging.info(String.format("\tGET %s", username));

                                    String passSecret = my_gs.userList.getPasswordHash(username);
                                    try {
                                        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
                                        kpg.initialize(256);
                                        KeyPair kp = kpg.generateKeyPair();
                                        byte[] ourPk = kp.getPublic().getEncoded();
    
                                        MessageDigest digest = MessageDigest.getInstance("SHA-256");
                                        digest.update(passSecret.getBytes("UTF-8"));
                                        byte[] keyBytes = new byte[16];
                                        System.arraycopy(digest.digest(), 0, keyBytes, 0, keyBytes.length);
    
                                        Cipher decrypt = Cipher.getInstance("AES/CBC/PKCS7PADDING");
                                        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
                                        decrypt.init(Cipher.DECRYPT_MODE, key, ivSpec);
                                        byte[] otherPk = decrypt.doFinal(Base64.getDecoder().decode(encrypted));
    
                                        KeyFactory kf = KeyFactory.getInstance("EC");
                                        X509EncodedKeySpec pkSpec = new X509EncodedKeySpec(otherPk);
                                        PublicKey otherPublicKey = kf.generatePublic(pkSpec);
    
                                        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
                                        ka.init(kp.getPrivate());
                                        ka.doPhase(otherPublicKey, true);
    
                                        byte[] sharedSecret = ka.generateSecret();
                                        deriveKeys(sharedSecret, ourPk, otherPk);
    
                                        SecureRandom challenge = new SecureRandom();
                                        String encodedChallenge = Base64.getEncoder().encodeToString(challenge.generateSeed(64)); 
    
                                        Cipher encrypt = Cipher.getInstance("AES/CBC/PKCS7PADDING");
                                        byte[] iv = new byte[16];
                                        SecureRandom random = new SecureRandom();
                                        random.nextBytes(iv);
                                        IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
                                        encrypt.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
                                        byte[] encryptedKey = encrypt.doFinal(ourPk);
                                        byte[] encryptedChallenge = encrypt.doFinal(Base64.getDecoder().decode(encodedChallenge));
                                        IVk = iv;
    
                                        Envelope message2 = new Envelope("MESSAGE2");
                                        message2.addObject(Base64.getEncoder().encodeToString(encryptedKey));
                                        message2.addObject(Base64.getEncoder().encodeToString(encryptedChallenge));
                                        message2.addObject(iv);
                                        output.writeObject(message2);
                                    //--------------------------------------------------------------
                                        Envelope message3 = (Envelope)input.readObject();
                                        if (message3.getMessage().equals("MESSAGE3")) {
                                            String thisChallenge = (String)message3.getObjContents().get(0);
                                            String otherChallenge = (String)message3.getObjContents().get(1);
                                            IvParameterSpec newIv = new IvParameterSpec((byte[])message3.getObjContents().get(2));
        
                                            decrypt = Cipher.getInstance("AES/CBC/PKCS7PADDING");
                                            decrypt.init(Cipher.DECRYPT_MODE, aes_k, newIv);
                                            byte[] decryptThisChallenge = decrypt.doFinal(Base64.getDecoder().decode(thisChallenge));
                                            byte[] decryptOtherChallenge = decrypt.doFinal(Base64.getDecoder().decode(otherChallenge));
    
                                            encrypt = Cipher.getInstance("AES/CBC/PKCS7PADDING");
                                            iv = new byte[16];
                                            random = new SecureRandom();
                                            random.nextBytes(iv);
                                            ivParameterSpec = new IvParameterSpec(iv);
                                            encrypt.init(Cipher.ENCRYPT_MODE, aes_k, ivParameterSpec);
                                            byte[] encryptOther = encrypt.doFinal(decryptOtherChallenge);
        
                                            if (Base64.getEncoder().encodeToString(decryptThisChallenge).equals(encodedChallenge)) {
                                                Envelope message4 = new Envelope("MESSAGE4");
                                                message4.addObject(Base64.getEncoder().encodeToString(encryptOther));
                                                message4.addObject(iv);
                                                output.writeObject(message4);
    
                                                output.setEncryption(aes_k, hmac_k, iv);
                                                input.setEncryption(aes_k, hmac_k, iv);
                                                Envelope actual = (Envelope)input.readObject();
                                                if (actual.getMessage().equals("GOOD")) {
                                                    String fsPubKey = (String)message.getObjContents().get(0);
                                                    UserToken yourToken = createToken(username, false, true, fsPubKey); //Create a token
                                                    if (my_gs.userList.isTemp(username)) {
                                                        response = new Envelope("REQUEST-NEW");
                                                        response.addObject("The password entered for this user has expired, please enter a new password: ");
                                                        output.writeObject(response);
                                                        Envelope returned = null;
                                                        String newPassSecret = passSecret;
                                                        String password, salt = username;
                                                        int iterations = 10000, keyLength = 256;
                                                        char[] passwordChars;
                                                        byte[] saltBytes, hashedBytes;
                                                      
                                                        do {
                                                            returned = (Envelope)input.readObject();
                                                            if (returned.getMessage().equals("NEW")) {
                                                                password = (String)returned.getObjContents().get(0);
                                                                if (!isStrong(password)) {
                                                                    response = new Envelope("REQUEST-NEW");
                                                                    response.addObject("The password entered is not strong enough, please enter a new password: ");
                                                                    output.writeObject(response);
                                                                    continue;
                                                                }
                                                                passwordChars = password.toCharArray();
                                                                saltBytes = salt.getBytes();
                                                                hashedBytes = hashPassword(passwordChars, saltBytes, iterations, keyLength);
                                                                newPassSecret = Base64.getEncoder().encodeToString(hashedBytes);
                                                                if (newPassSecret.equals(passSecret) || my_gs.userList.checkRecent(username, newPassSecret)) {
                                                                    response = new Envelope("REQUEST-NEW");
                                                                    response.addObject("The password entered has been used by this user recently, please enter a new password: ");
                                                                    output.writeObject(response);
                                                                    continue;
                                                                } else {
                                                                    break;
                                                                }
                                                            } else {
                                                                break;
                                                            }
                                                        } while (newPassSecret.equals(passSecret));
                                                        if (returned.getMessage().equals("NEW")) {
                                                            my_gs.userList.resetHash(username, newPassSecret);
                                                            yourToken.setPasswordSecret(newPassSecret);
                                                        }
                                                    }
                                                    
                                                    //Respond to the client. On error, the client will receive a null token
                                                    response = new Envelope("OK");
                                                    response.addObject(yourToken);
                                                    logging.info("\tSuccess");
                                                } else {
                                                    logging.info("Message: " + actual.getMessage());
                                                    aes_k = null;
                                                    hmac_k = null;
                                                    IVk = null;
                                                    response = new Envelope("FAIL");
                                                    action="\tFAIL-GET | Given challenge was incorrect\n";
                                                    response.addObject(action.substring(1,action.length()-1));
                                                    logging.info(String.format("%s", action));
                                                }
                                            } else {
                                                aes_k = null;
                                                hmac_k = null;
                                                IVk = null;
                                                response = new Envelope("FAIL");
                                                action="\tFAIL-GET | Unexpected response\n";
                                                response.addObject(action.substring(1,action.length()-1));
                                                logging.info(String.format("%s", action));
                                            }                                        
                                        } else {
                                            aes_k = null;
                                            hmac_k = null;
                                            IVk = null;
                                            response = new Envelope("FAIL");
                                            action="\tFAIL-GET | Unexpected response\n";
                                            response.addObject(action.substring(1,action.length()-1));
                                            logging.info(String.format("%s", action));
                                        }
                                    } catch (Exception e) {
                                        aes_k = null;
                                        hmac_k = null;
                                        IVk = null;
                                        response = new Envelope("FAIL");
                                        action="\tFAIL-GET | Unexpected response crash\n";
                                        response.addObject(action.substring(1,action.length()-1));
                                        logging.info(String.format("%s", action));
                                    }
                                }                           
                            }
                        }
                    }
                    output.writeObject(response);
                } else if (message.getMessage().equals("REFRESH")) { //Client needs their token refeshed
                    if (message.getObjContents().size() != 2) {
                        response = new Envelope("FAIL-BADCONTENTS");
                        action="\tFAIL-GET | as request has bad contents.\n";
                        response.addObject(action.substring(1,action.length()-1));
                        logging.info(String.format("%s", action));
                    } else {
                        UserToken yourToken = (UserToken)message.getObjContents().get(0); // Extract the token
                        String username = yourToken.getSubject(); //Get username associated with the token
                        String password = yourToken.getPasswordSecret();
                        logging.info(String.format("\tREFRESH %s", username));
                        if (my_gs.userList.getPasswordHash(username).equals(password)) {
                            UserToken newToken = refreshToken(username, (String)message.getObjContents().get(1)); //Create a refreshed token 
                            // Response to the client. On eror, the clien will reveive a null token
                            response = new Envelope("OK");
                            response.addObject(newToken);
                            logging.info("\tSuccess");
                        } else {
                            response = new Envelope("FAIL");
                            action="\tFAIL-REFRESH | Incorrect Hash.\n";
                            response.addObject(action.substring(1,action.length()-1));
                            logging.info(String.format("%s", action));
                        }
                    }
                    output.writeObject(response);
                } else if (message.getMessage().equals("CUSER")) { //Client wants to create a user
                    if (message.getObjContents().size() != 3) {
                        response = new Envelope("FAIL-BADCONTENTS");
                        action="\tFAIL-CUSER | as request has bad contents.\n";
                        response.addObject(action.substring(1,action.length()-1));
                        logging.info(String.format("%s", action));
                    } else {
                        if (message.getObjContents().get(0) == null) {
                            response = new Envelope("FAIL-BADUSER");
                            action="\tFAIL-GET | as request has bad user.\n";
                            response.addObject(action.substring(1,action.length()-1));
                            logging.info(String.format("%s", action));
                        }
                        if (message.getObjContents().get(1) == null) {
                            response = new Envelope("FAIL-BADTOKEN");
                            action="\tFAIL-GET | as request has bad token.\n";
                            response.addObject(action.substring(1,action.length()-1));
                            logging.info(String.format("%s", action));
                        } 
                        if (message.getObjContents().get(2) == null) {
                            response = new Envelope("FAIL-BADTEMPPASS");
                            action="\tFAIL-GET | as request has bad token.\n";
                            response.addObject(action.substring(1,action.length()-1));
                            logging.info(String.format("%s", action));
                        } else {
                            String username = (String)message.getObjContents().get(0); //Extract the username
                            UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token

                            logging.info(String.format("\tCUSER %s by %s", username, yourToken.getSubject()));

                            String password = (String)message.getObjContents().get(2);
                            String salt = username;
                            int iterations = 10000;
                            int keyLength = 256;
                            char[] passwordChars = password.toCharArray();
                            byte[] saltBytes = salt.getBytes();
                            byte[] hashedBytes = hashPassword(passwordChars, saltBytes, iterations, keyLength);
                            String passSecret = Base64.getEncoder().encodeToString(hashedBytes);

                            action = createUser(username, yourToken, passSecret); //Creates user with given username
                            if (action.equals("OK")){
                                response = new Envelope("OK"); //Success
                                logging.info("\tSuccess");
                            } else { //Prints reason why it fails
                                response = new Envelope("FAIL-CUSER");
                                response.addObject(action.substring(1,action.length()-1));
                                logging.info(String.format("%s", action));
                            }
                        }
                    }
                    output.writeObject(response);
                } else if (message.getMessage().equals("DUSER")) { //Client wants to delete a user
                    if (message.getObjContents().size() != 2) {
                        response = new Envelope("FAIL-BADCONTENTS");
                        action="\tFAIL-DUSER | as request has bad contents.\n";
                        response.addObject(action.substring(1,action.length()-1));
                        logging.info(String.format("%s", action));
                    } else {
                        if (message.getObjContents().get(0) == null) {
                            response = new Envelope("FAIL-BADUSER");
                            action="\tFAIL-DUSER | as request has bad user.\n";
                            response.addObject(action.substring(1,action.length()-1));
                            logging.info(String.format("%s", action));
                        }
                        if (message.getObjContents().get(1) == null) {
                            response = new Envelope("FAIL-BADTOKEN");
                            action="\tFAIL-DUSER | as request has bad token.\n";
                            response.addObject(action.substring(1,action.length()-1));
                            logging.info(String.format("%s", action));
                        } else {
                            String username = (String)message.getObjContents().get(0); //Extract the username
                            UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token

                            logging.info(String.format("\tDUSER %s by %s", username, yourToken.getSubject()));

                            action = deleteUser(username, yourToken); //Deletes user with given username
                            if (action.equals("OK")){
                                response = new Envelope("OK"); //Success
                                logging.info("\tSuccess");
                            } else { //Prints reason why it fails
                                response = new Envelope("FAIL-DUSER");
                                response.addObject(action.substring(1,action.length()-1));
                                logging.info(String.format("%s", action));
                            }
                        }
                    }
                    output.writeObject(response);
                } else if (message.getMessage().equals("CGROUP")) { //Client wants to create a group
                    /* TODO:  Write this handler */
                    if (message.getObjContents().size() != 2) {
                        response = new Envelope("FAIL-BADCONTENTS");
                        action="\tFAIL-CGROUPC | as request has bad contents.\n";
                        response.addObject(action.substring(1,action.length()-1));
                        logging.info(String.format("%s", action));
                    } else {
                        if (message.getObjContents().get(0) == null) {
                            response = new Envelope("FAIL-BADGROUP");
                            action="\tFAIL-CGROUPC | as request has bad group.\n";
                            response.addObject(action.substring(1,action.length()-1));
                            logging.info(String.format("%s", action));
                        }
                        if (message.getObjContents().get(1) == null) {
                            response = new Envelope("FAIL-BADTOKEN");
                            action="\tFAIL-CGROUPC | as request has bad token.\n";
                            response.addObject(action.substring(1,action.length()-1));
                            logging.info(String.format("%s", action));
                        } else {
                            String groupName = (String)message.getObjContents().get(0); //Extract desired group name
                            UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token

                            logging.info(String.format("\tCGROUP %s by %s", groupName, yourToken.getSubject()));

                            action = createGroup(groupName, yourToken); //Creates group with given name
                            if (action.equals("OK")){
                                response = new Envelope("OK"); //Success
                                logging.info("\tSuccess");
                            } else { //Prints reason why it fails
                                response = new Envelope("FAIL-CGROUP");
                                response.addObject(action.substring(1,action.length()-1));
                                logging.info(String.format("%s", action));
                            }
                        }
                    }
                    output.writeObject(response);
                } else if (message.getMessage().equals("DGROUP")) { //Client wants to delete a group
                    /* TODO:  Write this handler */
                    if (message.getObjContents().size() != 2) {
                        response = new Envelope("FAIL-BADCONTENTS");
                        action="\tFAIL-DGROUP | as request has bad contents.\n";
                        response.addObject(action.substring(1,action.length()-1));
                        logging.info(String.format("%s", action));
                    } else {
                        if (message.getObjContents().get(0) == null) {
                            response = new Envelope("FAIL-BADGROUP");
                            action="\tFAIL-DGROUP | as request has bad group.\n";
                            response.addObject(action.substring(1,action.length()-1));
                            logging.info(String.format("%s", action));
                        }
                        if (message.getObjContents().get(1) == null) {
                            response = new Envelope("FAIL-BADTOKEN");
                            action="\tFAIL-DGROUP | as request has bad token.\n";
                            response.addObject(action.substring(1,action.length()-1));
                            logging.info(String.format("%s", action));
                        } else {
                            String groupName = (String)message.getObjContents().get(0); //Extract desired group name
                            UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token

                            logging.info(String.format("\tDGROUP %s by %s", groupName, yourToken.getSubject()));

                            action = deleteGroup(groupName, yourToken); //Deletes group with given name
                            if (action.equals("OK")){
                                response = new Envelope("OK"); //Success
                                logging.info("\tSuccess");
                            } else { //Prints reason why it fails
                                response = new Envelope("FAIL-DGROUP");
                                response.addObject(action.substring(1,action.length()-1));
                                logging.info(String.format("%s", action));
                            }
                        }
                    }
                    output.writeObject(response);
                } else if (message.getMessage().equals("LMEMBERS")) { //Client wants a list of members in a group
                    /* TODO:  Write this handler */
                    if (message.getObjContents().size() != 2) {
                        response = new Envelope("FAIL-BADCONTENTS");
                        action="\tFAIL-LMEMBERS | as request has bad contents.\n";
                        response.addObject(action.substring(1,action.length()-1));
                        logging.info(String.format("%s", action));
                    } else {
                        if (message.getObjContents().get(0) == null) {
                            response = new Envelope("FAIL-BADGROUP");
                            action="\tFAIL-LMEMBERS | as request has bad group.\n";
                            response.addObject(action.substring(1,action.length()-1));
                            logging.info(String.format("%s", action));
                        }
                        if (message.getObjContents().get(1) == null) {
                            response = new Envelope("FAIL-BADTOKEN");
                            action="\tFAIL-LMEMBERS | as request has bad token.\n";
                            response.addObject(action.substring(1,action.length()-1));
                            logging.info(String.format("%s", action));
                        } else {
                            String groupname = (String)message.getObjContents().get(0); //Extract desired group name
                            UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the token

                            logging.info(String.format("\tLMEMBERS %s by %s", groupname, yourToken.getSubject()));

                            String requester = yourToken.getSubject(); //Extract subject name

                            if (my_gs.userList.checkUser(requester)) {
                                if (my_gs.groupList.checkGroup(groupname)) {
                                    if (my_gs.groupList.getGroupOwner(groupname).equals(requester)) {
                                        if (my_gs.userList.getShown(requester).contains(groupname)) {
                                            response = new Envelope("OK"); //Success
                                            List<String> members = my_gs.groupList.getGroupUsers(groupname); //Extracts current members within group
                                            members.add(0, requester); //Owner of group inherently included
            
                                            for(int i=0; i<members.size(); i++){ //Ran into issues when pushing a List<String> 
                                                response.addObject(members.get(i));
                                            }
                                            logging.info("\tSuccess");
                                        } else { //Prints reason why it fails
                                            response = new Envelope("FAIL-LMEMBERS");
                                            action = "\t"+requester+" has not escalated permissions for group "+groupname+"\n";
                                            response.addObject(action.substring(1,action.length()-1));
                                            logging.info(String.format("%s", action));
                                        }
                                    } else { //Prints reason why it fails
                                        response = new Envelope("FAIL-LMEMBERS");
                                        action = "\t"+requester+" is not owner of group "+groupname+"\n";
                                        response.addObject(action.substring(1,action.length()-1));
                                        logging.info(String.format("%s", action));
                                    }
                                } else { //Prints reason why it fails
                                    response = new Envelope("FAIL-LMEMBERS");
                                    action = "\t"+requester+" is not a member of group "+groupname+"\n";
                                    response.addObject(action.substring(1,action.length()-1));
                                    logging.info(String.format("%s", action));
                                }
                            } else { //Prints reason why it fails
                                response = new Envelope("FAIL-LMEMBERS");
                                action = "\t"+requester+" is not a user on the server \n";
                                response.addObject(action.substring(1,action.length()-1));
                                logging.info(String.format("%s", action));
                            }
                        }
                    }
                    output.writeObject(response);
                } else if (message.getMessage().equals("AUSERTOGROUP")) { //Client wants to add user to a group
                    /* TODO:  Write this handler */
                    if (message.getObjContents().size() != 3) {
                        response = new Envelope("FAIL-BADCONTENTS");
                        action="\tFAIL-AUSERTOGROUP | as request has bad contents.\n";
                        response.addObject(action.substring(1,action.length()-1));
                        logging.info(String.format("%s", action));
                    } else {
                        if (message.getObjContents().get(0) == null) {
                            response = new Envelope("FAIL-BADUSER");
                            action="\tFAIL-AUSERTOGROUP | as request has bad user.\n";
                            response.addObject(action.substring(1,action.length()-1));
                            logging.info(String.format("%s", action));
                        }
                        if (message.getObjContents().get(1) == null) {
                            response = new Envelope("FAIL-BADGROUP");
                            action="\tFAIL-AUSERTOGROUP | as request has bad group.\n";
                            response.addObject(action.substring(1,action.length()-1));
                            logging.info(String.format("%s", action));
                        }
                        if (message.getObjContents().get(2) == null) {
                            response = new Envelope("FAIL-BADTOKEN");
                            action="\tFAIL-AUSERTOGROUP | as request has bad token.\n";
                            response.addObject(action.substring(1,action.length()-1));
                            logging.info(String.format("%s", action));
                        } else {
                            String toAddUsername = (String)message.getObjContents().get(0); //Extract desired user to add
                            String groupName = (String)message.getObjContents().get(1); //Extract desired groupname to add user to
                            UserToken yourToken = (UserToken)message.getObjContents().get(2); //Extract the user's token

                            logging.info(String.format("\tAUSERTOGROUP %s %s by %s", toAddUsername, groupName, yourToken.getSubject()));

                            action = addUserToGroup(toAddUsername, groupName, yourToken); //Adds given user to given group
                            if (action.equals("OK")){
                                response = new Envelope("OK");
                                logging.info("\tSuccess");
                            } else { //Prints reason why it fails
                                response = new Envelope("FAIL-AUSERTOGROUP");
                                response.addObject(action.substring(1,action.length()-1));
                                logging.info(String.format("%s", action));
                            }
                        }
                    }
                    output.writeObject(response);
                } else if (message.getMessage().equals("RUSERFROMGROUP")) { //Client wants to remove user from a group
                    /* TODO:  Write this handler */
                    if (message.getObjContents().size() != 3) {
                        response = new Envelope("FAIL-BADCONTENTS");
                        action="\tFAIL-RUSERFROMGROUP | as request has bad contents.\n";
                        response.addObject(action.substring(1,action.length()-1));
                        logging.info(String.format("%s", action));
                    } else {
                        if (message.getObjContents().get(0) == null) {
                            response = new Envelope("FAIL-BADUSER");
                            action="\tFAIL-RUSERFROMGROUP | as request has bad user.\n";
                            response.addObject(action.substring(1,action.length()-1));
                            logging.info(String.format("%s", action));
                        }
                        if (message.getObjContents().get(1) == null) {
                            response = new Envelope("FAIL-BADGROUP");
                            action="\tFAIL-RUSERFROMGROUP | as request has bad group.\n";
                            response.addObject(action.substring(1,action.length()-1));
                            logging.info(String.format("%s", action));
                        }
                        if (message.getObjContents().get(2) == null) {
                            response = new Envelope("FAIL-BADTOKEN");
                            action="\tFAIL-RUSERFROMGROUP | as request has bad token.\n";
                            response.addObject(action.substring(1,action.length()-1));
                            logging.info(String.format("%s", action));
                        } else {
                            String toRemoveUsername = (String)message.getObjContents().get(0); //Extract desired user to remvoe
                            String groupName = (String)message.getObjContents().get(1); //Extract desired groupname to remove user to
                            UserToken yourToken = (UserToken)message.getObjContents().get(2); //Extract the user's token

                            logging.info(String.format("\tRUSERFROMGROUP %s %s by %s", toRemoveUsername, groupName, yourToken.getSubject()));

                            action = removeUserFromGroup(toRemoveUsername, groupName, yourToken); //Removes given user from given group
                            if (action.equals("OK")){
                                response = new Envelope("OK");
                                logging.info("\tSuccess");
                            } else { //Prints reason why it fails
                                response = new Envelope("FAIL-RUSERFROMGROUP");
                                response.addObject(action.substring(1,action.length()-1));
                                logging.info(String.format("%s", action));
                            }
                        }
                    }
                    output.writeObject(response);
                } else if (message.getMessage().equals("SHOW")) { //Client wants to add a group to their scope
                    /* TODO:  Write this handler */
                    if (message.getObjContents().size() != 2) {
                        response = new Envelope("FAIL-BADCONTENTS");
                        action="\tFAIL-SHOW | as request has bad contents.\n";
                        response.addObject(action.substring(1,action.length()-1));
                        logging.info(String.format("%s", action));
                    } else {
                        if (message.getObjContents().get(0) == null) {
                            response = new Envelope("FAIL-BADGROUP");
                            action="\tFAIL-SHOW | as request has bad group.\n";
                            response.addObject(action.substring(1,action.length()-1));
                            logging.info(String.format("%s", action));
                        }
                        if (message.getObjContents().get(1) == null) {
                            response = new Envelope("FAIL-TOKEN");
                            action="\tFAIL-SHOW | as request has bad token.\n";
                            response.addObject(action.substring(1,action.length()-1));
                            logging.info(String.format("%s", action));
                        } else {
                            String groupName = (String)message.getObjContents().get(0); //Extract desired groupname to add to scope
                            UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the user's token

                            logging.info(String.format("\tSHOW %s by %s", groupName, yourToken.getSubject()));

                            action = showGroup(groupName,yourToken); //Adds given group to user's scope
                            if (action.equals("OK")){
                                response = new Envelope("OK");
                                logging.info("\tSuccess");
                            } else { //Prints reason why it fails
                                response = new Envelope("FAIL-SHOW");
                                response.addObject(action.substring(1,action.length()-1));
                                logging.info(String.format("%s", action));
                            }
                        }
                    }
                    output.writeObject(response);
                } else if (message.getMessage().equals("SHOWALL")) { //Client wants to add all groups to their scope
                    /* TODO:  Write this handler */
                    if (message.getObjContents().size() != 1) {
                        response = new Envelope("FAIL-BADCONTENTS");
                        action="\tFAIL-SHOWALL | as request has bad contents.\n";
                        response.addObject(action.substring(1,action.length()-1));
                        logging.info(String.format("%s", action));
                    } else {
                        if (message.getObjContents().get(0) == null) {
                            response = new Envelope("FAIL-BADTOKEN");
                            action="\tFAIL-SHOWALL | as request has bad token.\n";
                            response.addObject(action.substring(1,action.length()-1));
                            logging.info(String.format("%s", action));
                        } else {
                            UserToken yourToken = (UserToken)message.getObjContents().get(0); //Extract the user's token

                            logging.info(String.format("\tSHOWALL by %s", yourToken.getSubject()));

                            action = showAll(yourToken); //Adds all groups possible to the user's scope
                            if (action.equals("OK")){
                                response = new Envelope("OK");
                                logging.info("\tSuccess");
                            } else { //Prints reason why it fails
                                response = new Envelope("FAIL-SHOWALL");
                                response.addObject(action.substring(1,action.length()-1));
                                logging.info(String.format("%s", action));
                            }
                        }
                    }
                    output.writeObject(response);
                } else if (message.getMessage().equals("HIDE")) { //Client wants to remove a group from their scope
                    /* TODO:  Write this handler */
                    if (message.getObjContents().size() != 2) {
                        response = new Envelope("FAIL-BADCONTENTS");
                        action="\tFAIL-HIDE | as request has bad contents.\n";
                        response.addObject(action.substring(1,action.length()-1));
                        logging.info(String.format("%s", action));
                    } else {
                        if (message.getObjContents().get(0) == null) {
                            response = new Envelope("FAIL-BADGROUP");
                            action="\tFAIL-HIDE | as request has bad group.\n";
                            response.addObject(action.substring(1,action.length()-1));
                            logging.info(String.format("%s", action));
                        }
                        if (message.getObjContents().get(1) == null) {
                            response = new Envelope("FAIL-BADTOKEN");
                            action="\tFAIL-HIDE | as request has bad token.\n";
                            response.addObject(action.substring(1,action.length()-1));
                            logging.info(String.format("%s", action));
                        } else {
                            String groupName = (String)message.getObjContents().get(0); //Extract desired groupname to add user to
                            UserToken yourToken = (UserToken)message.getObjContents().get(1); //Extract the user's token

                            logging.info(String.format("\tHIDE %s by %s", groupName, yourToken.getSubject()));

                            action = hideGroup(groupName, yourToken); //Removes given group from user's scope
                            if (action.equals("OK")){
                                response = new Envelope("OK");
                                logging.info("\tSuccess");
                            } else { //Prints reason why it fails
                                response = new Envelope("FAIL-HIDE");
                                response.addObject(action.substring(1,action.length()-1));
                                logging.info(String.format("%s", action));
                            }
                        }
                    }
                    output.writeObject(response);
                } else if (message.getMessage().equals("HIDEALL")) { //Client wants to remove all groups from their scope
                    /* TODO:  Write this handler */
                    if (message.getObjContents().size() != 1) {
                        response = new Envelope("FAIL-BADCONTENTS");
                        action="\tFAIL-HIDEALL | as request has bad contents.\n";
                        response.addObject(action.substring(1,action.length()-1));
                        logging.info(String.format("%s", action));
                    } else {
                        if (message.getObjContents().get(0) == null) {
                            response = new Envelope("FAIL-BADTOKEN");
                            action="\tFAIL-HIDEALL | as request has bad token.\n";
                            response.addObject(action.substring(1,action.length()-1));
                            logging.info(String.format("%s", action));
                        } else {
                            UserToken yourToken = (UserToken)message.getObjContents().get(0); //Extract the user's token

                            logging.info(String.format("\tHIDEALL by %s", yourToken.getSubject()));

                            action = hideAll(yourToken); //Removes all groups from the user's scope
                            if (action.equals("OK")){
                                response = new Envelope("OK");
                                logging.info("\tSuccess");
                            } else { //Prints reason why it fails
                                response = new Envelope("FAIL-HIDEALL");
                                response.addObject(action.substring(1,action.length()-1));
                                logging.info(String.format("%s", action));
                            }
                        }
                    }
                    output.writeObject(response);
                } else if (message.getMessage().equals("CURKEY")) {
                    //Expects Token, Groupname
                    //Returns Key and ID
                    response = new Envelope("FAILED");
                    if (message.getObjContents().size() != 2) {
                        response = new Envelope("FAIL-BADCONTENTS");
                        action="\tFAIL-CURKEY | as request has bad contents.\n";
                        response.addObject(action.substring(1,action.length()-1));
                        logging.info(String.format("%s", action));
                    } else {
                        UserToken token = (UserToken)message.getObjContents().get(0); //Token
                        String groupname = (String)message.getObjContents().get(1); //Groupname

                        logging.info(String.format("\tCURKEY %s by %s", groupname, token.getSubject()));

                        if (token == null) {
                            response = new Envelope("FAIL-BADTOKEN");
                            action="\tFAIL-CURKEY | as request has bad token.\n";
                            response.addObject(action.substring(1,action.length()-1));
                            logging.info(String.format("%s", action));
                        } else if (groupname == null) {
                            response = new Envelope("FAIL-GROUPNAME");
                            action="\tFAIL-CURKEY | request has bad groupname.\n";
                            response.addObject(action.substring(1,action.length()-1));
                            logging.info(String.format("%s", action));
                        } else {
                            SecretKey currentKey = my_gs.groupList.getKey(token.getSubject(), groupname);
                            String id = my_gs.groupList.getID(token.getSubject(), groupname);

                            if (currentKey == null) {
                                response = new Envelope("FAIL-UNAUTHORIZED");
                                action="\tFAIL-CURKEY | requestor is not in group "+groupname+"\n";
                                response.addObject(action.substring(1,action.length()-1));
                                logging.info(String.format("%s", action));
                            } else if (id == null) {
                                response = new Envelope("FAIL-UNAUTHORIZED");
                                action="\tFAIL-CURKEY | requestor is not in group "+groupname+"\n";
                                response.addObject(action.substring(1,action.length()-1));
                                logging.info(String.format("%s", action));
                            } else {
                                response = new Envelope("OK");
                                response.addObject(currentKey);
                                response.addObject(id);
                                logging.info("\tSuccess");
                            }
                        }

                    }
                    output.writeObject(response);
                } else if (message.getMessage().equals("KEYID")) {
                    //Expects Token, Groupname, ID
                    //Returns Key
                    response = new Envelope("FAILED");
                    if (message.getObjContents().size() != 3) {
                        response = new Envelope("FAIL-BADCONTENTS");
                        action="\tFAIL-KEYID | as request has bad contents.\n";
                        response.addObject(action.substring(1,action.length()-1));
                        logging.info(String.format("%s", action));
                    } else {
                        UserToken token = (UserToken)message.getObjContents().get(0); //Token
                        String groupname = (String)message.getObjContents().get(1); //Groupname
                        String id = (String)message.getObjContents().get(2); //Unique ID

                        logging.info(String.format("\tKEYID %s by %s", groupname, token.getSubject()));

                        if (token == null) {
                            response = new Envelope("FAIL-BADTOKEN");
                            action="\tFAIL-KEYID | as request has bad token.\n";
                            response.addObject(action.substring(1,action.length()-1));
                            logging.info(String.format("%s", action));
                        } else if (groupname == null) {
                            response = new Envelope("FAIL-GROUPNAME");
                            action="\tFAIL-KEYID | request has bad groupname.\n";
                            response.addObject(action.substring(1,action.length()-1));
                            logging.info(String.format("%s", action));
                        } else if (id == null) {
                            response = new Envelope("FAIL-BADID");
                            action="\tFAIL-KEYID | request had bad ID.\n";
                            response.addObject(action.substring(1,action.length()-1));
                            logging.info(String.format("%s", action));
                        } else {
                            SecretKey someKey = my_gs.groupList.getKey(token.getSubject(), groupname, id);

                            if (someKey == null) {
                                response = new Envelope("FAIL-UNAUTHORIZED");
                                action="\tFAIL-KEYID | requestor is not in group "+groupname+"\n";
                                response.addObject(action.substring(1,action.length()-1));
                                logging.info(String.format("%s", action));
                            } else {
                                response = new Envelope("OK");
                                response.addObject(someKey);
                                logging.info("\tSuccess");
                            }
                        }

                    }
                    output.writeObject(response);
                } else if (message.getMessage().equals("RESET")) {
                    response = new Envelope("FAILED");
                    if (message.getObjContents().size() != 2) {
                        response = new Envelope("FAIL-BADCONTENTS");
                        action="\tFAIL-RESET | as request has bad contents.\n";
                        response.addObject(action.substring(1,action.length()-1));
                        logging.info(String.format("%s", action));
                    } else {
                        UserToken token = (UserToken)message.getObjContents().get(0);
                        String passHash = (String)message.getObjContents().get(1);

                        if (token == null) {
                            response = new Envelope("FAIL-BADTOKEN");
                            action="\tFAIL-RESET | as request has bad token.\n";
                            response.addObject(action.substring(1,action.length()-1));
                            logging.info(String.format("%s", action));
                        } else if (passHash == null) {
                            response = new Envelope("FAIL-BADPASS");
                            action="\tFAIL-RESET | as request has a bad password.\n";
                            response.addObject(action.substring(1,action.length()-1));
                            logging.info(String.format("%s", action));
                        } else {
                            String usrHash = my_gs.userList.getPasswordHash(token.getSubject());
                            if (usrHash == null) {
                                response = new Envelope("FAIL-BADTOKEN");
                                action="\tFAIL-RESET | as user is not in the system.\n";
                                response.addObject(action.substring(1,action.length()-1));
                                logging.info(String.format("%s", action));
                            } else {
                                my_gs.userList.reset(token.getSubject());
                                response = new Envelope("OK");
                                logging.info("\tSuccess");
                            }
                        }
                    }
                    output.writeObject(response);
                } else if (message.getMessage().equals("DISCONNECT")) { //Client wants to disconnect
                    socket.close(); //Close the socket
                    proceed = false; //End this communication loop
                } else if (
                    message.getMessage().equals("FAIL-MSGCOUNT") ||
                    message.getMessage().equals("FAIL-HMAC")
                ) { // Error in reading message
                    response = message;
                    action = (String) message.getObjContents().get(0);
                    logging.info(String.format("\t%s\n", action));
                } else {
                    response = new Envelope("FAIL"); //Server does not understand client request
                    output.writeObject(response);
                }
            } while(proceed);
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }

    private boolean verifyServer(
        EncryptedObjectInputStream input,
        EncryptedObjectOutputStream output
    ) {
        try {
            Envelope response = new Envelope("GROUP");
            String puzzle = "";
            if (my_gs.getCompPuzzle()) {
                puzzle = ComputationPuzzle.generatePuzzle();
            } else {
                puzzle = ComputationPuzzle.generateKnownPuzzle();
            }
            response.addObject(puzzle);
            output.writeObject(response);

            response = (Envelope)input.readObject();
            if (response.getMessage().equals("FAIL")) {
                return false;
            }

            String target = (String)response.getObjContents().get(0);
            if (ComputationPuzzle.compareResults(puzzle, target)) {
                System.out.println("Computational Puzzle Succeeded");
                response = new Envelope("SUCCESS");
                response.addObject(null);
                output.writeObject(response);
                return true;
            } else {
                System.out.println("Computational Puzzle Failed");
                response = new Envelope("FAIL");
                response.addObject(null);
                output.writeObject(response);
                return false;
            }
        } catch(Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    UserToken refreshToken(String username, String fsPubKey){
        //Issue a refreshed token while maintaining user's scope
        UserToken yourToken = new Token(
            my_gs.name,
            username,
            my_gs.userList.getUserGroups(username),
            my_gs.userList.getShown(username),
            my_gs.userList.getPasswordHash(username),
            my_gs.getRSAKey(),
            fsPubKey
        );
        return yourToken;
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

    //Method to create tokens
    UserToken createToken(String username, boolean flag, boolean reset, String fsPubKey) {
        //Check that user exists
        if (my_gs.userList.checkUser(username)) {
            if (flag) {
                //Issue a refreshed token while maintaining user's scope
                UserToken yourToken = new Token(
                    my_gs.name,
                    username,
                    my_gs.userList.getUserGroups(username),
                    my_gs.userList.getShown(username),
                    my_gs.userList.getPasswordHash(username),
                    my_gs.getRSAKey(),
                    fsPubKey
                );
                return yourToken;
            } else {
                //Issue a new token with server's name, user's name, and user's groups
                UserToken yourToken = new Token(
                    my_gs.name,
                    username,
                    my_gs.userList.getUserGroups(username),
                    my_gs.userList.getPasswordHash(username),
                    my_gs.getRSAKey()
                );
                if(reset){ //When doing a GET, you don't want to reset an active user's scope
                    my_gs.userList.resetShown(username);
                }
                return yourToken;
            }
        } else {
            return null;
        }
    }

    //Method to create a user
    String createUser(String username, UserToken yourToken, String passSecret) {
        if (yourToken == null || !yourToken.verify()) {
            return "\tUserToken was invalid\n";
        }

        String requester = yourToken.getSubject();

        //Check that user is not only within the ADMIN group but also has it within their scope
        if (!yourToken.getShownGroups().contains("ADMIN") && yourToken.getGroups().contains("ADMIN")) {
            return "\t"+requester+" has not escalated permissions for group ADMIN\n";
        }

        String out="FAIL";

        //Check if requester exists
        if (my_gs.userList.checkUser(requester)) {
            //Get the user's groups
            ArrayList<String> temp = my_gs.userList.getShown(requester);
            //requester needs to be an administrator
            if (temp.contains("ADMIN")) {
                //Does user already exist?
                if (my_gs.userList.checkUser(username)) {
                    out="\t"+username+" is already a user within the system\n";
                    return out; //User already exists
                } else {
                    my_gs.userList.addUser(username, passSecret);
                    return "OK";
                }
            } else {
                out="\t"+requester+" is not an ADMIN within the system\n";
                return out; //requester not an administrator
            }
        } else {
            out="\t"+requester+" is not a user within the system\n";
            return out; //requester does not exist
        }
    }

    //Method to delete a user
    String deleteUser(String username, UserToken yourToken) {
        if (yourToken == null || !yourToken.verify()) {
            return "\tUserToken was invalid\n";
        }

        String requester = yourToken.getSubject();

        //Check that user is not only within the ADMIN group but also has it within their scope
        if (!yourToken.getShownGroups().contains("ADMIN") && yourToken.getGroups().contains("ADMIN")) {
            return "\t"+requester+" has not escalated permissions for group ADMIN\n";
        }

        String out="FAIL";

        //Does requester exist?
        if (my_gs.userList.checkUser(requester)) {
            ArrayList<String> temp = my_gs.userList.getShown(requester);
            //requester needs to be an administer
            if (temp.contains("ADMIN")) {
                //Does user exist?
                if (my_gs.userList.checkUser(username)) {
                    //User needs deleted from the groups they belong
                    ArrayList<String> deleteFromGroups = new ArrayList<String>();

                    //This will produce a hard copy of the list of groups this user belongs
                    for(int index = 0; index < my_gs.userList.getUserGroups(username).size(); index++) {
                        deleteFromGroups.add(my_gs.userList.getUserGroups(username).get(index));
                    }

                    //Delete the user from the groups
                    //If user is the owner, removeMember will automatically delete group!
                    for(int index = 0; index < deleteFromGroups.size(); index++) {
                        my_gs.groupList.removeMember(username, deleteFromGroups.get(index));
                    }

                    //If groups are owned, they must be deleted
                    ArrayList<String> deleteOwnedGroup = new ArrayList<String>();

                    //Make a hard copy of the user's ownership list
                    for(int index = 0; index < my_gs.userList.getUserOwnership(username).size(); index++) {
                        deleteOwnedGroup.add(my_gs.userList.getUserOwnership(username).get(index));
                    }

                    //Delete owned groups
                    for(int index = 0; index < deleteOwnedGroup.size(); index++) {
                        //Use the delete group method. Token must be created for this action
                        deleteGroup(
                            deleteOwnedGroup.get(index),
                            new Token(
                                my_gs.name,
                                username,
                                deleteOwnedGroup,
                                yourToken.getPasswordSecret(),
                                my_gs.getRSAKey()
                            )
                        );
                    }

                    //Delete the user from the user list
                    my_gs.userList.deleteUser(username);

                    out="OK";
                    return out;
                } else {
                    out="\t"+username+" is not a user within the system\n";
                    return out; //User does not exist

                }
            } else {
                out="\t"+requester+" is not an ADMIN within the system\n";
                return out; //requester is not an administer
            }
        } else {
            out="\t"+requester+" is not a user within the system\n";
            return out; //requester does not exist
        }
    }

    String deleteGroup(String groupname, UserToken token) {
        if (token == null || !token.verify()) {
            return "\tUserToken was invalid\n";
        }

        // TODO: Delete the group
        String requester = token.getSubject();        

        //Check that user is not only within the groupname group but also has it within their scope
        if (!token.getShownGroups().contains(groupname) && token.getGroups().contains(groupname)) {
            return "\t"+requester+" has not escalated permissions for group "+groupname+"\n";
        }

        String out="FAIL";

        if (my_gs.userList.checkUser(requester)) {
            if (my_gs.groupList.checkGroup(groupname)) {
                String groupOwner = my_gs.groupList.getGroupOwner(groupname);
                if (requester.equals(groupOwner)) {
                    ArrayList<String> groupUsers = my_gs.groupList.getGroupUsers(groupname); //Get current users within group
                    for(int index = 0; index < groupUsers.size(); index++) { //Removes users from group 
                        my_gs.userList.removeGroup(groupUsers.get(index), groupname);
                        UserToken remove = createToken(groupUsers.get(index), false, false, "");
                        remove.removeFromGroup(groupname);
                    }
                    my_gs.groupList.deleteGroup(groupname); //Why we don't need to remove individual members from the group
                    //Remove owner 
                    my_gs.userList.removeGroup(requester, groupname);
                    my_gs.userList.removeOwnership(requester, groupname);
                    token.removeFromGroup(groupname);
                    return "OK";
                } else {
                    out="\t"+requester+" is not owner of group "+groupname+"\n";
                }
            } else {
                out="\t"+groupname+" is not already a group within the system\n";
            }
        } else {
            out="\t"+requester+" is not a user within the system\n";
        }
        return out;
    }

    String createGroup(String groupname, UserToken token) {
        if (token == null || !token.verify()) {
            return "\tUserToken was invalid\n";
        }

        String requester = token.getSubject();

        String out="FAIL";

        if (my_gs.userList.checkUser(requester)) {
            if (!my_gs.groupList.checkGroup(groupname)){
                //Creates group and adds owner information 
                my_gs.userList.addGroup(requester, groupname);
                my_gs.groupList.addGroup(groupname, requester);
                my_gs.userList.addOwnership(requester, groupname);
                token.addToGroup(groupname);
                return "OK";
            } else {
                out="\t"+groupname+" is already a group within the system\n";
            }
        } else {
            out="\t"+requester+" is not a user within the system\n";
        }
        return out;
    }

    String addUserToGroup(String toAdd, String groupname, UserToken token) {
        if (token == null || !token.verify()) {
            return "\tUserToken was invalid\n";
        }

        String requester = token.getSubject();
        UserToken toAddToken = createToken(toAdd, false, false, "");

        //Check that user is not only within the groupname group but also has it within their scope
        if (!token.getShownGroups().contains(groupname)) {
            return "\t"+requester+" has not escalated permissions for group "+groupname+"\n";
        }

        String out="FAIL";

        //Both toAdd and requester are in groups and group exists
        if (my_gs.userList.checkUser(requester)) {
            if (my_gs.userList.checkUser(toAdd)) {
                if (my_gs.groupList.checkGroup(groupname)) {
                    if (!requester.equals(toAdd)) {
                        if (toAddToken!=null) { 
                            ArrayList<String> currentGroupsForNewUser = my_gs.userList.getUserGroups(toAdd); 
                            String owner = my_gs.groupList.getGroupOwner(groupname);
                
                            if (!currentGroupsForNewUser.contains(groupname)) {
                                if (requester.equals(owner)) {
                                    //Adds user to group on all aspects
                                    my_gs.userList.addGroup(toAdd, groupname);
                                    my_gs.groupList.addMember(toAdd, groupname);
                                    toAddToken.addToGroup(groupname);
                                    return "OK";
                                } else {
                                    out="\t"+requester+" is not owner of group "+groupname+"\n";
                                }
                            } else {
                                out="\t"+toAdd+" is already apart of group "+groupname+"\n";
                            }
                        } else {
                            out="\tToken is null\n";
                        }
                    } else {
                        out="\t"+requester+" and "+toAdd+" are the same. This would create a permenant group\n";
                    }
                } else {
                    out="\t"+groupname+" not a group within the system\n";
                }
            } else {
                out="\t"+toAdd+" is not a user within the system\n";
            }
        } else {
            out="\t"+requester+" is not a user within the system\n";
        }
        return out;
    }

    String removeUserFromGroup(String toRemove, String groupname, UserToken token) {
        if (token == null || !token.verify()) {
            return "\tUserToken was invalid\n";
        }

        String requester = token.getSubject();
        UserToken toRemoveToken = createToken(toRemove, false, false, "");

        //Check that user is not only within the groupname group but also has it within their scope
        if (!token.getShownGroups().contains(groupname) && token.getGroups().contains(groupname)) {
            return "\t"+requester+" has not escalated permissions for group "+groupname+"\n";
        }

        String out="FAIL";

        //Both toRemove and requester are in groups and group exists
        if (my_gs.userList.checkUser(requester)) {
            if (my_gs.userList.checkUser(toRemove)) {
                if (my_gs.groupList.checkGroup(groupname)) { 
                    if (!requester.equals(toRemove)) {
                        if (toRemoveToken!=null) {
                            ArrayList<String> currentGroupsForNewUser = my_gs.userList.getUserGroups(toRemove);
                            String owner = my_gs.groupList.getGroupOwner(groupname);
                
                            if (currentGroupsForNewUser.contains(groupname)) {
                                if (requester.equals(owner)) {
                                    //Removes user from group on all aspects
                                    my_gs.userList.removeGroup(toRemove, groupname);
                                    my_gs.groupList.removeMember(toRemove, groupname);
                                    toRemoveToken.removeFromGroup(groupname);
                                    return "OK";
                                } else {
                                    out="\t"+requester+" is not owner of group "+groupname+"\n";
                                }
                            }else {
                                out="\t"+toRemove+" is not apart of group "+groupname+"\n";
                            }
                        } else {
                            out="\tToken is null\n";
                        }
                    } else {
                        out="\t"+requester+" and "+toRemove+" are the same. This would create a permenant group\n";
                    }
                } else {
                    out="\t"+groupname+" not a group within the system\n";
                }
            } else {
                out="\t"+toRemove+" is not a user within the system\n";
            }
        } else {
            out="\t"+requester+" is not a user within the system\n";
        }
        return out;
    }

    String showGroup(String groupname, UserToken token) {
        if (token == null || !token.verify()) {
            return "\tUserToken was invalid\n";
        }

        String requester = token.getSubject();

        String out="FAIL";

        if (my_gs.userList.checkUser(requester)){
            if (token.getGroups().contains(groupname)) {
                if (!token.getShownGroups().contains(groupname)) {
                    //Adds group to user's scope
                    my_gs.userList.addShown(requester, groupname);
                    token.addToShown(groupname);
                    return "OK";
                } else {
                    out="\t"+requester+" already escalated to show group "+groupname+"\n";
                }
            } else {
                out="\t"+requester+" is not a member of group "+groupname+"\n";
            }
        } else {
            out="\t"+requester+" is not a user within the system\n";
        }
        return out;
    }

    String showAll(UserToken token) {
        if (token == null || !token.verify()) {
            return "\tUserToken was invalid\n";
        }

        String requester = token.getSubject();

        String out="FAIL";

        if (my_gs.userList.checkUser(requester)) {
            //Adds all groups that user is in to user's scope
            List<String> groups = token.getGroups();
            List<String> shownGroups = token.getShownGroups();
            for(int index = 0; index < groups.size(); index++) {
                if (!shownGroups.contains(groups.get(index))) {
                    my_gs.userList.addShown(requester, groups.get(index));
                    token.addToShown(groups.get(index));
                }
            }
            return "OK";
        } else {
            out="\t"+requester+" is not a user within the system\n";
        }
        return out;
    }

    String hideGroup(String groupname, UserToken token) {
        if (token == null || !token.verify()) {
            return "\tUserToken was invalid\n";
        }

        String requester = token.getSubject();

        String out="FAIL";

        if (my_gs.userList.checkUser(requester)) { 
            if (token.getShownGroups().contains(groupname)) {
                //Removes group from user's scope
                my_gs.userList.removeShown(requester, groupname);
                token.removeFromShown(groupname); 
                return "OK";
            } else {
                out="\t"+requester+" has not escalated to see group "+groupname+"\n";
            }
        } else {
            out="\t"+requester+" is not a user within the system\n";
        }
        return out;
    }

    String hideAll(UserToken token) {
        if (token == null || !token.verify()) {
            return "\tUserToken was invalid\n";
        }

        String requester = token.getSubject();

        String out="FAIL";

        if (my_gs.userList.checkUser(requester)) {
            //Removes all groups within user's scope
            List<String> shownGroups = token.getShownGroups();
            for(int index = 0; index < shownGroups.size(); index++) {
                my_gs.userList.removeShown(requester, shownGroups.get(index));
                token.removeFromShown(shownGroups.get(index));
            }
            return "OK";
        } else {
            out="\t"+requester+" is not a user within the system\n";
        }
        return out;
    }

    byte[] hashPassword(final char[] password, final byte[] salt, final int iterations, final int keyLength ) {
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance( "PBKDF2WithHmacSHA512" );
            PBEKeySpec spec = new PBEKeySpec( password, salt, iterations, keyLength );
            SecretKey key = skf.generateSecret( spec );
            byte[] res = key.getEncoded( );
            return res;
        } catch ( NoSuchAlgorithmException | InvalidKeySpecException e ) {
            throw new RuntimeException( e );
        }
    }

    boolean isStrong(String pwd) {
        try {
            File dictionary = new File("top1000000.txt");
            Scanner dictRead = new Scanner(dictionary);
            while (dictRead.hasNextLine()) {
                String ref = dictRead.nextLine();
                if (pwd.equals(ref) || similarity(ref, pwd) >= 80.0) {
                    System.out.println(ref);
                    return false;
                }
            }
        } catch(Exception e) {

        }

        double nScore=0, nLength=0, nAlphaUC=0, nAlphaLC=0, nNumber=0, nSymbol=0, nMidChar=0, nRequirements=0, nAlphasOnly=0, nNumbersOnly=0, nUnqChar=0, nRepChar=0, nConsecAlphaUC=0, nConsecAlphaLC=0, nConsecNumber=0, nConsecSymbol=0, nConsecCharType=0, nSeqAlpha=0, nSeqNumber=0, nSeqSymbol=0, nRepInc=0, nSeqChar=0, nReqChar=0, nMultConsecCharType=0;
        double nMultRepChar=1, nMultConsecSymbol=1;
        double nMultMidChar=2, nMultRequirements=2, nMultConsecAlphaUC=2, nMultConsecAlphaLC=2, nMultConsecNumber=2;
        double nReqCharType=3, nMultAlphaUC=3, nMultAlphaLC=3, nMultSeqAlpha=3, nMultSeqNumber=3, nMultSeqSymbol=3;
        double nMultLength=4, nMultNumber=4;
        double nMultSymbol=6;
        String nTmpAlphaUC="", nTmpAlphaLC="", nTmpNumber="", nTmpSymbol="";
        String sAlphaUC="0", sAlphaLC="0", sNumber="0", sSymbol="0", sMidChar="0", sRequirements="0", sAlphasOnly="0", sNumbersOnly="0", sRepChar="0", sConsecAlphaUC="0", sConsecAlphaLC="0", sConsecNumber="0", sSeqAlpha="0", sSeqNumber="0", sSeqSymbol="0";
        String sAlphas = "abcdefghijklmnopqrstuvwxyz";
        String sNumerics = "01234567890";
        String sSymbols = ")!@#$%^&*()";
        double nMinPwdLen = 8;
        double nd = 0;

        nScore = pwd.length() * nMultLength;
        nLength = pwd.length();
        String[] arrPwd = pwd.split("");
        int arrPwdLen = arrPwd.length;
        
        /* Loop through password to check for Symbol, Numeric, Lowercase and Uppercase pattern matches */
        for (int a=0; a < arrPwdLen; a++) {
            if (sAlphas.toUpperCase().contains(arrPwd[a])) {
                if (nTmpAlphaUC != "") { if ((nTmpAlphaUC + 1) == ""+a) { nConsecAlphaUC++; nConsecCharType++; } }
                nTmpAlphaUC = ""+a;
                nAlphaUC++;
            }
            else if (sAlphas.contains(arrPwd[a])) { 
                if (nTmpAlphaLC != "") { if ((nTmpAlphaLC + 1) == ""+a) { nConsecAlphaLC++; nConsecCharType++; } }
                nTmpAlphaLC = ""+a;
                nAlphaLC++;
            }
            else if (sNumerics.contains(arrPwd[a])) { 
                if (a > 0 && a < (arrPwdLen - 1)) { nMidChar++; }
                if (nTmpNumber != "") { if ((nTmpNumber + 1) == ""+a) { nConsecNumber++; nConsecCharType++; } }
                nTmpNumber = ""+a;
                nNumber++;
            }
            else if (sSymbols.contains(arrPwd[a])) { 
                if (a > 0 && a < (arrPwdLen - 1)) { nMidChar++; }
                if (nTmpSymbol != "") { if ((nTmpSymbol + 1) == ""+a) { nConsecSymbol++; nConsecCharType++; } }
                nTmpSymbol = ""+a;
                nSymbol++;
            }
            /* Internal loop through password to check for repeat characters */
            boolean bCharExists = false;
            for (int b=0; b < arrPwdLen; b++) {
                if (arrPwd[a] == arrPwd[b] && a != b) { /* repeat character exists */
                    bCharExists = true;
                    nRepInc += Math.abs(arrPwdLen/(b-a));
                }
            }
            if (bCharExists) { 
                nRepChar++; 
                nUnqChar = arrPwdLen-nRepChar;
                nRepInc = (nUnqChar!=0) ? Math.ceil(nRepInc/nUnqChar) : Math.ceil(nRepInc); 
            }
        }
        
        /* Check for sequential alpha string patterns (forward and reverse) */
        for (int s=0; s < 23; s++) {
            String sFwd = sAlphas.substring(s,s+3);
            byte[] strAsByteArray = sFwd.getBytes();
            byte[] result = new byte[strAsByteArray.length];
            for (int i = 0; i < strAsByteArray.length; i++)
                result[i] = strAsByteArray[strAsByteArray.length - i - 1];

            String sRev = new String(result);
            if (pwd.toLowerCase().indexOf(sFwd) != -1 || pwd.toLowerCase().indexOf(sRev) != -1) { nSeqAlpha++; nSeqChar++;}
        }
        
        /* Check for sequential numeric string patterns (forward and reverse) */
        for (int s=0; s < 8; s++) {
            String sFwd = sNumerics.substring(s,s+3);
            byte[] strAsByteArray = sFwd.getBytes();
            byte[] result = new byte[strAsByteArray.length];
            for (int i = 0; i < strAsByteArray.length; i++)
                result[i] = strAsByteArray[strAsByteArray.length - i - 1];

            String sRev = new String(result);
            if (pwd.toLowerCase().indexOf(sFwd) != -1 || pwd.toLowerCase().indexOf(sRev) != -1) { nSeqNumber++; nSeqChar++;}
        }
        
        /* Check for sequential symbol string patterns (forward and reverse) */
        for (int s=0; s < 8; s++) {
            String sFwd = sSymbols.substring(s,s+3);
            byte[] strAsByteArray = sFwd.getBytes();
            byte[] result = new byte[strAsByteArray.length];
            for (int i = 0; i < strAsByteArray.length; i++)
                result[i] = strAsByteArray[strAsByteArray.length - i - 1];

            String sRev = new String(result);
            if (pwd.toLowerCase().indexOf(sFwd) != -1 || pwd.toLowerCase().indexOf(sRev) != -1) { nSeqSymbol++; nSeqChar++;}
        }
        
    /* Modify overall score value based on usage vs requirements */

        /* General point assignment */
        // $("nLengthBonus").innerHTML = "+ " + nScore; 
        if (nAlphaUC > 0 && nAlphaUC < nLength) {   
            nScore = (nScore + ((nLength - nAlphaUC) * 2));
            sAlphaUC = "+ " + ((nLength - nAlphaUC) * 2); 
        }
        if (nAlphaLC > 0 && nAlphaLC < nLength) {   
            nScore = (nScore + ((nLength - nAlphaLC) * 2)); 
            sAlphaLC = "+ " + ((nLength - nAlphaLC) * 2);
        }
        if (nNumber > 0 && nNumber < nLength) { 
            nScore = (nScore + (nNumber * nMultNumber));
            sNumber = "+ " + (nNumber * nMultNumber);
        }
        if (nSymbol > 0) {  
            nScore = (nScore + (nSymbol * nMultSymbol));
            sSymbol = "+ " + (nSymbol * nMultSymbol);
        }
        if (nMidChar > 0) { 
            nScore = (nScore + (nMidChar * nMultMidChar));
            sMidChar = "+ " + (nMidChar * nMultMidChar);
        }
        
        /* Point deductions for poor practices */
        if ((nAlphaLC > 0 || nAlphaUC > 0) && nSymbol == 0 && nNumber == 0) {  // Only Letters
            nScore = (nScore - nLength);
            nAlphasOnly = nLength;
            sAlphasOnly = "- " + nLength;
        }
        if (nAlphaLC == 0 && nAlphaUC == 0 && nSymbol == 0 && nNumber > 0) {  // Only Numbers
            nScore = (nScore - nLength); 
            nNumbersOnly = nLength;
            sNumbersOnly = "- " + nLength;
        }
        if (nRepChar > 0) {  // Same character exists more than once
            nScore = (nScore - nRepInc);
            sRepChar = "- " + nRepInc;
        }
        if (nConsecAlphaUC > 0) {  // Consecutive Uppercase Letters exist
            nScore = (nScore - (nConsecAlphaUC * nMultConsecAlphaUC)); 
            sConsecAlphaUC = "- " + (nConsecAlphaUC * nMultConsecAlphaUC);
        }
        if (nConsecAlphaLC > 0) {  // Consecutive Lowercase Letters exist
            nScore = (nScore - (nConsecAlphaLC * nMultConsecAlphaLC)); 
            sConsecAlphaLC = "- " + (nConsecAlphaLC * nMultConsecAlphaLC);
        }
        if (nConsecNumber > 0) {  // Consecutive Numbers exist
            nScore = (nScore - (nConsecNumber * nMultConsecNumber));  
            sConsecNumber = "- " + (nConsecNumber * nMultConsecNumber);
        }
        if (nSeqAlpha > 0) {  // Sequential alpha strings exist (3 characters or more)
            nScore = (nScore - (nSeqAlpha * nMultSeqAlpha)); 
            sSeqAlpha = "- " + (nSeqAlpha * nMultSeqAlpha);
        }
        if (nSeqNumber > 0) {  // Sequential numeric strings exist (3 characters or more)
            nScore = (nScore - (nSeqNumber * nMultSeqNumber)); 
            sSeqNumber = "- " + (nSeqNumber * nMultSeqNumber);
        }
        if (nSeqSymbol > 0) {  // Sequential symbol strings exist (3 characters or more)
            nScore = (nScore - (nSeqSymbol * nMultSeqSymbol)); 
            sSeqSymbol = "- " + (nSeqSymbol * nMultSeqSymbol);
        }
        return nScore>=60;
    }

    public static double similarity(String ref, String toCompare) {
        String longer = ref.toLowerCase();
        String shorter = toCompare.toLowerCase();
        if (ref.length() < toCompare.length()) { // longer should always have greater length
            longer = toCompare; shorter = ref;
        }
        if (longer.length() == 0) { return 1.0; /* both strings are zero length */ }

        int[] costs = new int[shorter.length() + 1];
        for (int i = 0; i <= longer.length(); i++) {
            int last = i;
            for (int j = 0; j <= shorter.length(); j++) {
                if (i == 0) {
                    costs[j] = j;
                } else {
                    if (j > 0) {
                        int val = costs[j - 1];
                        if (longer.charAt(i - 1) != shorter.charAt(j - 1)) {
                            val = Math.min(last, val);
                            val = Math.min(costs[j], val) + 1;
                        }
                        costs[j - 1] = last;
                        last = val;
                    }
                }
            }
            if (i > 0) {
                costs[shorter.length()] = last;
            }
        }

        return ((longer.length() - costs[shorter.length()]) / (double) longer.length())*100;
    }
}
