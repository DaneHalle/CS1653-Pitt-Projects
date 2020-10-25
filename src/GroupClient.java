/* Implements the GroupClient Interface */

import java.util.ArrayList;
import java.util.List;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;  // Used to write objects to the server
import java.io.BufferedReader;      // Needed to read from the console
import java.io.InputStreamReader;   // Needed to read from the console
import java.nio.ByteBuffer;

import java.util.StringTokenizer;
import java.util.Base64;
import java.util.*;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.KeyAgreement;
import javax.crypto.Cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.io.UnsupportedEncodingException;
import static javax.xml.bind.DatatypeConverter.printHexBinary;
import static javax.xml.bind.DatatypeConverter.parseHexBinary;

import java.security.Security;
import java.security.SecureRandom;
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

public class GroupClient extends Client implements GroupClientInterface {

    public UserToken getToken(String username, String password) {
        try {
            Security.addProvider(new BouncyCastleProvider());
            UserToken token = null;
            Envelope message1 = null, message2 = null, message3 = null, response = null;

            //Tell the server to return a token.
            message1 = new Envelope("GET");
            message1.addObject(username); //Username

            String salt = username;
            int iterations = 10000;
            int keyLength = 256;
            char[] passwordChars = password.toCharArray();
            byte[] saltBytes = salt.getBytes();
            byte[] hashedBytes = hashPassword(passwordChars, saltBytes, iterations, keyLength);
            String passSecret = Base64.getEncoder().encodeToString(hashedBytes); //First time logging in will be the temp password designated by admins 

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(256);
            KeyPair kp = kpg.generateKeyPair();
            byte[] ourPk = kp.getPublic().getEncoded();

            Cipher encrypt = Cipher.getInstance("AES/CBC/PKCS7PADDING");
            SecretKeySpec key = new SecretKeySpec(Base64.getEncoder().encode(hashedBytes), "AES");
            byte[] iv = new byte[16];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            encrypt.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
            byte[] encrypted = encrypt.doFinal(ourPk);

            message1.addObject(Base64.getEncoder().encodeToString(encrypted)); //{g^b mod p}W
            message1.addObject(ivParameterSpec);
            output.writeObject(message1); 

            //--------------------------------------------------------------

            message2 = (Envelope)input.readObject();
            if (message2.getMessage().equals("MESSAGE2")) {
                String encryptedKey = (String)message2.getObjContents().get(0);
                String encryptedChallenge = (String)message2.getObjContents().get(1);
                IvParameterSpec ivSpec = (IvParameterSpec)message2.getObjContents().get(2);

                Cipher decrypt = Cipher.getInstance("AES/CBC/PKCS7PADDING");
                decrypt.init(Cipher.DECRYPT_MODE, key, ivSpec);
                byte[] otherPk = decrypt.doFinal(Base64.getDecoder().decode(encryptedKey));
                byte[] otherChallenge = decrypt.doFinal(Base64.getDecoder().decode(encryptedChallenge));

                KeyFactory kf = KeyFactory.getInstance("EC");
                X509EncodedKeySpec pkSpec = new X509EncodedKeySpec(otherPk);
                PublicKey otherPublicKey = kf.generatePublic(pkSpec);
                
                KeyAgreement ka = KeyAgreement.getInstance("ECDH");
                ka.init(kp.getPrivate());
                ka.doPhase(otherPublicKey, true);

                byte[] sharedSecret = ka.generateSecret();
                MessageDigest hash = MessageDigest.getInstance("SHA-256");
                hash.update(sharedSecret);
                List<ByteBuffer> keys = Arrays.asList(ByteBuffer.wrap(ourPk), ByteBuffer.wrap(otherPk));
                Collections.sort(keys);
                hash.update(keys.get(0));
                hash.update(keys.get(1));
                byte[] derivedKey = hash.digest();
                String k = Base64.getEncoder().encodeToString(derivedKey);
                SecretKeySpec derived = new SecretKeySpec(derivedKey, "AES");

                SecureRandom challenge = new SecureRandom();

                iv = new byte[16];
                random = new SecureRandom();
                random.nextBytes(iv);
                ivParameterSpec = new IvParameterSpec(iv);
                encrypt.init(Cipher.ENCRYPT_MODE, derived, ivParameterSpec);
                byte[] encryptedOther = encrypt.doFinal(otherChallenge); //Server's challenge
                byte[] encryptedThis = encrypt.doFinal(challenge.generateSeed(64)); //Server's challenge

                message3 = new Envelope("MESSAGE3");
                message3.addObject(Base64.getEncoder().encodeToString(encryptedOther));
                message3.addObject(Base64.getEncoder().encodeToString(encryptedThis));
                message3.addObject(ivParameterSpec);
                output.writeObject(message3); 

                //--------------------------------------------------------------

                message4 = (Envelope)input.readObject();
                if (message4.getMessage().equals("MESSAGE4")) {
                    String encryptedThisChallenge = (String)message2.getObjContents().get(0);
                    ivSpec = (IvParameterSpec)message2.getObjContents().get(1);

                    decrypt = Cipher.getInstance("AES/CBC/PKCS7PADDING");
                    decrypt.init(Cipher.DECRYPT_MODE, derived, ivSpec);
                    byte[] decryptThisChallenge = decrypt.doFinal(Base64.getDecoder().decode(encryptedThisChallenge));

                    if (Base64.getEncoder().encodeToString(decryptThisChallenge).equals(encodedChallenge)) {
                        //Continue
                    } else {
                        //Return FAIL
                        return null;
                    }
                } else {
                    //Return FAIL
                    return null;
                }


            } else {
                //Return FAIL
                return null;
            }



            //Get the response from the server
            response = (Envelope)input.readObject();
            // boolean first=true; 
            // StringTokenizer cmd;
            // if(response.getMessage().equals("REQUEST-NEW"));
            // do {
            //     if (response.getMessage().equals("REQUEST-NEW")) {
            //         //Get some new password...how though?
            //         String print = first ? "The password entered for this user has expired, please enter a new password: " : "The password entered is the same as the previous password, please enter a new password: ";
            //         System.out.println(print);
            //         cmd = new StringTokenizer(readInput());
            //         message = new Envelope("NEW");
            //         message.addObject(cmd.nextToken());
            //         output.writeObject(message);
            //     }
            //     response = (Envelope)input.readObject();
            // } while (response.getMessage().equals("REQUEST-NEW"));

            //Successful response
            if(response.getMessage().equals("OK")) {
                //If there is a token in the Envelope, return it
                ArrayList<Object> temp = null;
                temp = response.getObjContents();

                if(temp.size() == 1) {
                    token = (UserToken)temp.get(0);
                    return token;
                }
            }

            return null;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return null;
        }

    }

    public UserToken refreshToken(UserToken token) {
        try {
            UserToken newToken = null;
            Envelope message = null, response = null;

            //Tell the server to return a token.
            message = new Envelope("REFRESH");
            message.addObject(token); //Add user name string
            message.addObject(token.getPasswordSecret());
            output.writeObject(message);

            //Get the response from the server
            response = (Envelope)input.readObject();

            //Successful response
            if(response.getMessage().equals("OK")) {
                //If there is a token in the Envelope, return it
                ArrayList<Object> temp = null;
                temp = response.getObjContents();

                if(temp.size() == 1) {
                    newToken = (UserToken)temp.get(0);

                    return newToken;
                }
            }

            return null;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return null;
        }

    }

    public boolean createUser(String username, UserToken token, String password) {
        try {
            Envelope message = null, response = null;
            //Tell the server to create a user
            message = new Envelope("CUSER");
            message.addObject(username); //Add user name string
            message.addObject(token); //Add the requester's token
            message.addObject(password);
            output.writeObject(message);

            response = (Envelope)input.readObject();

            //If server indicates success, return true
            if(response.getMessage().equals("OK")) {
                return true;
            }
            
            System.out.printf("FAILED: %s\n", response.getObjContents().get(0));
            return false;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

    public boolean deleteUser(String username, UserToken token) {
        try {
            Envelope message = null, response = null;

            //Tell the server to delete a user
            message = new Envelope("DUSER");
            message.addObject(username); //Add user name
            message.addObject(token);  //Add requester's token
            output.writeObject(message);

            response = (Envelope)input.readObject();

            //If server indicates success, return true
            if(response.getMessage().equals("OK")) {
                return true;
            }

            System.out.printf("FAILED: %s\n", response.getObjContents().get(0));
            return false;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

    public boolean createGroup(String groupname, UserToken token) {
        try {
            Envelope message = null, response = null;
            //Tell the server to create a group
            message = new Envelope("CGROUP");
            message.addObject(groupname); //Add the group name string
            message.addObject(token); //Add the requester's token
            output.writeObject(message);

            response = (Envelope)input.readObject();

            //If server indicates success, return true
            if(response.getMessage().equals("OK")) {
                return true;
            }

            System.out.printf("FAILED: %s\n", response.getObjContents().get(0));
            return false;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

    public boolean deleteGroup(String groupname, UserToken token) {
        try {
            Envelope message = null, response = null;
            //Tell the server to delete a group
            message = new Envelope("DGROUP");
            message.addObject(groupname); //Add group name string
            message.addObject(token); //Add requester's token
            output.writeObject(message);

            response = (Envelope)input.readObject();
            //If server indicates success, return true
            if(response.getMessage().equals("OK")) {
                return true;
            }

            System.out.printf("FAILED: %s\n", response.getObjContents().get(0));
            return false;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

    @SuppressWarnings("unchecked")
    public List<String> listMembers(String group, UserToken token) {
        try {
            Envelope message = null, response = null;
            //Tell the server to return the member list
            message = new Envelope("LMEMBERS");
            message.addObject(group); //Add group name string
            message.addObject(token); //Add requester's token
            output.writeObject(message);

            response = (Envelope)input.readObject();

            //If server indicates success, return the member list
            if(response.getMessage().equals("OK")) {
                List<String> toReturn = new ArrayList<String>();
                for(int index = 0; index < response.getObjContents().size(); index++) {
                    String toAdd = (String)response.getObjContents().get(index);
                    if(!toReturn.contains(toAdd)) {
                        toReturn.add(toAdd);
                    }
                }
                return toReturn;
                // return (List<String>)response.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
            }

            System.out.printf("FAILED: %s\n", response.getObjContents().get(0));
            return null;

        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return null;
        }
    }

    public boolean addUserToGroup(String username, String groupname, UserToken token) {
        try {
            Envelope message = null, response = null;
            //Tell the server to add a user to the group
            message = new Envelope("AUSERTOGROUP");
            message.addObject(username); //Add user name string
            message.addObject(groupname); //Add group name string
            message.addObject(token); //Add requester's token
            output.writeObject(message);

            response = (Envelope)input.readObject();
            //If server indicates success, return true
            if(response.getMessage().equals("OK")) {
                return true;
            }

            System.out.printf("FAILED: %s\n", response.getObjContents().get(0));
            return false;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

    public boolean deleteUserFromGroup(String username, String groupname, UserToken token) {
        try {
            Envelope message = null, response = null;
            //Tell the server to remove a user from the group
            message = new Envelope("RUSERFROMGROUP");
            message.addObject(username); //Add user name string
            message.addObject(groupname); //Add group name string
            message.addObject(token); //Add requester's token
            output.writeObject(message);

            response = (Envelope)input.readObject();
            //If server indicates success, return true
            if(response.getMessage().equals("OK")) {
                return true;
            }

            System.out.printf("FAILED: %s\n", response.getObjContents().get(0));
            return false;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

    private static String readInput() {
        try{
            System.out.print(" > ");	
            BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
            return in.readLine();
        } catch(Exception e){
            // Uh oh...
            System.err.println("Buffer Reader Error");
            e.printStackTrace();
            return "";
        }
    }

    public boolean showGroup(String group, UserToken token) {
        try {
            Envelope message = null, response = null;
            //Tell the server to create a user
            message = new Envelope("SHOW");
            message.addObject(group); //Add group name string
            message.addObject(token); //Add the requester's token
            output.writeObject(message);

            response = (Envelope)input.readObject();

            //If server indicates success, return true
            if(response.getMessage().equals("OK")) {
                return true;
            }
            
            System.out.printf("FAILED: %s\n", response.getObjContents().get(0));
            return false;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

    public boolean showAll(UserToken token) {
        try {
            Envelope message = null, response = null;
            //Tell the server to create a user
            message = new Envelope("SHOWALL");
            message.addObject(token); //Add the requester's token
            output.writeObject(message);

            response = (Envelope)input.readObject();

            //If server indicates success, return true
            if(response.getMessage().equals("OK")) {
                return true;
            }
            
            System.out.printf("FAILED: %s\n", response.getObjContents().get(0));
            return false;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }    

    public boolean hideGroup(String group, UserToken token) {
        try {
            Envelope message = null, response = null;
            //Tell the server to create a user
            message = new Envelope("HIDE");
            message.addObject(group); //Add group name string
            message.addObject(token); //Add the requester's token
            output.writeObject(message);

            response = (Envelope)input.readObject();

            //If server indicates success, return true
            if(response.getMessage().equals("OK")) {
                return true;
            }
            
            System.out.printf("FAILED: %s\n", response.getObjContents().get(0));
            return false;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }

    }

    public boolean hideAll(UserToken token) {
        try {
            Envelope message = null, response = null;
            //Tell the server to create a user
            message = new Envelope("HIDEALL");
            message.addObject(token); //Add the requester's token
            output.writeObject(message);

            response = (Envelope)input.readObject();

            //If server indicates success, return true
            if(response.getMessage().equals("OK")) {
                return true;
            }
            
            System.out.printf("FAILED: %s\n", response.getObjContents().get(0));
            return false;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }

    }    

    private byte[] hashPassword(final char[] password, final byte[] salt, final int iterations, final int keyLength ) {
        try {
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
            PBEKeySpec spec = new PBEKeySpec( password, salt, iterations, keyLength );
            SecretKey key = skf.generateSecret( spec );
            byte[] res = key.getEncoded( );
            return res;
        } catch ( NoSuchAlgorithmException | InvalidKeySpecException e ) {
            throw new RuntimeException( e );
        }
    }
}
