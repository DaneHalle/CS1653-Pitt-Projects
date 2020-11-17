/* Implements the GroupClient Interface */

import java.util.ArrayList;
import java.util.List;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream; // Used to write objects to the server
import java.io.BufferedReader; // Needed to read from the console
import java.io.InputStreamReader; // Needed to read from the console
import java.nio.ByteBuffer;

import java.util.StringTokenizer;
import java.util.Base64;
import java.util.*;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JOptionPane;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.KeyAgreement;
import javax.crypto.Cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.io.UnsupportedEncodingException;

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

public class AttackGroup extends Client implements GroupClientInterface {

    private boolean gui = false;

    public AttackGroup(boolean _gui){
        gui = _gui;
    }

    public UserToken getToken(String username, String password) {
        try {
            Security.addProvider(new BouncyCastleProvider());
            UserToken token = null;
            Envelope message1 = null, message2 = null, message3 = null, message4 = null, actual = null, response = null;

            //Tell the server to return a token.
            message1 = new Envelope("GET");
            message1.addObject(username); //Username

            //--------------------------------------------------------------

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

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(passSecret.getBytes("UTF-8"));
            byte[] keyBytes = new byte[16];
            System.arraycopy(digest.digest(), 0, keyBytes, 0, keyBytes.length);

            SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
            byte[] iv = new byte[16];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);
            IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
            encrypt.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
            byte[] encrypted = encrypt.doFinal(ourPk);

            message1.addObject(Base64.getEncoder().encodeToString(encrypted)); //{g^b mod p}W
            message1.addObject(iv);
            message1.addObject(fsPubKey);

            output.writeObject(message1); 
            //--------------------------------------------------------------

            message2 = (Envelope)input.readObject();
            if (message2.getMessage().equals("MESSAGE2")) {
                String encryptedKey = (String)message2.getObjContents().get(0);
                String encryptedChallenge = (String)message2.getObjContents().get(1);
                IvParameterSpec ivSpec = new IvParameterSpec((byte[])message2.getObjContents().get(2));

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
                deriveKeys(sharedSecret, ourPk, otherPk);

                SecureRandom challenge = new SecureRandom();
                String encodedChallenge = Base64.getEncoder().encodeToString(challenge.generateSeed(64)); 

                iv = new byte[16];
                random = new SecureRandom();
                random.nextBytes(iv);
                ivParameterSpec = new IvParameterSpec(iv);
                encrypt.init(Cipher.ENCRYPT_MODE, aes_k, ivParameterSpec);
                byte[] encryptedOther = encrypt.doFinal(otherChallenge); //Server's challenge
                byte[] encryptedThis = encrypt.doFinal(Base64.getDecoder().decode(encodedChallenge)); //Server's challenge
                IVk = iv;

                message3 = new Envelope("MESSAGE3");
                message3.addObject(Base64.getEncoder().encodeToString(encryptedOther));
                message3.addObject(Base64.getEncoder().encodeToString(encryptedThis));
                message3.addObject(iv);

                output.writeObject(message3); 

                //--------------------------------------------------------------

                message4 = (Envelope)input.readObject();

                if (message4.getMessage().equals("MESSAGE4")) {
                    String encryptedThisChallenge = (String)message4.getObjContents().get(0);
                    ivSpec = new IvParameterSpec((byte[])message4.getObjContents().get(1));

                    decrypt = Cipher.getInstance("AES/CBC/PKCS7PADDING");
                    decrypt.init(Cipher.DECRYPT_MODE, aes_k, ivSpec);
                    byte[] decryptThisChallenge = decrypt.doFinal(Base64.getDecoder().decode(encryptedThisChallenge));


                    output.setEncryption(aes_k, hmac_k, iv);
                    input.setEncryption(aes_k, hmac_k, iv);
                    if (Base64.getEncoder().encodeToString(decryptThisChallenge).equals(encodedChallenge)) {
                        actual = new Envelope("GOOD");
                        output.writeObject(actual);
                        response = (Envelope)input.readObject();
                        boolean first=true; 
                        StringTokenizer cmd;
                        do {
                            if (response.getMessage().equals("REQUEST-NEW")) {
                                String print = (String)response.getObjContents().get(0);
                                if(gui){
                                    cmd = new StringTokenizer(JOptionPane.showInputDialog(print));
                                } else {
                                    System.out.println(print);
                                    cmd = new StringTokenizer(readInput());
                                }
                                actual = new Envelope("NEW");
                                actual.addObject(cmd.nextToken());
                                output.writeObject(actual);
                                first = false;
                            } else {
                                break;
                            }
                            response = (Envelope)input.readObject();
                        } while (response.getMessage().equals("REQUEST-NEW"));

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
                        //Continue
                    } else {
                        aes_k = null;
                        hmac_k = null;
                        IVk = null;
                        actual = new Envelope("FAIL");
                        output.writeObject(actual);
                        response = (Envelope)input.readObject();
                        return null;
                    }
                } else {
                    aes_k = null;
                    hmac_k = null;
                    IVk = null;
                    actual = new Envelope("FAIL");
                    output.writeObject(actual);
                    response = (Envelope)input.readObject();
                    return null;
                }
            } else {
                aes_k = null;
                hmac_k = null;
                IVk = null;
                return null;
            }

            return null;
        } catch(Exception e) {
            aes_k = null;
            hmac_k = null;
            IVk = null;
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return null;
        }

    }

    public void testEncryption() {
        try {
            Cipher aes = Cipher.getInstance("AES");
                        
            byte[] test = "AES Test String".getBytes("UTF-8");
            SecretKeySpec aesSpec = new SecretKeySpec(aes_k.getEncoded(), "AES");
            IvParameterSpec ivParams = new IvParameterSpec(IVk);
            aes.init(Cipher.ENCRYPT_MODE, aes_k, ivParams);
            byte[] result = aes.doFinal(test);
            String resultEncoded = Base64.getEncoder().encodeToString(result);
            System.out.println("---------------------------------------");
            System.out.println("Result: " + resultEncoded);

            Envelope message = new Envelope("TEST");
            message.addObject(null);
            output.writeObject(message);
        } catch (Exception e) {
            e.printStackTrace();
        } 
    }

    public UserToken refreshToken(UserToken token, String fsPubKey) {
        try {
            UserToken newToken = null;
            Envelope message = null, response = null;

            //Tell the server to return a token.
            message = new Envelope("REFRESH");
            message.addObject(token); //Add user name string
            message.addObject(fsPubKey);
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

            System.out.printf("FAILED: %s\n", response.getObjContents().get(0));
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
            System.out.print(" >>>> ");	
            BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
            return in.readLine();
        } catch(Exception e){
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

    public Object[] curKey(UserToken token, String groupname) {
        try {
            Envelope message = null, response = null;
            message = new Envelope("CURKEY");
            message.addObject(token); 
            message.addObject(groupname);
            output.writeObject(message);

            response = (Envelope)input.readObject();

            if (response.getMessage().equals("OK")) {
                Object[] out = {(SecretKey)response.getObjContents().get(0), (String)response.getObjContents().get(1)};
                return out;
            }

            System.out.printf("FAILED: %s\n", response.getObjContents().get(0));
            return null;
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return null;
        }
    }

    public SecretKey keyID(UserToken token, String groupname, String id) {
        try {
            Envelope message = null, response = null;
            message = new Envelope("KEYID");
            message.addObject(token); 
            message.addObject(groupname);
            message.addObject(id);
            output.writeObject(message);
            

            response = (Envelope)input.readObject();

            if (response.getMessage().equals("OK")) {
                return (SecretKey)response.getObjContents().get(0);
            }

            System.out.printf("FAILED: %s\n", response.getObjContents().get(0));
            return null;
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return null;
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
