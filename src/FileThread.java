/* File worker thread handles the business of uploading, downloading, and removing files for clients with valid tokens */

import java.lang.Thread;
import java.net.Socket;
import java.util.Base64;
import java.util.List;
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
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.ECParameterSpec;
import java.security.interfaces.ECPublicKey;

public class FileThread extends Thread {
    private final Socket socket;
    private FileServer my_fs;

    public FileThread(Socket _socket, FileServer _fs) {
        socket = _socket;
        my_fs = _fs;
    }

    public void run() {
        boolean proceed = true;

        Security.addProvider(new BouncyCastleProvider());

        try {
            System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
            final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
            final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
            Envelope response;

            if (!establishConnection(input, output)) {
                socket.close();
                proceed = false;
            }

            do {
                Envelope e = (Envelope) input.readObject();
                output.reset();

                System.out.println(
                        socket.getInetAddress() + ":" + socket.getPort() + " | Request received: " + e.getMessage());
                String action = "";
                // Handler to list files that this user is allowed to see
                if (e.getMessage().equals("LFILES")) {
                    /* TODO: Write this handler */
                    if (e.getObjContents().size() != 1) {
                        response = new Envelope("FAIL-BADCONTENTS");
                        action = "\tFAIL-LFILES | as request has bad contents.\n";
                        response.addObject(action.substring(1, action.length() - 1));
                        System.out.printf("%s", action);
                    } else {
                        if (e.getObjContents().get(0) == null) {
                            response = new Envelope("FAIL-BADTOKEN");
                            action = "\tFAIL-LFILES | as request has bad token.\n";
                            response.addObject(action.substring(1, action.length() - 1));
                            System.out.printf("%s", action);
                        } else {
                            UserToken token = (UserToken) e.getObjContents().get(0);
                            String requester = token.getSubject();
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
                        System.out.printf("%s", action);
                    } else {
                        if (e.getObjContents().get(0) == null) {
                            response = new Envelope("FAIL-BADGROUP");
                            action = "\tFAIL-LFORGROUP | as request has bad group.\n";
                            response.addObject(action.substring(1, action.length() - 1));
                            System.out.printf("%s", action);
                        }
                        if (e.getObjContents().get(1) == null) {
                            response = new Envelope("FAIL-BADTOKEN");
                            action = "\tFAIL-LFORGROUP | as request has bad token.\n";
                            response.addObject(action.substring(1, action.length() - 1));
                            System.out.printf("%s", action);
                        } else {
                            String group = (String) e.getObjContents().get(0);
                            UserToken token = (UserToken) e.getObjContents().get(1);
                            String requester = token.getSubject();
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
                                    System.out.printf("%s", action);
                                }
                            } else {
                                response = new Envelope("FAIL-UNAUTHORIZED");
                                action = "\tFAIL-LFORGROUP | " + requester + " is not a user within group " + group
                                        + "\n";
                                response.addObject(action.substring(1, action.length() - 1));
                                System.out.printf("%s", action);
                            }

                        }
                    }
                    output.writeObject(response);
                } else if (e.getMessage().equals("UPLOADF")) {

                    if (e.getObjContents().size() != 3) {
                        response = new Envelope("FAIL-BADCONTENTS");
                        action = "\tFAIL-UPLOADF | as request has bad contents.\n";
                        response.addObject(action.substring(1, action.length() - 1));
                        System.out.printf("%s", action);
                    } else {
                        if (e.getObjContents().get(0) == null) {
                            response = new Envelope("FAIL-BADPATH");
                            action = "\tFAIL-UPLOADF | as request has bad path.\n";
                            response.addObject(action.substring(1, action.length() - 1));
                            System.out.printf("%s", action);
                        }
                        if (e.getObjContents().get(1) == null) {
                            response = new Envelope("FAIL-BADGROUP");
                            action = "\tFAIL-UPLOADF | as request has bad group.\n";
                            response.addObject(action.substring(1, action.length() - 1));
                            System.out.printf("%s", action);
                        }
                        if (e.getObjContents().get(2) == null) {
                            response = new Envelope("FAIL-BADTOKEN");
                            action = "\tFAIL-UPLOADF | as request has bad token.\n";
                            response.addObject(action.substring(1, action.length() - 1));
                            System.out.printf("%s", action);
                        } else {
                            String remotePath = (String) e.getObjContents().get(0);
                            String group = (String) e.getObjContents().get(1);
                            UserToken yourToken = (UserToken) e.getObjContents().get(2); // Extract token

                            if (FileServer.fileList.checkFile(remotePath)) {
                                response = new Envelope("FAIL-FILEEXISTS"); // Success
                                action = "\tError: file already exists at " + remotePath + "\n";
                                response.addObject(action.substring(1, action.length() - 1));
                                System.out.printf("%s", action);
                            } else if (!yourToken.getGroups().contains(group)) {
                                response = new Envelope("FAIL-UNAUTHORIZED"); // Success
                                action = "\tError: user missing valid token for group " + group + "\n";
                                response.addObject(action.substring(1, action.length() - 1));
                                System.out.printf("%s", action);
                            } else if (!yourToken.getShownGroups().contains(group)) {
                                response = new Envelope("FAIL-PRIVILEGE"); // Success
                                action = "\t" + yourToken.getSubject() + " has not escalated permissions for group "
                                        + group + "\n";
                                response.addObject(action.substring(1, action.length() - 1));
                                System.out.printf("%s", action);
                            } else {
                                File file = new File("shared_files/" + remotePath.replace('/', '_'));
                                file.createNewFile();
                                FileOutputStream fos = new FileOutputStream(file);
                                System.out.printf("Successfully created file %s\n", remotePath.replace('/', '_'));

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
                                    System.out.printf("Transfer successful file %s\n", remotePath);
                                    FileServer.fileList.addFile(yourToken.getSubject(), group, remotePath);
                                    response = new Envelope("OK"); // Success
                                } else {
                                    response = new Envelope("ERROR-TRANSFER"); // Success
                                    action = "\tError reading file " + remotePath + " from client\n";
                                    response.addObject(action.substring(1, action.length() - 1));
                                    System.out.printf("%s", action);
                                }
                                fos.close();
                            }
                        }
                    }

                    output.writeObject(response);
                } else if (e.getMessage().compareTo("DOWNLOADF") == 0) {

                    String remotePath = (String) e.getObjContents().get(0);
                    Token t = (Token) e.getObjContents().get(1);
                    ShareFile sf = FileServer.fileList.getFile("/" + remotePath);
                    if (sf == null) {
                        e = new Envelope("ERROR_FILEMISSING");
                        action = "\tError: File " + remotePath + " doesn't exist\n";
                        response.addObject(action.substring(1, action.length() - 1));
                        System.out.printf("%s", action);
                        output.writeObject(e);

                    } else if (!t.getGroups().contains(sf.getGroup())) {
                        e = new Envelope("ERROR_PERMISSION");
                        action = "\tError user " + t.getSubject() + " doesn't have permission\n";
                        response.addObject(action.substring(1, action.length() - 1));
                        System.out.printf("%s", action);
                        output.writeObject(e);
                    } else if (!t.getShownGroups().contains(sf.getGroup())) {
                        e = new Envelope("ERROR_PRIVILEGE");
                        action = "\t" + t.getSubject() + " has not escalated permissions for group " + sf.getGroup()
                                + "\n";
                        response.addObject(action.substring(1, action.length() - 1));
                        System.out.printf("%s", action);
                        output.writeObject(e);
                    } else {

                        try {
                            File f = new File("shared_files/_" + remotePath.replace('/', '_'));
                            if (!f.exists()) {
                                e = new Envelope("ERROR_NOTONDISK");
                                action = "\tError file _" + remotePath.replace('/', '_') + " missing from disk\n";
                                response.addObject(action.substring(1, action.length() - 1));
                                System.out.printf("%s", action);
                                output.writeObject(e);

                            } else {
                                FileInputStream fis = new FileInputStream(f);

                                do {
                                    byte[] buf = new byte[4096];
                                    if (e.getMessage().compareTo("DOWNLOADF") != 0) {
                                        action = "\tServer error: " + e.getMessage() + "\n";
                                        response.addObject(action.substring(1, action.length() - 1));
                                        System.out.printf("%s", action);
                                        break;
                                    }
                                    e = new Envelope("CHUNK");
                                    int n = fis.read(buf); // can throw an IOException
                                    if (n > 0) {
                                        System.out.printf(".");
                                    } else if (n < 0) {
                                        action = "\tRead error\n";
                                        response.addObject(action.substring(1, action.length() - 1));
                                        System.out.printf("%s", action);

                                    }

                                    e.addObject(buf);
                                    e.addObject(Integer.valueOf(n));

                                    output.writeObject(e);

                                    e = (Envelope) input.readObject();

                                } while (fis.available() > 0);

                                // If server indicates success, return the member list
                                if (e.getMessage().compareTo("DOWNLOADF") == 0) {

                                    e = new Envelope("EOF");
                                    output.writeObject(e);

                                    e = (Envelope) input.readObject();
                                    if (e.getMessage().compareTo("OK") == 0) {
                                        System.out.printf("File data upload successful\n");
                                    } else {
                                        action = "\tUpload failed: " + e.getMessage() + "\n";
                                        response.addObject(action.substring(1, action.length() - 1));
                                        System.out.printf("%s", action);
                                    }
                                } else {
                                    action = "\tUpload failed: " + e.getMessage() + "\n";
                                    response.addObject(action.substring(1, action.length() - 1));
                                    System.out.printf("%s", action);
                                }
                            }
                        } catch (Exception e1) {
                            System.err.println("Error: " + e.getMessage());
                            e1.printStackTrace(System.err);
                        }
                    }
                } else if (e.getMessage().compareTo("DELETEF") == 0) {

                    String remotePath = (String) e.getObjContents().get(0);
                    Token t = (Token) e.getObjContents().get(1);
                    ShareFile sf = FileServer.fileList.getFile("/" + remotePath);
                    if (sf == null) {
                        e = new Envelope("ERROR_DOESNTEXIST");
                        action = "\tError: File " + remotePath + " doesn't exist\n";
                        response.addObject(action.substring(1, action.length() - 1));
                        System.out.printf("%s", action);
                    } else if (!t.getGroups().contains(sf.getGroup())) {
                        e = new Envelope("ERROR_PERMISSION");
                        action = "\tError user " + t.getSubject() + " doesn't have permission\n";
                        response.addObject(action.substring(1, action.length() - 1));
                        System.out.printf("%s", action);
                    } else if (!t.getShownGroups().contains(sf.getGroup())) {
                        e = new Envelope("ERROR-PRIVILEGE"); // Success
                        action = "\t" + t.getSubject() + " has not escalated permissions for group " + sf.getGroup()
                                + "\n";
                        response.addObject(action.substring(1, action.length() - 1));
                        System.out.printf("%s", action);
                    } else {

                        try {

                            File f = new File("shared_files/" + "_" + remotePath.replace('/', '_'));

                            if (!f.exists()) {
                                e = new Envelope("ERROR_FILEMISSING");
                                action = "\tError file _" + remotePath.replace('/', '_') + " missing from disk\n";
                                response.addObject(action.substring(1, action.length() - 1));
                                System.out.printf("%s", action);
                            } else if (f.delete()) {
                                System.out.printf("File %s deleted from disk\n", "_" + remotePath.replace('/', '_'));
                                FileServer.fileList.removeFile("/" + remotePath);
                                e = new Envelope("OK");
                            } else {
                                e = new Envelope("ERROR_DELETE");
                                action = "\tError deleting file _" + remotePath.replace('/', '_') + " from disk\n";
                                response.addObject(action.substring(1, action.length() - 1));
                                System.out.printf("%s", action);
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
                }
            } while (proceed);
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }

    boolean establishConnection(ObjectInputStream input, ObjectOutputStream output)
            throws NoSuchAlgorithmException, IOException {
        Envelope response;

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        KeyPair kp = kpg.generateKeyPair();
        byte[] ourPk = kp.getPublic().getEncoded();

        String encodedPubKey = Base64.getEncoder().encodeToString(ourPk);
        System.out.println("Public Key: " + encodedPubKey);

        String encodedSig = Base64.getEncoder().encodeToString(my_fs.signData(ourPk));
        
        byte[] rsaPublicKeyByte = my_fs.getPublicKey().getEncoded();
        String encodedRSAPk = Base64.getEncoder().encodeToString(rsaPublicKeyByte);

        response = new Envelope("FILE");
        response.addObject(encodedPubKey);
        response.addObject(encodedSig);
        response.addObject(encodedRSAPk);
        // response.addObject(ivEncoded);
        output.writeObject(response);

        return true;
    }



}
