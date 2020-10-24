/* Group server. Server loads the users from UserList.bin.
 * If user list does not exists, it creates a new list and makes the user the server administrator.
 * On exit, the server saves the user list to file.
 */

/*
 * TODO: This file will need to be modified to save state related to
 *       groups that are created in the system
 *
 */

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Scanner;

// Crypto Libraries
import java.security.*;

import javax.crypto.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class GroupServer extends Server {

    public UserList userList;
    public GroupList groupList;

    private KeyPair rsa_key;
    private SecureRandom secureRandom = null;
    private final int keySize = 2048;

    public GroupServer(int _port) {
        super(_port, "alpha");

        Security.addProvider(new BouncyCastleProvider());
    }

    public void start() {
        // Overwrote server.start() because if no user file exists, initial admin account needs to be created

        String userFile = "UserList.bin";
        Scanner console = new Scanner(System.in);
        ObjectInputStream userStream;
        ObjectInputStream groupStream;

        //This runs a thread that saves the lists on program exit
        Runtime runtime = Runtime.getRuntime();
        runtime.addShutdownHook(new ShutDownListener(this));

        //Open user file to get user list
        try {
            FileInputStream fis = new FileInputStream(userFile);
            userStream = new ObjectInputStream(fis);
            userList = (UserList)userStream.readObject();
            groupList = new GroupList(userList);
        } catch(FileNotFoundException e) {
            System.out.println("UserList File Does Not Exist. Creating UserList...");
            System.out.println("No users currently exist. Your account will be the administrator.");
            System.out.print("Enter your username: ");
            String username = console.next();
            System.out.print("Enter your password: ");
            String password = console.next();
            
            String salt = username;
            int iterations = 10000;
            int keyLength = 256;
            char[] passwordChars = password.toCharArray();
            byte[] saltBytes = salt.getBytes();
            byte[] hashedBytes = hashPassword(passwordChars, saltBytes, iterations, keyLength);
            String passSecret = new String(hashedBytes);

            //Create a new list, add current user to the ADMIN group. They now own the ADMIN group.
            userList = new UserList();
            userList.addUser(username, passSecret);
            userList.addGroup(username, "ADMIN");
            userList.addOwnership(username, "ADMIN");
            groupList = new GroupList(userList);
        } catch(IOException e) {
            System.out.println("Error reading from UserList file");
            System.exit(-1);
        } catch(ClassNotFoundException e) {
            System.out.println("Error reading from UserList file");
            System.exit(-1);
        }

        //Autosave Daemon. Saves lists every 5 minutes
        AutoSave aSave = new AutoSave(this);
        aSave.setDaemon(true);
        aSave.start();

        // Generate the keyPair
        generateKey();

        //This block listens for connections and creates threads on new connections
        try {
            final ServerSocket serverSock = new ServerSocket(port);
            System.out.printf("%s up and running\n", this.getClass().getName());

            Socket sock = null;
            GroupThread thread = null;

            while(true) {
                sock = serverSock.accept();
                thread = new GroupThread(sock, this);
                thread.start();
            }
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }

    }

    private void generateKey() {
        KeyPairGenerator keyPair;

        try {
            keyPair = KeyPairGenerator.getInstance("RSA");
            secureRandom = new SecureRandom();
        } catch(Exception e) {
            e.printStackTrace();
            rsa_key = null;
            
            return;
        }

        keyPair.initialize(keySize);
        rsa_key = keyPair.generateKeyPair();
    }

    public synchronized byte[] signData(byte[] data) {
        try {
            Signature rsa_signature = Signature.getInstance("RSA");
            
            rsa_signature.initSign(rsa_key.getPrivate(), secureRandom);
            rsa_signature.update(data);

            return rsa_signature.sign();
        } catch(Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public synchronized PublicKey getPublicKey() {
        return rsa_key.getPublic();
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

}

//This thread saves the user list
class ShutDownListener extends Thread {
    public GroupServer my_gs;

    public ShutDownListener (GroupServer _gs) {
        my_gs = _gs;
    }

    public void run() {
        System.out.println("Shutting down server");
        ObjectOutputStream outStream;
        try {
            outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
            outStream.writeObject(my_gs.userList);
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }
}

class AutoSave extends Thread {
    public GroupServer my_gs;

    public AutoSave (GroupServer _gs) {
        my_gs = _gs;
    }

    public void run() {
        do {
            try {
                Thread.sleep(300000); //Save group and user lists every 5 minutes
                System.out.println("Autosave group and user lists...");
                ObjectOutputStream outStream;
                try {
                    outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
                    outStream.writeObject(my_gs.userList);
                } catch(Exception e) {
                    System.err.println("Error: " + e.getMessage());
                    e.printStackTrace(System.err);
                }

            } catch(Exception e) {
                System.out.println("Autosave Interrupted");
            }
        } while(true);
    }
}
