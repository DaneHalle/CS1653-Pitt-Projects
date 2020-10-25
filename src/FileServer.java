/* FileServer loads files from FileList.bin.  Stores files in shared_files directory. */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;

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

public class FileServer extends Server {

    public static FileList fileList;

    private KeyPair rsa_key;
    private SecureRandom secureRandom = null;
    private final int keySize = 2048;

    public FileServer(int _port) {
        super(_port, "omega");

        Security.addProvider(new BouncyCastleProvider());
    }

    public void start() {
        String fileFile = "FileList.bin";
        ObjectInputStream fileStream;

        //This runs a thread that saves the lists on program exit
        Runtime runtime = Runtime.getRuntime();
        Thread catchExit = new Thread(new ShutDownListenerFS());
        runtime.addShutdownHook(catchExit);

        //Open user file to get user list
        try {
            FileInputStream fis = new FileInputStream(fileFile);
            fileStream = new ObjectInputStream(fis);
            fileList = (FileList)fileStream.readObject();
        } catch(FileNotFoundException e) {
            System.out.println("FileList Does Not Exist. Creating FileList...");

            fileList = new FileList();

        } catch(IOException e) {
            System.out.println("Error reading from FileList file");
            System.exit(-1);
        } catch(ClassNotFoundException e) {
            System.out.println("Error reading from FileList file");
            System.exit(-1);
        }

        File file = new File("shared_files");
        if (file.mkdir()) {
            System.out.println("Created new shared_files directory");
        } else if (file.exists()) {
            System.out.println("Found shared_files directory");
        } else {
            System.out.println("Error creating shared_files directory");
        }

        //Autosave Daemon. Saves lists every 5 minutes
        AutoSaveFS aSave = new AutoSaveFS();
        aSave.setDaemon(true);
        aSave.start();

        // Generate the key pair
        generateKey();

        //This block listens for connections and creates threads on new connections
        try {
            final ServerSocket serverSock = new ServerSocket(port);
            System.out.printf("%s up and running\n", this.getClass().getName());

            Socket sock = null;
            Thread thread = null;

            while(true) {
                sock = serverSock.accept();
                thread = new FileThread(sock, this);
                thread.start();
            }
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }

    private void generateKey() {
        KeyPairGenerator keyPair;

        try{
            keyPair = KeyPairGenerator.getInstance("RSA");
            keyPair.initialize(2048);
            secureRandom = new SecureRandom();
        } catch(Exception e) {
            e.printStackTrace();
            rsa_key = null;

            return;
        }

        rsa_key = keyPair.generateKeyPair();
    }

    public synchronized byte[] signData(byte[] data){
        try{
            Signature rsa_signature = Signature.getInstance("RSA", "BC");

            rsa_signature.initSign(rsa_key.getPrivate(), secureRandom);
            rsa_signature.update(data);

            return rsa_signature.sign();
        }catch(Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public synchronized PublicKey getPublicKey() {
        return rsa_key.getPublic();
    }
}

//This thread saves user and group lists
class ShutDownListenerFS implements Runnable {
    public void run() {
        System.out.println("Shutting down server");
        ObjectOutputStream outStream;

        try {
            outStream = new ObjectOutputStream(new FileOutputStream("FileList.bin"));
            outStream.writeObject(FileServer.fileList);
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }
}

class AutoSaveFS extends Thread {
    public void run() {
        do {
            try {
                Thread.sleep(300000); //Save group and user lists every 5 minutes
                System.out.println("Autosave file list...");
                ObjectOutputStream outStream;
                try {
                    outStream = new ObjectOutputStream(new FileOutputStream("FileList.bin"));
                    outStream.writeObject(FileServer.fileList);
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
