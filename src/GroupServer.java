/* Group server. Server loads the users from UserList.bin.
 * If user list does not exists, it creates a new list and makes the user the server administrator.
 * On exit, the server saves the user list to file.
 */

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Base64;
import java.util.Scanner;
import java.io.File;

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
        super(_port, "beta");

        Security.addProvider(new BouncyCastleProvider());
    }

    public void start() {
        // Overwrote server.start() because if no user file exists, initial admin account needs to be created

        String userFile = "UserList.bin";
        String groupFile = "GroupList.bin";
        Scanner console = new Scanner(System.in);
        ObjectInputStream userStream;
        ObjectInputStream groupStream;

        //This runs a thread that saves the lists on program exit
        Runtime runtime = Runtime.getRuntime();
        runtime.addShutdownHook(new ShutDownListener(this));

        String loggingDir = "./group_logs/";
        File dir = new File(loggingDir);
        if(!dir.exists()) {
            dir.mkdir();
        }

        //Open user file to get user list
        try {
            FileInputStream fis = new FileInputStream(userFile);
            userStream = new ObjectInputStream(fis);
            fis = new FileInputStream(groupFile);
            groupStream = new ObjectInputStream(fis);

            userList = (UserList)userStream.readObject();
            userList.checkExpired();
            groupList = (GroupList)groupStream.readObject();
        } catch(FileNotFoundException e) {
            System.out.println("UserList File Does Not Exist. Creating UserList...");
            System.out.println("No users currently exist. Your account will be the administrator.");
            System.out.print("Enter your username: ");
            String username = console.next();
            System.out.print("Enter your password: ");
            String password = console.next();

            while (!isStrong(password)) {
                System.out.print("Please enter a stronger password: ");
                password = console.next();
            }
            
            String salt = username;
            int iterations = 10000;
            int keyLength = 256;
            char[] passwordChars = password.toCharArray();
            byte[] saltBytes = salt.getBytes();
            byte[] hashedBytes = hashPassword(passwordChars, saltBytes, iterations, keyLength);
            String passSecret = Base64.getEncoder().encodeToString(hashedBytes);

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
        try {
            secureRandom = new SecureRandom();
            rsa_key = userList.generateKeys();
        } catch(Exception e) {
            e.printStackTrace();
        }
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

    public synchronized KeyPair getRSAKey() {
        return rsa_key;
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
        return nScore>=40;
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
            outStream = new ObjectOutputStream(new FileOutputStream("GroupList.bin"));
            outStream.writeObject(my_gs.groupList);
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
                    my_gs.userList.checkExpired();
                    outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
                    outStream.writeObject(my_gs.userList);
                    outStream = new ObjectOutputStream(new FileOutputStream("GroupList.bin"));
                    outStream.writeObject(my_gs.groupList);
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