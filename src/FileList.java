/* This list represents the files on the server */
import java.util.ArrayList;
import java.util.Collections;
import java.util.Base64;

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
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;

public class FileList implements java.io.Serializable {

    /*Serializable so it can be stored in a file for persistence */
    private static final long serialVersionUID = -8911161283900260136L;
    private String publicKey = null;
    private String privateKey = null;
    private ArrayList<ShareFile> list;

    public FileList() {
        list = new ArrayList<ShareFile>();
    }

    public synchronized void addFile(String owner, String group, String path, String id) {
        ShareFile newFile = new ShareFile(owner, group, path, id);
        list.add(newFile);
    }

    public synchronized void removeFile(String path) {
        for (int i = 0; i < list.size(); i++) {
            if (list.get(i).getPath().compareTo(path)==0) {
                list.remove(i);
            }
        }
    }

    public synchronized boolean checkFile(String path) {
        for (int i = 0; i < list.size(); i++) {
            if (list.get(i).getPath().compareTo(path)==0) {
                return true;
            }
        }
        return false;
    }

    public synchronized ArrayList<ShareFile> getFiles() {
        Collections.sort(list);
        return list;
    }

    public synchronized ShareFile getFile(String path) {
        for (int i = 0; i < list.size(); i++) {
            if (list.get(i).getPath().compareTo(path)==0) {
                return list.get(i);
            }
        }
        return null;
    }

    public KeyPair generateKeys() {
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator keyPair;
        KeyPair rsa_key;

        if (publicKey == null || privateKey == null) {
            System.out.println("KeyPair does not exist. Generating new pair...");
            try {
                keyPair = KeyPairGenerator.getInstance("RSA"); //shouldnt we initialize to 2048?????
                keyPair.initialize(2048);
            } catch(Exception e) {
                e.printStackTrace();
                
                return null;
            }

            rsa_key = keyPair.generateKeyPair();

            publicKey = Base64.getEncoder().encodeToString(rsa_key.getPublic().getEncoded());
            privateKey = Base64.getEncoder().encodeToString(rsa_key.getPrivate().getEncoded());
        } else {
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKey);
            byte[] privateKeyBytes = Base64.getDecoder().decode(privateKey);

            try {
                KeyFactory kf = KeyFactory.getInstance("RSA");
                PublicKey pubK = kf.generatePublic(new X509EncodedKeySpec(publicKeyBytes));
                PrivateKey privK = kf.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));

                rsa_key = new KeyPair(pubK, privK);
            } catch(Exception e) {
                e.printStackTrace();

                return null;
            }
        }

        return rsa_key;
    }
}
