/* This list represents the users on the server */
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Hashtable;
import java.util.Base64;
import java.util.Enumeration;
import java.time.OffsetDateTime;

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

public class UserList implements java.io.Serializable {

    private static final long serialVersionUID = 7600343803563417992L;
    private String publicKey = null;
    private String privateKey = null;
    private Hashtable<String, User> list = new Hashtable<String, User>();

    public synchronized void addUser(String username, String passHash) {
        User newUser = new User(passHash);
        list.put(username, newUser);
    }

    public synchronized void deleteUser(String username) {
        list.remove(username);
    }

    public synchronized boolean checkUser(String username) {
        if(list.containsKey(username)) {
            return true;
        } else {
            return false;
        }
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

    public synchronized ArrayList<String> getUserGroups(String username) {
        return list.get(username).getGroups();
    }

    public synchronized ArrayList<String> getUserOwnership(String username) {
        return list.get(username).getOwnership();
    }

    public synchronized ArrayList<String> getShown(String username) {
        return list.get(username).getShown();
    }

    public synchronized void addGroup(String user, String groupname) {
        // System.out.println(user+" "+groupname);
        list.get(user).addGroup(groupname);
    }

    public synchronized void removeGroup(String user, String groupname) {
        list.get(user).removeGroup(groupname);
    }

    public synchronized void addOwnership(String user, String groupname) {
        list.get(user).addOwnership(groupname);
    }

    public synchronized void removeOwnership(String user, String groupname) {
        list.get(user).removeOwnership(groupname);
    }

    public synchronized void addShown(String user, String groupname) {
        list.get(user).addShown(groupname);
    }

    public synchronized void removeShown(String user, String groupname) {
        list.get(user).removeShown(groupname);
    }

    public synchronized void resetShown(String user) {
        list.get(user).resetShown();
    }

    public synchronized String getPasswordHash(String username) {
        if (list.get(username) == null)
            return null;
        return list.get(username).getPasswordHash();
    }

    public synchronized boolean isTemp(String username) {
        if (list.get(username) == null)
            return false;
        return list.get(username).getTemp();
    }

    public synchronized void resetHash(String username, String newHash) {
        if (list.get(username) != null)
            list.get(username).resetPasswordHash(newHash);
    }

    public synchronized void checkExpired() {
        ArrayList<String> users = getAllUsers();
        for (int i = 0; i < users.size(); i++) {
            list.get(users.get(i)).checkExpire();
        }
    }

    public synchronized boolean checkRecent(String username, String toCheck) {
        if (list.get(username) != null) 
            return list.get(username).checkRecent(toCheck);
        return false;
    }

    /**
     * Function to get all groups accessible to any given user. To be used by 
     * groupList. 
     *
     * @return ArrayList<String> of all groups accessible to users within the Server
     */
    public synchronized ArrayList<String> getAllUsers() {
        ArrayList<String> out = new ArrayList<String>();
        Enumeration<String> enumeration = list.keys();

        while(enumeration.hasMoreElements()){
            String key = enumeration.nextElement();
            out.add(key);
        }
        return out;
    }


    class User implements java.io.Serializable {

        /**
         *
         */
        private static final long serialVersionUID = -6699986336399821598L;
        private ArrayList<String> groups;
        private ArrayList<String> ownership; // this is there own group
        private ArrayList<String> shown;
        private String passHash;
        private boolean temp;
        private OffsetDateTime expire;
        private String[] prevHash;
        private int idx;

        public User(String inPass) {
            groups = new ArrayList<String>();
            ownership = new ArrayList<String>();
            shown = new ArrayList<String>();
            passHash=inPass;
            temp=true;
            expire=OffsetDateTime.now();
            prevHash = new String[5];
            idx=0;
        }

        public ArrayList<String> getGroups() {
            return groups;
        }

        public ArrayList<String> getOwnership() {
            return ownership;
        }

        public ArrayList<String> getShown() {
            return shown;
        }

        public void addGroup(String group) {
            if(!groups.contains(group)){
                groups.add(group);
            }
        }

        public void removeGroup(String group) {
            if(!groups.isEmpty()) {
                if(groups.contains(group)) {
                    groups.remove(groups.indexOf(group));
                }
                if(shown.contains(group)) {
                    shown.remove(shown.indexOf(group));
                }
            }
        }

        public void addOwnership(String group) {
            if(!ownership.contains(group)){
                ownership.add(group);
            }
        }

        public void removeOwnership(String group) {
            if(!ownership.isEmpty()) {
                if(ownership.contains(group)) {
                    ownership.remove(ownership.indexOf(group));
                }
            }
        }

        public void addShown(String group) {
            if(!shown.contains(group)){
                shown.add(group);
            }
        }

        public void removeShown(String group) {
            if(!shown.isEmpty()) {
                if(shown.contains(group)) {
                    shown.remove(shown.indexOf(group));
                }
            }
        }

        public void resetShown() {
            shown=new ArrayList<String>();
        }

        public String getPasswordHash() {
            return passHash;
        }

        public boolean getTemp() {
            return temp;
        }

        public void checkExpire() {
            if (expire.isBefore(OffsetDateTime.now())) {
                temp=true;
            }        
        }

        public boolean checkRecent(String checkHash) {
            List<String> check = Arrays.asList(prevHash);
            for (int i = 0; i<5; i++) {
                System.out.println(prevHash[i]);
            }
            return check.contains(checkHash);
        }

        public void resetPasswordHash(String newHash) {
            if (temp){
                prevHash[idx]=passHash;
                idx=(idx+1)%5;
                passHash=newHash;
                temp=false;
                expire = OffsetDateTime.now().plusMinutes(1);
            }
            // expire = OffsetDateTime.now().plusMonths(3);
        }
    }

}
