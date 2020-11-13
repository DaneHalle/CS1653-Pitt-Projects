import java.util.ArrayList;
import java.util.Base64;

// Crypto libraries 
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.io.UnsupportedEncodingException;

import java.security.Security;
import java.security.SecureRandom;

public class Envelope implements java.io.Serializable {

    /**
     *
     */
    private static final long serialVersionUID = -7726335089122193103L;
    private String msg;
    private ArrayList<Object> objContents = new ArrayList<Object>();
    private long messageCount;
    private String hmac;

    public Envelope(String text) {
        messageCount = -1;
        msg = text;
        hmac = null;
    }

    public Envelope(String text, long messageInit) {
        msg = text;
        messageCount = messageInit;
    }

    public String getMessage() {
        return msg;
    }

    public ArrayList<Object> getObjContents() {
        return objContents;
    }

    public void addObject(Object object) {
        objContents.add(object);
    }

    public long getMessageCount() {
        return messageCount;
    }

    public void setMessageCount(long messageInit) {
        messageCount = messageInit;
    }

    public byte[] toByte() {
        String strEnvelope = toString();
        byte[] data;

        try {
            data = strEnvelope.getBytes("UTF-8");
            return data;
        } catch(Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public String toString() {
        String str = "";
        // System.out.println(msg);
        str += messageCount + "\n";
        str += msg + "\n";
        for(int i=0; i < objContents.size(); i++) {
            Object content = objContents.get(i);
            // System.out.println(content.getClass().getName());
            if (content.getClass().getName().equals("[B")) {
                // Byte Array
                str += Base64.getEncoder().encodeToString((byte[])content);
            } else {
                str += objContents.get(i) + "\n";
            }
            // System.out.println(objContents.get(i).getClass().getSimpleName());
        }

        return str;
    }

    public void generateHash(SecretKeySpec integrity_key) {
        try {
            Mac sha256_hmac = Mac.getInstance("HmacSHA256");
            sha256_hmac.init(integrity_key);

            byte[] envelopeValue = toByte();
            byte[] hash = sha256_hmac.doFinal(envelopeValue);

            hmac = Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            e.printStackTrace();
            hmac = null;
        }
    }

    public boolean verifyHash(SecretKeySpec integrity_key) {
        if (hmac == null || integrity_key == null) {
            // The hmac has not been established so can not verify
            // OR generate a hash
            return true;
        }

        String compareHmac = "";

        try {
            Mac sha256_hmac = Mac.getInstance("HmacSHA256");
            sha256_hmac.init(integrity_key);

            byte[] envelopeValue = toByte();
            byte[] hash = sha256_hmac.doFinal(envelopeValue);

            compareHmac = Base64.getEncoder().encodeToString(hash);
        } catch(Exception e) {
            e.printStackTrace();
            return false;
        }

        if (hmac.equals(compareHmac)) {
            return true;
        } else {
            return false;
        }
    }

    public static void main(String args[]) {
        Envelope env = new Envelope("GET");

        String user = "John Smith";

        ArrayList<String> inGroup = new ArrayList<String>();
        inGroup.add("fish");
        inGroup.add("dog");
        inGroup.add("cat");

        ArrayList<String> inShown = new ArrayList<String>();
        inShown.add("fish");
        inShown.add("dog");

        Token t = new Token(
            "group",
            "John",
            inGroup,
            inShown,
            "secret",
            "public_key_AAAAAAA",
            "encoded_Signature_BBBBBBBB"
        );

        env.addObject(user);
        env.addObject(t);

        try {
            byte[] arr = "byte array here".getBytes("UTF-8");
            env.addObject(arr);
        } catch(Exception e) {
            e.printStackTrace();
        }

        System.out.println(env);
    }
}
