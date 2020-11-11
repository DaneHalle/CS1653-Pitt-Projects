import java.util.ArrayList;

// Crypto libraries 
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.Cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.io.UnsupportedEncodingException;

import java.security.Security;

public class Envelope implements java.io.Serializable {

    /**
     *
     */
    private static final long serialVersionUID = -7726335089122193103L;
    private String msg;
    private ArrayList<Object> objContents = new ArrayList<Object>();
    private int messageCount;
    private String hmac;

    public Envelope(String text) {
        msg = text;
        messageCount = -1;
    }

    public Envelope(String text, int messageInit) {
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

    public int getMessageCount() {
        return messageCount;
    }

    public int setMessageCount(int messageInit) {
        messageCount = messageInit;
    }

    public generateHash(SecretKeySpec integrity_key)
}
