import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.IOException;

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

public class EncryptedObjectInputStream {
    private ObjectInputStream input;

    private SecretKeySpec aes_key;
    private int messageCount;
    private byte[] iv;

    public EncryptedObjectInputStream(InputStream socketInput) {
        try {
            input = new ObjectInputStream(socketInput);
        } catch(IOException e) {
            e.printStackTrace();
            input = null;
        }

        aes_key = null;
        iv = null;
    }

    public void setEncryption(SecretKeySpec k, byte[] IVk) {
        aes_key = k;
        iv = IVk;
    }

    public Envelope readObject() throws IOException, ClassNotFoundException {
        // No key means no encryption so just deserialize
        if (input == null) {
            return null;
        }

        if (aes_key == null) {
            return readUnencrypted();
        } else {
            return readEncrypted();
        }
    }

    private Envelope readUnencrypted() throws IOException, ClassNotFoundException {
        return (Envelope)input.readObject();
    }

    private enum MessageResult {
        NONCE,
        HMAC,
        SUCCESS
    }

    private Envelope readEncrypted() throws IOException, ClassNotFoundException {
        Security.addProvider(new BouncyCastleProvider());
        
        SealedObject encObj = (SealedObject)input.readObject();
        Envelope result = null;
        try {
            Cipher aes = Cipher.getInstance("AES");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            aes.init(Cipher.DECRYPT_MODE, aes_key, ivSpec);

            result = (Envelope)encObj.getObject(aes);

            if ()
        } catch (Exception e) {
            e.printStackTrace();
        }

        return result;
    }

    public void close() throws IOException {
        input.close();
    }
}