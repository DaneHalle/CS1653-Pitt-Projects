import java.io.OutputStream;
import java.io.ObjectOutputStream;
import java.io.IOException;
import java.io.Serializable;

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

public class EncryptedObjectOutputStream {
    private ObjectOutputStream output;

    private SecretKeySpec aes_key;
    private byte[] iv;

    public EncryptedObjectOutputStream(OutputStream socketOutput) {
        try {
            output = new ObjectOutputStream(socketOutput);
        } catch(IOException e) {
            e.printStackTrace();
            output = null;
        }

        aes_key = null;
        iv = null;
    }

    public void setEncryption(SecretKeySpec k, byte[] IVk) {
        aes_key = k;
        iv = IVk;
    }

    public void reset() throws IOException {
        output.reset();
    }

    public void writeObject(Serializable obj) throws IOException {
        // No key means no encryption so just deserialize
        if (output == null) {
            return;
        }

        if (aes_key == null) {
            writeUnencrypted(obj);
        } else {
            writeEncrypted(obj);
        }
    }

    private void writeUnencrypted(Serializable obj) throws IOException {
        output.writeObject(obj);
    }

    private void writeEncrypted(Serializable obj) throws IOException {
        Security.addProvider(new BouncyCastleProvider());
        
        SealedObject sealedObj = null;
        try {
            Cipher aes = Cipher.getInstance("AES");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            aes.init(Cipher.ENCRYPT_MODE, aes_key, ivSpec);

            sealedObj = new SealedObject(obj, aes);
        } catch (Exception e) {
            e.printStackTrace();
        }

        output.writeObject(sealedObj);
    }

    public void close() throws IOException {
        output.close();
    }
}