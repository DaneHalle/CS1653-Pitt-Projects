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
    private SecretKeySpec hmac_key;
    private byte[] iv;
    private long messageCount;
    private final long initCount = 1;

    private EncryptedObjectInputStream inputReference;

    public EncryptedObjectOutputStream(OutputStream socketOutput) {
        try {
            output = new ObjectOutputStream(socketOutput);
        } catch(IOException e) {
            e.printStackTrace();
            output = null;
        }

        aes_key = null;
        hmac_key = null;
        iv = null;

        messageCount = -1;
        inputReference = null;
    }

    public long getMessageCount() {
        return messageCount;
    }

    public void setMessageCount(long count) {
        messageCount = count;
    }

    public void setEncryption(SecretKeySpec confid_k, byte[] IVk) {
        aes_key = confid_k;
        iv = IVk;

        hmac_key = null;
    }

    public void setEncryption(SecretKeySpec confid_k, SecretKeySpec integ_k, byte[] IVk) {
        aes_key = confid_k;
        hmac_key = integ_k;
        iv = IVk;
    }

    public void setInputReference(EncryptedObjectInputStream ref) {
        inputReference = ref;
    }

    public void reset() throws IOException {
        output.reset();
    }

    public void writeObject(Envelope obj) throws IOException {
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

    private void writeUnencrypted(Envelope obj) throws IOException {
        output.writeObject(obj);
    }

    private void establishCount(Envelope obj) {
        if (obj == null) {
            System.out.println("===== ERROR: Envelope is null =====");
        }

        if (inputReference == null) {
            System.out.println("===== ERROR: Output Reference is not set =====");
        }

        if (messageCount == -1 && inputReference.getMessageCount() != -1) {
            System.out.println("===== ERROR: OUTPUT is not synced with input ===== " + inputReference.getMessageCount() + " " + messageCount);
        }

        if (messageCount == -1) {
            // Start the count at 0
            messageCount = initCount;
            obj.setMessageCount(initCount);
            inputReference.setMessageCount(initCount);
        } else {
            long updatedCount = messageCount + 1;
            // if (updatedCount == 10)
            //     updatedCount = messageCount-2;
            obj.setMessageCount(updatedCount);
            inputReference.setMessageCount(updatedCount);
        }
    }

    private void writeEncrypted(Envelope obj) throws IOException {
        Security.addProvider(new BouncyCastleProvider());
        
        SealedObject sealedObj = null;
        try {
            Cipher aes = Cipher.getInstance("AES");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            aes.init(Cipher.ENCRYPT_MODE, aes_key, ivSpec);

            // Generate the HMAC for the envelope
            establishCount(obj);
            obj.generateHash(aes_key); // TODO: change aes_key type

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