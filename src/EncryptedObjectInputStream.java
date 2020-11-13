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
    private SecretKeySpec hmac_key;
    private byte[] iv;
    private long messageCount;

    private EncryptedObjectOutputStream outputReference;

    public EncryptedObjectInputStream(InputStream socketInput) {
        try {
            input = new ObjectInputStream(socketInput);
        } catch(IOException e) {
            e.printStackTrace();
            input = null;
        }

        aes_key = null;
        hmac_key = null;
        iv = null;

        messageCount = -1;
        outputReference = null;
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

    public void setOutputReference(EncryptedObjectOutputStream ref) {
        outputReference = ref;
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

    private MessageResult testIntegrity(Envelope msg) {
        if (msg == null) {
            System.out.println("===== ERROR: Envelope is null =====");
        }

        if (outputReference == null) {
            System.out.println("===== ERROR: Output Reference is not set =====");
        }

        if (messageCount == -1 && outputReference.getMessageCount() != -1) {
            System.out.println("===== ERROR: INPUT is not synced with output =====");
        }

        // TODO: Check message hash here
        if (!msg.verifyHash(hmac_key)) {
            return MessageResult.HMAC;
        }

        if (messageCount == -1) {
            // Get message count;
            messageCount = msg.getMessageCount();
            // Set the output stream message count as current
            outputReference.setMessageCount(messageCount);

            return MessageResult.SUCCESS;
        } else if(messageCount >= msg.getMessageCount()) {
            System.out.println("Message count error: " + messageCount + " vs " + msg.getMessageCount());
            // message count did not increment by one
            return MessageResult.NONCE;
        } else {
            messageCount = msg.getMessageCount();
            outputReference.setMessageCount(messageCount);
            return MessageResult.SUCCESS;
        }
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
        } catch (Exception e) {
            e.printStackTrace();
        }

        Envelope error;

        switch(testIntegrity(result)) {
        case NONCE:
            error = new Envelope("FAIL-MSGCOUNT");
            error.addObject("FAIL-MSGCOUNT | The message count was not correct.");
            return error;
        case HMAC:
            error = new Envelope("FAIL-HMAC");
            error.addObject("FAIL-HMAC | The HMAC did not match and was corrupted.");
            return error;
        case SUCCESS:
            return result;
        }

        return result;
    }

    public void close() throws IOException {
        input.close();
    }
}