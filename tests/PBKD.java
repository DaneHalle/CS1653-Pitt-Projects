import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class PBKD {
    public static void main(String[] args) throws UnsupportedEncodingException {
        System.out.println(args[0]);
        String password = args[0];
        String salt = args[1];
        int iterations = 10000;
        int keyLength = 256;
        char[] passwordChars = password.toCharArray();
        byte[] saltBytes = salt.getBytes();

        byte[] hashedBytes = hashPassword(passwordChars, saltBytes, iterations, keyLength);
        System.out.println(new String(hashedBytes));
    }

    public static byte[] hashPassword( final char[] password, final byte[] salt, final int iterations, final int keyLength ) {
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
}