import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;

/*
 * Skeleton code for class SessionKey
 */

class SessionKey {
    private SecretKey secretKey;
    /*
     * Constructor to create a secret key of a given length
     */
    public SessionKey(Integer length) throws NoSuchAlgorithmException {
//        https://www.baeldung.com/java-secret-key-to-string
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(length);
        SecretKey originalKey = keyGenerator.generateKey();
        secretKey = originalKey;
    }

    /*
     * Constructor to create a secret key from key material
     * given as a byte array
     */
    public SessionKey(byte[] keybytes) {
//        https://www.baeldung.com/java-secret-key-to-string
        SecretKey originalKey = new SecretKeySpec(keybytes, 0, keybytes.length, "AES");
        secretKey = originalKey;
    }

    /*
     * Return the secret key
     */
    public SecretKey getSecretKey() {
        return secretKey;
    }

    /*
     * Return the secret key encoded as a byte array
     */
    public byte[] getKeyBytes() {
//        Returns the key in its primary encoding format, or null if this key does not support encoding.
        return secretKey.getEncoded();
    }
}

