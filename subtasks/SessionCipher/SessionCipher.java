import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;

// https://www.tutorialspoint.com/java_cryptography/java_cryptography_encrypting_data.htm

public class SessionCipher {

    private SessionKey skey;
//    private byte[] iv;
    IvParameterSpec iv;

    /*
     * Constructor to create a SessionCipher from a SessionKey. The IV is
     * created automatically.
     */
    public SessionCipher(SessionKey key) throws NoSuchAlgorithmException {
        byte[] randomivbytes = new byte[16];
        SecureRandom.getInstanceStrong().nextBytes(randomivbytes);
        skey = key;
//        https://docs.oracle.com/javase/8/docs/api/javax/crypto/spec/IvParameterSpec.html
        iv = new IvParameterSpec(randomivbytes);

    }

    /*
     * Constructor to create a SessionCipher from a SessionKey and an IV,
     * given as a byte array.
     */

    public SessionCipher(SessionKey key, byte[] ivbytes) {
        skey = key;
        iv = new IvParameterSpec(ivbytes);
    }

    /*
     * Return the SessionKey
     */
    public SessionKey getSessionKey() {
        return skey;
    }

    /*
     * Return the IV as a byte array
     */
    public byte[] getIVBytes() {
        return iv.getIV();
    }

    /*
     * Attach OutputStream to which encrypted data will be written.
     * Return result as a CipherOutputStream instance.
     */
//    https://docs.oracle.com/javase/8/docs/technotes/guides/security/crypto/CryptoSpec.html#CipherOutput
    CipherOutputStream openEncryptedOutputStream(OutputStream os) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {

        Cipher c = Cipher.getInstance("AES/CTR/NoPadding");
        SecretKey secretkey = skey.getSecretKey();
        c.init(Cipher.ENCRYPT_MODE, secretkey, iv);

        CipherOutputStream cos;
        cos = new CipherOutputStream(os, c);

        return cos;
    }

    /*
     * Attach InputStream from which decrypted data will be read.
     * Return result as a CipherInputStream instance.
     */

    CipherInputStream openDecryptedInputStream(InputStream inputstream) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        Cipher c = Cipher.getInstance("AES/CTR/NoPadding");
        SecretKey secretkey = skey.getSecretKey();
        c.init(Cipher.DECRYPT_MODE, secretkey, iv);

        CipherInputStream cis;
        cis = new CipherInputStream(inputstream, c);

        return cis;
    }
}
