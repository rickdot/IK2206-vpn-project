import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class HandshakeCrypto {
	int flag = -1;
	PublicKey publickey = null;
	PrivateKey privateKey = null;

	/*
	 * Constructor to create an instance for encryption/decryption with a public key.
	 * The public key is given as a X509 certificate.
	 */
	public HandshakeCrypto(HandshakeCertificate handshakeCertificate) {
		publickey = handshakeCertificate.getCertificate().getPublicKey();
		flag = 0;
	}

	/*
	 * Constructor to create an instance for encryption/decryption with a private key.
	 * The private key is given as a byte array in PKCS8/DER format.
	 */

	public HandshakeCrypto(byte[] keybytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeyFactory kf = KeyFactory.getInstance("RSA"); // or "EC" or whatever
		privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(keybytes));
		flag = 1;
	}

	/*
	 * Decrypt byte array with the key, return result as a byte array
	 */
    public byte[] decrypt(byte[] ciphertext) throws NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
		Cipher cipher = Cipher.getInstance("RSA");
		if(flag==0){
			cipher.init(Cipher.DECRYPT_MODE, publickey);
		} else {
			cipher.init(Cipher.DECRYPT_MODE, privateKey);
		}
		return cipher.doFinal(ciphertext);

    }

	/*
	 * Encrypt byte array with the key, return result as a byte array
	 */
    public byte [] encrypt(byte[] plaintext) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("RSA");
		if(flag==0){
			cipher.init(Cipher.ENCRYPT_MODE, publickey);
		} else {
			cipher.init(Cipher.ENCRYPT_MODE, privateKey);
		}
		return cipher.doFinal(plaintext);

    }
}
