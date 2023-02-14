import java.io.ByteArrayInputStream;
import java.io.InputStream;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;

import java.security.cert.*;

/*
 * HandshakeCertificate class represents X509 certificates exchanged
 * during initial handshake
 */
public class HandshakeCertificate {
    X509Certificate cert;

// Certificates are instantiated using a certificate factory.

    /*
     * Constructor to create a certificate from data read on an input stream.
     * The data is DER-encoded, in binary or Base64 encoding (PEM format).
     */
    HandshakeCertificate(InputStream instream) throws CertificateException {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        cert = (X509Certificate)cf.generateCertificate(instream);
    }

    /*
     * Constructor to create a certificate from its encoded representation
     * given as a byte array
     */
    HandshakeCertificate(byte[] certbytes) throws CertificateException {
        InputStream targetStream = new ByteArrayInputStream(certbytes);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        cert = (X509Certificate)cf.generateCertificate(targetStream);


    }

    /*
     * Return the encoded representation of certificate as a byte array
     */
    public byte[] getBytes() throws CertificateEncodingException {
        return cert.getEncoded();
    }

    /*
     * Return the X509 certificate
     */
    public X509Certificate getCertificate() {
        return cert;
    }

    /*
     * Cryptographically validate a certificate.
     * Throw relevant exception if validation fails.
     */
    public void verify(HandshakeCertificate cacert) throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException {
        cert.verify(cacert.getCertificate().getPublicKey());
    }



//    implement in the final assignment

    /*
     * Return CN (Common Name) of subject
     */
    public String getCN() {
        String subjectInfo= cert.getSubjectX500Principal().getName();

        String[] parts = subjectInfo.split(",");
        String cn = "";
        for (String part:parts){
            if (part.startsWith("CN=")) {
                cn=part.split("CN=")[1];
//                System.out.println(cn);
                break;
            }
        }
        return cn;

    }

    /*
     * return email address of subject
     */
    public String getEmail() throws CertificateParsingException {
        String subjectInfo= cert.getSubjectX500Principal().toString();
//        System.out.println(subjectInfo);

        String[] parts = subjectInfo.split(",");
        String email = "";
        for (String part:parts){
            if (part.startsWith("EMAILADDRESS=")) {
                email=part.split("EMAILADDRESS=")[1];
//                System.out.println(email);
                break;
            }
        }
        return email;
    }
}
