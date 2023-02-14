import javax.crypto.*;
import java.net.*;
import java.io.*;

import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.text.SimpleDateFormat;
import java.util.Base64;

public class NetPipeClient {
    private static String PROGRAMNAME = NetPipeClient.class.getSimpleName();
    private static Arguments arguments;

    /*
     * Usage: explain how to use the program, then exit with failure status
     */
    private static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--host=<hostname>");
        System.err.println(indent + "--port=<portnumber>");
        System.err.println(indent + "--usercert=<client-cert.pem>");
        System.err.println(indent + "--cacert=<ca-cert.pem>");
        System.err.println(indent + "--key=<client-privatekey.der>");

        System.exit(1);
    }

    /*
     * Parse arguments on command line
     */
    private static void parseArgs(String[] args) {
        arguments = new Arguments();
        arguments.setArgumentSpec("host", "hostname");
        arguments.setArgumentSpec("port", "portnumber");
        arguments.setArgumentSpec("usercert", "usercert");
        arguments.setArgumentSpec("cacert", "cacert");
        arguments.setArgumentSpec("key", "key");

        try {
        arguments.loadArguments(args);
        } catch (IllegalArgumentException ex) {
            usage();
        }
    }


//    helper function
//    encode byte array to text(String), using Base64 encoding
    private static String encodeToText(byte[] data) {
        String encodedData = Base64.getEncoder().encodeToString(data);
        return encodedData;
    }

    private static byte[] decodeToBytes(String encodedData) {
        byte[] data = Base64.getDecoder().decode(encodedData);
        return data;
    }


    /*
     * Main program.
     * Parse arguments on command line, connect to server,
     * and call forwarder to forward data between streams.
     */
    public static void main( String[] args) throws IOException, CertificateException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, SignatureException, NoSuchProviderException {
        Socket socket = null;
        parseArgs(args);

        String host = arguments.get("host");
        int port = Integer.parseInt(arguments.get("port"));
        try {
            socket = new Socket(host, port);
        } catch (IOException ex) {
            System.err.printf("Can't connect to server at %s:%d\n", host, port);
            System.exit(1);
        }

//        Read certificate from file and create HandshakeCertificate
        String usercertFile = arguments.get("usercert");
        FileInputStream instream1 = new FileInputStream(usercertFile);
        HandshakeCertificate usercert = new HandshakeCertificate(instream1);

        String cacertFile = arguments.get("cacert");
        FileInputStream instream2 = new FileInputStream(cacertFile);
        HandshakeCertificate cacert = new HandshakeCertificate(instream2);

        String privatekeyFile = arguments.get("key");
        FileInputStream keyInputStream = new FileInputStream(privatekeyFile);
        byte[] privatekeyBytes = keyInputStream.readAllBytes();





//      Handshake protocol
//        ########## ClientHello ##########
//      send ClientHello message
        HandshakeMessage ClientHello = new HandshakeMessage(HandshakeMessage.MessageType.CLIENTHELLO);
        ClientHello.putParameter("Certificate", encodeToText(usercert.getBytes()));    // parameter value should be base64 encoded String
        ClientHello.send(socket);
        System.out.println("*** Client sent CilentHello message");

//        ########## ServerHello ##########
//       waiting for ServerHello
        HandshakeMessage recvServerHello = HandshakeMessage.recv(socket);
        System.out.println("*** Client received "+recvServerHello.getType()+" message");
        if(recvServerHello.getType() != HandshakeMessage.MessageType.SERVERHELLO) {
            throw new IOException("Not receiving ServerHello message");
        }
        if(recvServerHello.getParameter("Certificate")==null){
            throw new IOException("ServerHello error: Certificate not found");
        }

//        recover the certificate
        byte[] ServerCertBytes = decodeToBytes(recvServerHello.getParameter("Certificate"));
        HandshakeCertificate ServerCert = new HandshakeCertificate(ServerCertBytes);
//        verify the certificate
        try {
            ServerCert.verify(cacert);
        } catch (Exception ex) {
            System.err.print("ClientHello error: ");
            throw ex;
        }
        System.out.println("*** Client verified the Server Certificate ");



        HandshakeCrypto privateCrypto = new HandshakeCrypto(privatekeyBytes);  // client private key
        HandshakeCrypto publicCrypto = new HandshakeCrypto(ServerCert);   // server public key

//        ########## Session ##########
//        generate  key and IV
        SessionKey sessionkey = new SessionKey(128);
        SessionCipher sessioncipher = new SessionCipher(sessionkey);
        byte[] sessionkeyBytes = sessionkey.getKeyBytes();
        byte[] sessionIVBytes = sessioncipher.getIVBytes();
//      encrypting key and IV with server public key
//        send Session message
        HandshakeMessage Session = new HandshakeMessage(HandshakeMessage.MessageType.SESSION);
        Session.putParameter("SessionKey", encodeToText(publicCrypto.encrypt(sessionkeyBytes)));
        Session.putParameter("SessionIV", encodeToText(publicCrypto.encrypt(sessionIVBytes)));
        Session.send(socket);
        System.out.println("*** Client sent Session message");

//        ########## ServerFinished ##########
//        waiting for ServerFinished message
        HandshakeMessage recvServerFinished = HandshakeMessage.recv(socket);

        System.out.println("*** Client received "+recvServerFinished.getType()+" message");
        if(recvServerFinished.getType() != HandshakeMessage.MessageType.SERVERFINISHED) {
            throw new IOException("Not receiving ServerFinished message");
        }
        if(recvServerFinished.getParameter("Signature")==null){
            throw new IOException("ServerFinished error: Signature not found");
        }


//        verify the signature
        byte[] recvSignatureBytes = decodeToBytes(recvServerFinished.getParameter("Signature"));
        byte[] recvSignature = publicCrypto.decrypt(recvSignatureBytes);    // decrypt using server public key
//        recalculate the digest
        HandshakeDigest hd_recv = new HandshakeDigest();
        hd_recv.update(recvServerHello.getBytes());
        byte[] calculatedDigest = hd_recv.digest();
//        System.out.println("calculated: "+encodeToText(calculatedDigest));
//        System.out.println("received: "+encodeToText(recvSignature));
        if(!encodeToText(recvSignature).equals(encodeToText(calculatedDigest))) {
            throw new IOException("Authentication failed");
        }
        System.out.println("*** Client has authenticated the Server");


//        ########## ClientFinished ##########
//        get timestamp
        String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new java.util.Date());
//        calculate signature
        HandshakeDigest hd_send = new HandshakeDigest();
        hd_send.update(ClientHello.getBytes());
        hd_send.update(Session.getBytes());
        byte[] signature = hd_send.digest();
//        encrypt timestamp and signature
        byte[] encrpytedTimestamp = privateCrypto.encrypt(timestamp.getBytes());
        byte[] encryptedSignature = privateCrypto.encrypt(signature);

//        Send ClientFinished message
        HandshakeMessage ClientFinished = new HandshakeMessage(HandshakeMessage.MessageType.CLIENTFINISHED);
        ClientFinished.putParameter("Signature", encodeToText(encryptedSignature));
        ClientFinished.putParameter("TimeStamp", encodeToText(encrpytedTimestamp));
        ClientFinished.send(socket);
        System.out.println("*** Client sent ClientFinished message");
        System.out.println("--- Handshake completed ---");


//        System.out.println(" Client now have Session Key: "+ encodeToText(sessioncipher.getSessionKey().getKeyBytes()));
//        System.out.println(" Client now have Session IV: "+encodeToText(sessioncipher.getIVBytes()));


//        start transmission

        InputStream systemInput = System.in;
        OutputStream systemOutput = System.out;

        CipherInputStream cipherInput = sessioncipher.openDecryptedInputStream(systemInput);
        CipherOutputStream cipherOutput = sessioncipher.openEncryptedOutputStream(systemOutput);

        try {
//            Forwarder.forwardStreams(System.in, System.out, socket.getInputStream(), socket.getOutputStream(), socket);
            Forwarder.forwardStreams(cipherInput, cipherOutput, socket.getInputStream(), socket.getOutputStream(), socket);
        } catch (IOException ex) {
            System.out.println("Stream forwarding error\n");
            System.exit(1);
        }
    }
}
