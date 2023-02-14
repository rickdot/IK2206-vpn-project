import javax.crypto.*;
import java.net.*;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.text.SimpleDateFormat;
import java.util.Base64;

public class NetPipeServer {
    private static String PROGRAMNAME = NetPipeServer.class.getSimpleName();
    private static Arguments arguments;

    /*
     * Usage: explain how to use the program, then exit with failure status
     */
    private static void usage() {
        String indent = "";
        System.err.println(indent + "Usage: " + PROGRAMNAME + " options");
        System.err.println(indent + "Where options are:");
        indent += "    ";
        System.err.println(indent + "--port=<portnumber>");
        System.err.println(indent + "--usercert=<server-cert.pem>");
        System.err.println(indent + "--cacert=<ca-cert.pem>");
        System.err.println(indent + "--key=<server-privatekey.der>");
        System.exit(1);
    }

    /*
     * Parse arguments on command line
     */
    private static void parseArgs(String[] args) {
        arguments = new Arguments();
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
    private static String base64Encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    private static byte[] base64Decode(String encodedData) {
        return Base64.getDecoder().decode(encodedData);
    }

    /*
     * Main program.
     * Parse arguments on command line, wait for connection from client,
     * and call switcher to switch data between streams.
     */
    public static void main( String[] args) throws IOException, ClassNotFoundException, CertificateException, NoSuchAlgorithmException, SignatureException, InvalidKeyException, NoSuchProviderException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        parseArgs(args);
        ServerSocket serverSocket = null;
        int port = Integer.parseInt(arguments.get("port"));

        try {
            serverSocket = new ServerSocket(port);
        } catch (IOException ex) {
            System.err.printf("Error listening on port %d\n", port);
            System.out.println(ex);
            System.exit(1);
        }
        Socket socket = null;
        try {
            socket = serverSocket.accept();
        } catch (IOException ex) {
            System.out.printf("Error accepting connection on port %d\n", port);
            System.out.println(ex);
            System.exit(1);
        }


        String cacertFile = arguments.get("cacert");
        FileInputStream instream1 = new FileInputStream(cacertFile);
        HandshakeCertificate cacert = new HandshakeCertificate(instream1);

        String usercertFile = arguments.get("usercert");
        FileInputStream instream2 = new FileInputStream(usercertFile);
        HandshakeCertificate usercert = new HandshakeCertificate(instream2);

        String privatekeyFile = arguments.get("key");
        FileInputStream keyInputStream = new FileInputStream(privatekeyFile);
        byte[] privatekeyBytes = keyInputStream.readAllBytes();


//        Handshake protocol
//        ###### ClientHello ######
//        waiting for ClientHello
        HandshakeMessage recvClientHello = HandshakeMessage.recv(socket);

        System.out.println("*** Server received " + recvClientHello.getType() + " message");
        if(recvClientHello.getType() != HandshakeMessage.MessageType.CLIENTHELLO) {
            throw new IOException("Not receiving ClientHello message");
        }
        if(recvClientHello.getParameter("Certificate")==null){
            throw new IOException("ClientHello error: Certificate not found");
        }

//        recover the certificate
        byte[] ClientCertBytes = base64Decode(recvClientHello.getParameter("Certificate"));
        HandshakeCertificate ClientCert = new HandshakeCertificate(ClientCertBytes);
//        verify the certificate is signed by trusted CA
        try {
            ClientCert.verify(cacert);
        } catch (Exception ex) {
            System.err.print("ClientHello error: ");
            throw ex;
        }
        System.out.println("*** Server verified the Client Certificate ");

//        ###### ServerHello ######
//        send ServerHello message
        HandshakeMessage ServerHello = new HandshakeMessage(HandshakeMessage.MessageType.SERVERHELLO);
        ServerHello.putParameter("Certificate", base64Encode(usercert.getBytes()));
        ServerHello.send(socket);
        System.out.println("*** Server sent ServerHello message");


        HandshakeCrypto privateCrypto = new HandshakeCrypto(privatekeyBytes);
        HandshakeCrypto publicCrypto = new HandshakeCrypto(ClientCert);

//        ###### Session ######
//        waiting for Session message
        HandshakeMessage recvSession = HandshakeMessage.recv(socket);

        System.out.println("*** Server received " + recvSession.getType() + " message");
        if(recvSession.getType() != HandshakeMessage.MessageType.SESSION) {
            throw new IOException("Not receiving Session message");
        }
        if(recvSession.getParameter("SessionKey")==null){
            throw new IOException("Session error: SessionKey not found");
        }
        if(recvSession.getParameter("SessionIV")==null){
            throw new IOException("Session error: SessionIV not found");
        }

//        recover key and IV
        byte[] recoveredKeyBytes = privateCrypto.decrypt(base64Decode(recvSession.getParameter("SessionKey")));
        byte[] recoveredIVBytes = privateCrypto.decrypt(base64Decode(recvSession.getParameter("SessionIV")));
        SessionKey sessionkey = new SessionKey(recoveredKeyBytes);
        SessionCipher sessioncipher = new SessionCipher(sessionkey, recoveredIVBytes);


//        ###### ServerFinished ######
//        get timestamp
        String timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new java.util.Date());
//        calculate signature
        HandshakeDigest hd_send = new HandshakeDigest();
        hd_send.update(ServerHello.getBytes());
        byte[] signature = hd_send.digest();
//        encrypt timestamp and signature  using server private key

        byte[] encryptedTimestamp = privateCrypto.encrypt(timestamp.getBytes());
        byte[] encryptedSignature = privateCrypto.encrypt(signature);


//      send ServerFinished message
        HandshakeMessage ServerFinished = new HandshakeMessage(HandshakeMessage.MessageType.SERVERFINISHED);
        ServerFinished.putParameter("Signature", base64Encode(encryptedSignature));
        ServerFinished.putParameter("TimeStamp", base64Encode(encryptedTimestamp));
        ServerFinished.send(socket);
        System.out.println("*** Server sent ServerFinished message");

//        ###### ClientFinished ######
//      waiting for ClientFinished message
        HandshakeMessage recvClientFinished = HandshakeMessage.recv(socket);

        System.out.println("*** Server received " + recvClientFinished.getType() + " message");
        if(recvClientFinished.getType() != HandshakeMessage.MessageType.CLIENTFINISHED) {
            throw new IOException("Not receiving ClientFinished message");
        }
        if(recvClientFinished.getParameter("Signature")==null){
            throw new IOException("ClientFinished error: Signature not found");
        }

//        recover the signature
        byte[] recvSignatureBytes = base64Decode(recvClientFinished.getParameter("Signature"));
        byte[] recvSignature = publicCrypto.decrypt(recvSignatureBytes);    // decrypt using client public key
//      recalculate the digest
        HandshakeDigest hd_recv = new HandshakeDigest();
        hd_recv.update(recvClientHello.getBytes());
        hd_recv.update(recvSession.getBytes());
        byte[] calculatedDigest = hd_recv.digest();
//        System.out.println("calculated: "+encodeToText(calculatedDigest));
//        System.out.println("received: "+encodeToText(recvDecrypted));
        if (!base64Encode(recvSignature).equals(base64Encode(calculatedDigest))) {
            throw new IOException("Authentication failed");
        }
        System.out.println("*** Server has authenticated the Client");
        System.out.println("--- Handshake completed ---");

//        System.out.println(" Server now have Session Key: "+encodeToText(sessioncipher.getSessionKey().getKeyBytes()));
//        System.out.println(" Server now have Session IV: "+encodeToText(sessioncipher.getIVBytes()));


        InputStream systemInput = System.in;
        OutputStream systemOutput = System.out;


//        not sure    correct??
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
