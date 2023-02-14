import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;


public class FileDigest {
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
        HandshakeDigest handshakedigest = new HandshakeDigest();

        String fileName = args[0];
        FileInputStream fileInputStream = new FileInputStream(fileName);
        byte[] inputBytes = fileInputStream.readAllBytes();
//        System.out.println(inputBytes.toString());

        handshakedigest.update(inputBytes);

        String encodedDigest = Base64.getEncoder().encodeToString(handshakedigest.digest());
        System.out.println(encodedDigest);

//        byte[] encode = Base64.getEncoder().encode(handshakedigest.digest());
//        String result = new String(encode);
//        System.out.println(result);



    }
}
