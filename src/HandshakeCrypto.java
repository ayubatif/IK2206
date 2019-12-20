import javax.crypto.Cipher;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;

public class HandshakeCrypto {

    public static byte[] encrypt(byte[] plaininputbytes, PublicKey publickey) throws Exception {
        Cipher x = Cipher.getInstance("RSA");
        x.init(Cipher.ENCRYPT_MODE, publickey);
        return x.doFinal(plaininputbytes);
    }

    public static byte[] decrypt(byte[] cipher, PrivateKey privatekey) throws Exception {
        Cipher x = Cipher.getInstance("RSA");
        x.init(Cipher.DECRYPT_MODE, privatekey);
        return x.doFinal(cipher);
    }

    public static PublicKey getPublicKeyFromCertFile(String cert_filename) throws Exception {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        InputStream in_Cert = new FileInputStream(cert_filename);
        X509Certificate cert = (X509Certificate) certFactory.generateCertificate(in_Cert);
        in_Cert.close();
        try { VerifyCertificate.validate(cert); } catch (Exception e) { System.out.println("CertError\n"+e); }
        return cert.getPublicKey();
    }

    public static PrivateKey getPrivateKeyFromKeyFile(String privatekey_filename) throws Exception {
        Path path = Paths.get(privatekey_filename);
        byte[] privKeyByteArray = Files.readAllBytes(path);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privKeyByteArray);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }
}
