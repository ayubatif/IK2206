import java.io.FileInputStream;
import java.io.InputStream;
import java.security.*;
import java.security.cert.*;

public class VerifyCertificate {

    private static String getDN(X509Certificate cert) {
        return String.valueOf(cert.getSubjectDN());
    }

    public static void validate(X509Certificate cert) throws CertificateNotYetValidException, CertificateExpiredException {
        cert.checkValidity();
    }

    public static void verify(X509Certificate cert_CA, X509Certificate cert_toCheck) throws NoSuchProviderException, CertificateException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        PublicKey pubkey_CA = cert_CA.getPublicKey();
        cert_toCheck.verify(pubkey_CA);
    }

    public static void main(String[] args) throws Exception {
        String filename_CA = args[0];
        String filename_USER = args[1];

        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

        InputStream in_CA = new FileInputStream(filename_CA);
        X509Certificate cert_CA = (X509Certificate) certFactory.generateCertificate(in_CA);
        in_CA.close();

        InputStream in_USER = new FileInputStream(filename_USER);
        X509Certificate cert_USER = (X509Certificate) certFactory.generateCertificate(in_USER);
        in_USER.close();

        /*
        // an expired certificate
        InputStream in_Exp = new FileInputStream("expired.pem");
        X509Certificate cert_Exp = (X509Certificate) certFactory.generateCertificate(in_Exp);
        in_Exp.close();
         */


        try {
            if(cert_CA == null || cert_USER ==null) {
                throw new IllegalArgumentException("null certificate");
            }
            System.out.println(getDN(cert_CA));
            System.out.println(getDN(cert_USER));
            validate(cert_CA);
            verify(cert_CA, cert_CA);
            validate(cert_USER);
            verify(cert_CA, cert_USER);
            /*
            System.out.println("EXPERIMENTAL SECTION BELOW");
            validate(cert_Exp); // test expired certificate
            verify(cert_CA, cert_Exp); // test bad signature
             */
            System.out.println("Pass");
        } catch (Exception e) {
            System.out.println("Fail\n"+e);
        }
    }
}
