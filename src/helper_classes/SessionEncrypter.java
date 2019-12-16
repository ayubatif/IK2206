import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import java.io.FileOutputStream;
import java.security.SecureRandom;
import java.util.Base64;

public class SessionEncrypter {
    private SessionKey sessionKey;
    private byte[] iv;
    private Cipher cipher;

    public SessionEncrypter(Integer keylength) throws Exception {
        sessionKey = new SessionKey(keylength);
        SecretKey sKey = sessionKey.getSecretKey();
        byte[] ivBytes = new byte[keylength/8];
        SecureRandom random = new SecureRandom();
        random.nextBytes(ivBytes);
        iv = ivBytes;
        cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, sKey);
    }

    public CipherOutputStream openCipherOutputStream(FileOutputStream fileOutputStream) {
        CipherOutputStream cipherOutputStream = new CipherOutputStream(fileOutputStream, cipher);
        return cipherOutputStream;
    }

    public String encodeKey() {
        return Base64.getEncoder().encodeToString(sessionKey.getSecretKey().getEncoded());
    }

    public String encodeIV() {
        return Base64.getEncoder().encodeToString(iv);
    }
}
