import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.SecretKey;
import java.io.FileInputStream;
import java.util.Base64;

public class SessionDecrypter {
    private Cipher cipher;

    public SessionDecrypter(String encodeKey, String encodeIV) throws Exception {
        SessionKey sessionKey = new SessionKey(encodeKey);
        SecretKey skey = sessionKey.getSecretKey();
        byte[] iv = Base64.getDecoder().decode(encodeIV);
        cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, skey);
    }

    public CipherInputStream openCipherInputStream(FileInputStream fileInputStream) {
        CipherInputStream cipherInputStream = new CipherInputStream(fileInputStream, cipher);
        return cipherInputStream;
    }
}
