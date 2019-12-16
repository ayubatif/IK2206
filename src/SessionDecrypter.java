import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.FileInputStream;
import java.util.Base64;

public class SessionDecrypter {
    private Cipher cipher;
    private SessionKey sessionKey;
    private byte[] iv;

    public SessionDecrypter(String encodeKey, String encodeIV) throws Exception {
        sessionKey = new SessionKey(encodeKey);
        iv = Base64.getDecoder().decode(encodeIV);
        cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, sessionKey.getSecretKey());
    }

    public SessionDecrypter(byte[] givenKey, byte[] givenIV) throws Exception {
        sessionKey = new SessionKey(new String(givenKey));
        iv = givenIV;
        IvParameterSpec ivParam = new IvParameterSpec(iv);
        cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, sessionKey.getSecretKey(), ivParam);
    }


    public CipherInputStream openCipherInputStream(FileInputStream fileInputStream) {
        CipherInputStream cipherInputStream = new CipherInputStream(fileInputStream, cipher);
        return cipherInputStream;
    }
}
