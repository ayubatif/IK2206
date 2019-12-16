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
        IvParameterSpec ivParam = new IvParameterSpec(iv);
        cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, sessionKey.getSecretKey(), ivParam);
    }

    public SessionDecrypter(byte[] givenKey, byte[] givenIV) throws Exception {
        sessionKey = new SessionKey(Base64.getEncoder().encodeToString(givenKey));
        iv = givenIV;
        IvParameterSpec ivParam = new IvParameterSpec(givenIV);
        cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, sessionKey.getSecretKey(), ivParam);
    }


    public CipherInputStream openCipherInputStream(FileInputStream fileInputStream) {
        return new CipherInputStream(fileInputStream, cipher);
    }
}