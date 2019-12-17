import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class SessionDecrypter {
    private Cipher cipher;
    private SessionKey sessionKey;
    private byte[] iv;

    public SessionDecrypter(String encodeKey, String encodeIV) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        sessionKey = new SessionKey(encodeKey);
        iv = Base64.getDecoder().decode(encodeIV);
        IvParameterSpec ivParam = new IvParameterSpec(iv);
        cipher = Cipher.getInstance("AES/CBC/PKCS8Padding");
        cipher.init(Cipher.DECRYPT_MODE, sessionKey.getSecretKey(), ivParam);
    }

    public SessionDecrypter(byte[] givenKey, byte[] givenIV) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        sessionKey = new SessionKey(Base64.getEncoder().encodeToString(givenKey));
        iv = givenIV;
        IvParameterSpec ivParam = new IvParameterSpec(givenIV);
        cipher = Cipher.getInstance("AES/CBC/PKCS8Padding");
        cipher.init(Cipher.DECRYPT_MODE, sessionKey.getSecretKey(), ivParam);
    }


    public CipherInputStream openCipherInputStream(InputStream inputStream) {
        return new CipherInputStream(inputStream, cipher);
    }
}
