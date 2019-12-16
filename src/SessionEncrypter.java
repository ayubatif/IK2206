import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;

public class SessionEncrypter {
    private SessionKey sessionKey;
    private byte[] iv;
    private Cipher cipher;

    public SessionEncrypter(Integer keylength) throws Exception {
        SessionKey sessionKey = new SessionKey(keylength);
        byte[] ivBytes = new byte[keylength/8];
        SecureRandom random = new SecureRandom();
        random.nextBytes(ivBytes);
        iv = ivBytes;
        IvParameterSpec ivParams = new IvParameterSpec(iv);
        cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, sessionKey.getSecretKey(), ivParams);
    }

    public SessionEncrypter(byte[] key, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException {
        IvParameterSpec ivParams = new IvParameterSpec(iv);
        sessionKey = new SessionKey(new String(key));
        cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, sessionKey.getSecretKey(), ivParams);
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

    byte[] getKeyBytes() {
        return Base64.getEncoder().encode(sessionKey.getSecretKey().getEncoded());
    }

    byte[] getIVBytes() {
        return Base64.getEncoder().encode(iv);
    }
}
