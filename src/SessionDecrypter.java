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
    private SessionKey mSessionKey;
    private byte[] mIV;
    private Cipher mCipher;

    public SessionDecrypter(String encodeKey, String encodeIV) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        mSessionKey = new SessionKey(encodeKey);
        mIV = Base64.getDecoder().decode(encodeIV);
        mCipher = Cipher.getInstance("AES/CTR/NoPadding");
        mCipher.init(Cipher.DECRYPT_MODE, mSessionKey.getSecretKey(), new IvParameterSpec(mIV));
    }

    public SessionDecrypter(byte[] key, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        mSessionKey = new SessionKey(key);
        mIV = iv;
        mCipher = Cipher.getInstance("AES/CTR/NoPadding");
        mCipher.init(Cipher.DECRYPT_MODE, mSessionKey.getSecretKey(), new IvParameterSpec(mIV));
    }


    public CipherInputStream openCipherInputStream(InputStream inputStream) {
        return new CipherInputStream(inputStream, mCipher);
    }
}
