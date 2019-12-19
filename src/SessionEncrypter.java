import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class SessionEncrypter {
    private SessionKey mSessionKey;
    private byte[] mIV;
    private Cipher mCipher;

    public SessionEncrypter(Integer keylength) throws Exception {
        SessionKey sessionKey = new SessionKey(keylength);
        byte[] ivBytes = new byte[keylength/8];
        SecureRandom random = new SecureRandom();
        random.nextBytes(ivBytes);
        mIV = ivBytes;
        mCipher = Cipher.getInstance("AES/CTR/NoPadding");
        mCipher.init(Cipher.ENCRYPT_MODE, sessionKey.getSecretKey(), new IvParameterSpec(mIV));
    }

    public SessionEncrypter(byte[] key, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException {
        mSessionKey = new SessionKey(key);
        mIV = iv;
        mCipher = Cipher.getInstance("AES/CTR/NoPadding");
        mCipher.init(Cipher.ENCRYPT_MODE, mSessionKey.getSecretKey(), new IvParameterSpec(mIV));
    }

    public CipherOutputStream openCipherOutputStream(OutputStream outputStream) {
        return new CipherOutputStream(outputStream, mCipher);
    }

    public String encodeKey() {
        return Base64.getEncoder().encodeToString(mSessionKey.getSecretKey().getEncoded());
    }

    public String encodeIV() {
        return Base64.getEncoder().encodeToString(mIV);
    }

    byte[] getKeyBytes() {
        return mSessionKey.getSecretKey().getEncoded();
    }

    byte[] getIVBytes() {
        return mIV;
    }
}
