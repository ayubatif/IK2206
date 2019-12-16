import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.*;

public class SessionKey {
    private SecretKey secretKey;
    private Base64.Encoder encoder;

    SessionKey(int keyLength) throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        SecureRandom secureRandom = new SecureRandom();
        keyGenerator.init(keyLength, secureRandom);
        secretKey = keyGenerator.generateKey();
    }
    SessionKey(String encodedKey) {
        byte[] dcdKey = Base64.getDecoder().decode(encodedKey.getBytes());
        secretKey = new SecretKeySpec(dcdKey, 0, dcdKey.length, "AES");
    }
    SecretKey getSecretKey() {
        return secretKey;
    }
    String encodeKey() {
        if(encoder==null) encoder = Base64.getEncoder();
        return encoder.encodeToString(secretKey.getEncoded());
    }
    /*
    public static void main(String[] argz) {
        try {
            // Testing if key1 can be used to create key2 and if they then are equal when decoded
            SessionKey key1 = new SessionKey(128);
            SessionKey key2 = new SessionKey(key1.encodeKey());
            if (key1.getSecretKey().equals(key2.getSecretKey())) {
                System.out.println("Pass");
            }
            else {
                System.out.println("Fail");
            }
            // Testing frequency count of generated keys
            int i = 0;
            int max = 1;
            Map<SecretKey, Integer> kMap = new HashMap();
            while(i++<1000000){
                SessionKey key0 = new SessionKey(128);
                SecretKey secret = key0.getSecretKey();
                Integer n = kMap.get(secret);
                int m = (n == null) ? 1 : n + 1;
                if (m > max) max = m;
                kMap.put(secret, m);
            }
            System.out.println(max);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    */
}
