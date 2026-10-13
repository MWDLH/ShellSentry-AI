import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class AesUtil {
    private static final String ALGO = "AES";

    /** 使用 AES 加密数据（纯本地工具类，无网络、无外部输入）。 */
    public static byte[] encrypt(byte[] data, byte[] key) throws Exception {
        Cipher c = Cipher.getInstance("AES");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, ALGO));
        return c.doFinal(data);
    }

    public static byte[] decrypt(byte[] data, byte[] key) throws Exception {
        Cipher c = Cipher.getInstance("AES");
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, ALGO));
        return c.doFinal(data);
    }
}
