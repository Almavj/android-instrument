package com.rat.agent;

import android.util.Base64;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class CryptoUtils {

    private static final String ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String KEY_STR = "R4tD3m0K3y!2024#CtF";
    private static SecretKeySpec secretKey;
    private static byte[] iv;

    static {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] keyBytes = md.digest(KEY_STR.getBytes("UTF-8"));
            secretKey = new SecretKeySpec(keyBytes, "AES");
            iv = new byte[16];
            System.arraycopy(keyBytes, 0, iv, 0, 16);
        } catch (Exception e) {
            throw new RuntimeException("Crypto init failed", e);
        }
    }

    public static String encrypt(String plaintext) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
            byte[] encrypted = cipher.doFinal(plaintext.getBytes("UTF-8"));
            return Base64.encodeToString(encrypted, Base64.NO_WRAP);
        } catch (Exception e) {
            return plaintext;
        }
    }

    public static String decrypt(String ciphertext) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
            byte[] decoded = Base64.decode(ciphertext, Base64.NO_WRAP);
            return new String(cipher.doFinal(decoded), "UTF-8");
        } catch (Exception e) {
            return ciphertext;
        }
    }

    public static String encryptBytes(byte[] data) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));
            byte[] encrypted = cipher.doFinal(data);
            return Base64.encodeToString(encrypted, Base64.NO_WRAP);
        } catch (Exception e) {
            return Base64.encodeToString(data, Base64.NO_WRAP);
        }
    }

    public static byte[] decryptBytes(String ciphertext) {
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
            byte[] decoded = Base64.decode(ciphertext, Base64.NO_WRAP);
            return cipher.doFinal(decoded);
        } catch (Exception e) {
            return Base64.decode(ciphertext, Base64.NO_WRAP);
        }
    }
}
