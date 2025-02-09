package javaesecb;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AES_ECB {
    private SecretKeySpec secretKey;

    // Constructor to initialize the secret key
    public AES_ECB(String secretKeyParam) {
        byte[] secretKeyBytes = secretKeyParam.getBytes();
        if (secretKeyBytes.length != 16) {
            throw new IllegalArgumentException("Secret key must be exactly 16 bytes for AES-128.");
        }
        this.secretKey = new SecretKeySpec(secretKeyBytes, "AES");
    }

    // Method to encrypt a value
    public String encrypt(String valueToEncrypt) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encrypted = cipher.doFinal(valueToEncrypt.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    // Method to decrypt a value
    public String decrypt(String encryptedValue) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encryptedValue));
        return new String(decrypted);
    }

    // Main method for testing
    public static void main(String[] args) {
        try {
            String secretKey = "1234567890abcdef"; // Example 16-byte key
            AES_ECB aes = new AES_ECB(secretKey);

            String valueToEncrypt = "Hello, AES!";
            String encryptedValue = aes.encrypt(valueToEncrypt);
            System.out.println("Encrypted (Base64): " + encryptedValue);

            String decryptedValue = aes.decrypt(encryptedValue);
            System.out.println("Decrypted Text: " + decryptedValue);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
