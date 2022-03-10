package com.safaricom.et.processors.encryption.service;

import org.apache.nifi.logging.ComponentLog;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public  class AesEncryption implements EncryptionAlgorithm {

    private final ComponentLog logger;
    public AesEncryption(ComponentLog logger){
        this.logger = logger;
    }
    /**
     *
     * @param algorithm encryption algorithm
     * @param plainText plaintext
     * @param key private key
     * @return Base64 Encoded cipherText
     */

    @Override
    public String encrypt(final String algorithm, final String plainText,final String key)
            {

        SecretKeySpec secretKeySpec = new SecretKeySpec(Base64.getDecoder().decode(key), "AES");
                Cipher cipher = null;
                try {
                    cipher = Cipher.getInstance(algorithm);
                } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
                    logger.error("Error occurred due to {}", new Object[]{e.getMessage()});
                }
                try {
                    cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(new byte[16]));
                } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
                    logger.error("Error occurred due to {}", new Object[]{e.getMessage()});
                }
                byte[] cipherText = new byte[0];
                try {
                    cipherText = cipher.doFinal(plainText.getBytes());
                } catch (IllegalBlockSizeException | BadPaddingException e) {
                    logger.error("Error occurred due to {}", new Object[]{e.getMessage()});
                }
                return Base64.getEncoder().encodeToString(cipherText);
    }

    /**
     *
     * @param algorithm encryption algorithm
     * @param cipherText ciphertext
     * @param key private key
     */
    @Override
    public String decrypt(String algorithm, String cipherText, String key)
      {

        SecretKeySpec secretKeySpec = new SecretKeySpec(Base64.getDecoder().decode(key), "AES");
          Cipher cipher = null;
          try {
              cipher = Cipher.getInstance(algorithm);
          } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
              logger.error("Error occurred due to {}", new Object[]{e.getMessage()});
          }
          try {
              cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(new byte[16]));
          } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
              logger.error("Error occurred due to {}", new Object[]{e.getMessage()});
          }
          byte[] plainText = new byte[0];
          try {
              plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
          } catch (IllegalBlockSizeException | BadPaddingException e) {
              logger.error("Error occurred due to {}", new Object[]{e.getMessage()});
          }
          return new String(plainText);
    }

}
