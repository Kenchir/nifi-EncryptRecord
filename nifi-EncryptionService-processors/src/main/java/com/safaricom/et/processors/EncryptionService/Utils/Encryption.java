package com.safaricom.et.processors.EncryptionService.Utils;


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

public  class Encryption {


    /**
     *
     * @param algorithm
     * @param plainText
     * @param key
     * @return Base64 Encoded cipherText
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     */

    public String encrypt(final String algorithm, final String plainText,final String key)
            {

        SecretKeySpec secretKeySpec = new SecretKeySpec(Base64.getDecoder().decode(key), "AES");
                Cipher cipher = null;
                try {
                    cipher = Cipher.getInstance(algorithm);
                } catch (NoSuchAlgorithmException e) {
                    e.printStackTrace();
                } catch (NoSuchPaddingException e) {
                    e.printStackTrace();
                }
                try {
                    cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(new byte[16]));
                } catch (InvalidKeyException e) {
                    e.printStackTrace();
                } catch (InvalidAlgorithmParameterException e) {
                    e.printStackTrace();
                }
                byte[] cipherText = new byte[0];
                try {
                    cipherText = cipher.doFinal(plainText.getBytes());
                } catch (IllegalBlockSizeException e) {
                    e.printStackTrace();
                } catch (BadPaddingException e) {
                    e.printStackTrace();
                }
                return Base64.getEncoder().encodeToString(cipherText);
    }

    /**
     *
     * @param algorithm
     * @param cipherText
     * @param key
     * @return
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws InvalidAlgorithmParameterException
     * @throws InvalidKeyException
     */
    public String decrypt(String algorithm, String cipherText, String key)
      {

        SecretKeySpec secretKeySpec = new SecretKeySpec(Base64.getDecoder().decode(key), "AES");
          Cipher cipher = null;
          try {
              cipher = Cipher.getInstance(algorithm);
          } catch (NoSuchAlgorithmException e) {
              e.printStackTrace();
          } catch (NoSuchPaddingException e) {
              e.printStackTrace();
          }
          try {
              cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(new byte[16]));
          } catch (InvalidKeyException e) {
              e.printStackTrace();
          } catch (InvalidAlgorithmParameterException e) {
              e.printStackTrace();
          }
          byte[] plainText = new byte[0];
          try {
              plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
          } catch (IllegalBlockSizeException e) {
              e.printStackTrace();
          } catch (BadPaddingException e) {
              e.printStackTrace();
          }
          return new String(plainText);
    }

    /***
     *
     * @param key
     * @return Boolean .
     * key length should be 16 bytes.
     */
    public   boolean KEY_VALIDATOR(String key, int keySize){

        return  keySize / Base64.getDecoder().decode(key).length == 8? true: false;

    }

}
