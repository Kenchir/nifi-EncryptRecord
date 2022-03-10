package com.safaricom.et.processors.encryption.service;

public interface EncryptionAlgorithm {

    String encrypt(String algorithm, String plainText, String key);

    String decrypt(String algorithm, String cipherText, String key);
}
