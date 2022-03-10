package com.safaricom.et.processors.encryption.service;

public interface HashingAlgorithm {

    String  bytesToHex(byte[] hash);
    String hashMessage(String algorithm, String plainText);
}
