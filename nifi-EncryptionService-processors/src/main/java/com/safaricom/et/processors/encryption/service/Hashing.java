package com.safaricom.et.processors.encryption.service;

import org.apache.nifi.logging.ComponentLog;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Hashing implements HashingAlgorithm{
    private final ComponentLog logger;
    public Hashing(ComponentLog logger){
        this.logger = logger;
    }


    /**
     *
     * @param algorithm
     * @param plainText
     * @return hash
     */
    @Override
    public String hashMessage(String algorithm, String plainText) {

        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            logger.error("Error occurred due to {}", new Object[]{e.getMessage()});
        }

        byte[] encodedHash = digest.digest(
                plainText.getBytes(StandardCharsets.UTF_8));
        logger.info(encodedHash.toString());
        return  bytesToHex(encodedHash);
    }
    /**
     *
     * @param encodedhash
     * @return hex String
     */
    @Override
    public   String bytesToHex(byte[] encodedhash) {
        StringBuilder hexString = new StringBuilder(2 * encodedhash.length);
        for (int i = 0; i < encodedhash.length; i++) {
            String hex = Integer.toHexString(0xff & encodedhash[i]);
            if(hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
