package com.safaricom.et.processors.EncryptionService.Utils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public interface Hash {

    public  String hashMessage(String algo,String plaintext) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(algo);
        byte[] encodedHash = digest.digest(
                plaintext.getBytes(StandardCharsets.UTF_8));
        return  bytesToHex(encodedHash);
    }

    private static String bytesToHex(byte[] hash) {
        StringBuilder hexString = new StringBuilder(2 * hash.length);
        for (int i = 0; i < hash.length; i++) {
            String hex = Integer.toHexString(0xff & hash[i]);
            if(hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
