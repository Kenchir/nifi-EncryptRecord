package com.safaricom.et.processors.EncryptionService.Utils;

import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import  org.apache.nifi.logging.ComponentLog;
public class Hashing {


    public  String hashMessage(String algo,String plaintext)  {
        System.out.println("Algo: "+ algo + " plain: " + plaintext);

        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance(algo);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
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
        System.out.println(hexString.toString());
        return hexString.toString();
    }
}
