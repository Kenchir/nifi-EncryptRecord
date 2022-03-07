package com.safaricom.et.processors.EncryptionService;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class EnecryptionTest {

    public String generateKey(int n) throws NoSuchAlgorithmException {
        byte[] secureRandomKeyBytes = new byte[n / 8];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(secureRandomKeyBytes);
        return  Base64.getEncoder().encodeToString(new SecretKeySpec(secureRandomKeyBytes, "AES").getEncoded());
    }
}
