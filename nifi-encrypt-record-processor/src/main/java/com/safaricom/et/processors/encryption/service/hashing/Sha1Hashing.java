package com.safaricom.et.processors.encryption.service.hashing;

import org.apache.commons.codec.digest.DigestUtils;

public class Sha1Hashing implements HashingAlgorithm{

    @Override
    public String hash(String record) {
        return DigestUtils.sha1Hex(record);
    }
}
