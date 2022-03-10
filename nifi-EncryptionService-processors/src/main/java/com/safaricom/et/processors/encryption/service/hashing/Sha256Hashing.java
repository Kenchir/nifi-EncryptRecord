package com.safaricom.et.processors.encryption.service.hashing;

import com.google.common.hash.Hashing;
import org.apache.commons.codec.digest.DigestUtils;

import java.nio.charset.StandardCharsets;

public class Sha256Hashing implements HashingAlgorithm{
    @Override
    public String hash(String record) {
        return DigestUtils.sha256Hex(record);
    }
//    @Override
//    public String hash(String record) {
//        return Hashing.sha256().hashString(record, StandardCharsets.UTF_8).toString();
//    }
}
