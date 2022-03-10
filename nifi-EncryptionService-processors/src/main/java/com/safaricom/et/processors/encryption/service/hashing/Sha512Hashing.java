package com.safaricom.et.processors.encryption.service.hashing;

import com.google.common.hash.Hashing;

import java.nio.charset.StandardCharsets;

public class Sha512Hashing implements HashingAlgorithm{

    @Override
    public String hash(String record) {
        return Hashing.sha512().hashString(record, StandardCharsets.UTF_8).toString();
    }
}
