package com.safaricom.et.processors.encryption.utils;

import java.util.Base64;

public class Utils {
    /***
     *
     * @param key
     * @return Boolean .
     * key length should be 16 bytes.
     */
    public static boolean KeyValidator(String key, int keySize){

        return keySize / Base64.getDecoder().decode(key).length == 8;

    }
}
