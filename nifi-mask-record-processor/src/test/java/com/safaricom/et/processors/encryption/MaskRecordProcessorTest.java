/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.safaricom.et.processors.encryption;

import com.safaricom.et.processors.encryption.service.encryption.AesEncryption;
import org.apache.nifi.reporting.InitializationException;
import org.apache.nifi.serialization.record.MockRecordParser;
import org.apache.nifi.serialization.record.MockRecordWriter;
import org.apache.nifi.serialization.record.RecordFieldType;
import org.apache.nifi.util.MockFlowFile;
import org.apache.nifi.util.TestRunner;
import org.apache.nifi.util.TestRunners;
import org.junit.Before;
import org.junit.Test;

import java.security.NoSuchAlgorithmException;

import static java.lang.Integer.parseInt;


public class MaskRecordProcessorTest {

    private TestRunner testRunner;
    private MockRecordParser readerService;
    private MockRecordWriter writerService;
    private  EnecryptionTest enecryptionTest =new EnecryptionTest();
    private AesEncryption encryption;
    //Apparently pretty printing is not portable as these tests fail on windows
//    @BeforeClass
//    public static void setUpSuite() {
//        Assume.assumeTrue("Test only runs on *nix", !SystemUtils.IS_OS_WINDOWS);
//    }

    @Before
    public void init() throws InitializationException {
        testRunner = TestRunners.newTestRunner(MaskRecord.class);
        readerService = new MockRecordParser();
        writerService = new MockRecordWriter("header", false);
        testRunner.addControllerService("reader", readerService);
        testRunner.enableControllerService(readerService);
        testRunner.addControllerService("writer", writerService);
        testRunner.enableControllerService(writerService);

        testRunner.setProperty(MaskRecord.RECORD_READER, "reader");
        testRunner.setProperty(MaskRecord.RECORD_WRITER, "writer");
        readerService.addSchemaField("name", RecordFieldType.STRING);
        readerService.addSchemaField("msisdn", RecordFieldType.STRING);

        encryption = new AesEncryption(testRunner.getLogger());

    }

    @Test
    public void testRecordEncryption()  {
        testRunner.setProperty("/var_name", "/name");
        testRunner.setProperty("/var_msisdn", "/msisdn");
        String key = "n9Tp9+69gxNdUg9F632u1cCRuqcOuGmN";
        System.out.println(key);
        String algo = "AES/CBC/PKCS5Padding";
//        testRunner.setProperty(EncryptRecordProcessor.REPLACEMENT_VALUE_STRATEGY, EncryptRecordProcessor.RECORD_PATH_VALUES.getValue());
        testRunner.setProperty(MaskRecord.MODE, MaskRecord.ENCRYPT_MODE);
        testRunner.setProperty(MaskRecord.ENCRYPTION_ALGORITHM_TYPE, MaskRecord.AES_CBC_VALUES);
        testRunner.setProperty(MaskRecord.KEY_SIZE, MaskRecord.KEY_SIZE_192_VALUES);
        testRunner.setProperty(MaskRecord.SECRET_KEY,key);


        testRunner.enqueue("");
        readerService.addRecord("Ken", "123456789");
        testRunner.run();

        testRunner.assertAllFlowFilesTransferred(MaskRecord.REL_SUCCESS, 1);
        final MockFlowFile out = testRunner.getFlowFilesForRelationship(MaskRecord.REL_SUCCESS).get(0);
        System.out.println(out.getContent());
        out.assertContentEquals("header\nKen,123456789,"+encryption.encrypt(algo,"123456789",key)+","+encryption.encrypt(algo,"Ken",key)+"\n");
    }

    @Test
    public void testRecordDecryption() throws NoSuchAlgorithmException {
        testRunner.setProperty("/var_name", "/name");
        testRunner.setProperty("/var_msisdn", "/msisdn");
        String key = "n9Tp9+69gxNdUg9F632u1cCRuqcOuGmN";
        System.out.println(key);
        String algo = "AES/CBC/PKCS5Padding";
//        testRunner.setProperty(EncryptRecordProcessor.REPLACEMENT_VALUE_STRATEGY, EncryptRecordProcessor.RECORD_PATH_VALUES.getValue());
        testRunner.setProperty(MaskRecord.MODE, MaskRecord.DECRYPT_MODE);
        testRunner.setProperty(MaskRecord.ENCRYPTION_ALGORITHM_TYPE, MaskRecord.AES_CBC_VALUES);
        testRunner.setProperty(MaskRecord.KEY_SIZE, MaskRecord.KEY_SIZE_192_VALUES);
        testRunner.setProperty(MaskRecord.SECRET_KEY,key);
        String testName =encryption.encrypt(algo,"Ken",key);
        String testMsisdn = encryption.encrypt(algo,"123456789",key);

        testRunner.enqueue("");
        readerService.addRecord(testName, testMsisdn);
        testRunner.run();

        testRunner.assertAllFlowFilesTransferred(MaskRecord.REL_SUCCESS, 1);
        final MockFlowFile out = testRunner.getFlowFilesForRelationship(MaskRecord.REL_SUCCESS).get(0);
        out.assertContentEquals("header\n"+testName+","+testMsisdn+",123456789,Ken\n");
    }

}
