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
package com.safaricom.et.processors.EncryptionService;

import com.safaricom.et.processors.EncryptionService.Utils.Encryption;
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


public class EncryptRecordProcessorTest {

    private TestRunner testRunner;
    private MockRecordParser readerService;
    private MockRecordWriter writerService;
    private  EnecryptionTest enecryptionTest =new EnecryptionTest();
    private Encryption  encryption = new Encryption();
    //Apparently pretty printing is not portable as these tests fail on windows
//    @BeforeClass
//    public static void setUpSuite() {
//        Assume.assumeTrue("Test only runs on *nix", !SystemUtils.IS_OS_WINDOWS);
//    }

    @Before
    public void init() throws InitializationException {
        testRunner = TestRunners.newTestRunner(EncryptRecordProcessor.class);
        readerService = new MockRecordParser();
        writerService = new MockRecordWriter("header", false);
        testRunner.addControllerService("reader", readerService);
        testRunner.enableControllerService(readerService);
        testRunner.addControllerService("writer", writerService);
        testRunner.enableControllerService(writerService);

        testRunner.setProperty(EncryptRecordProcessor.RECORD_READER, "reader");
        testRunner.setProperty(EncryptRecordProcessor.RECORD_WRITER, "writer");
        readerService.addSchemaField("name", RecordFieldType.STRING);
        readerService.addSchemaField("msisdn", RecordFieldType.STRING);

    }

    @Test
    public void testRecordPathReplacementValue() throws NoSuchAlgorithmException {
        testRunner.setProperty("/var_name", "/name");
        testRunner.setProperty("/var_msisdn", "/msisdn");
        String key = enecryptionTest.generateKey(192);
        System.out.println(key);
        String algo = "AES/CBC/PKCS5Padding";
//        testRunner.setProperty(EncryptRecordProcessor.REPLACEMENT_VALUE_STRATEGY, EncryptRecordProcessor.RECORD_PATH_VALUES.getValue());
        testRunner.setProperty(EncryptRecordProcessor.ENCRYPTION_ALGORITHM_TYPE, EncryptRecordProcessor.AES_CBC_VALUES);
        testRunner.setProperty(EncryptRecordProcessor.KEY_SIZE, EncryptRecordProcessor.KEY_SIZE_192_VALUES);
        testRunner.setProperty(EncryptRecordProcessor.SECRET_KEY,key);


        testRunner.enqueue("");
        readerService.addRecord("John", "727399473");
        testRunner.run();

        testRunner.assertAllFlowFilesTransferred(EncryptRecordProcessor.REL_SUCCESS, 1);
        final MockFlowFile out = testRunner.getFlowFilesForRelationship(EncryptRecordProcessor.REL_SUCCESS).get(0);
//        System.out.println(out.toString());
        out.assertContentEquals("header\nJohn,727399473,"+encryption.encrypt(algo,"727399473",key)+","+encryption.encrypt(algo,"John",key)+"\n");
    }
}
