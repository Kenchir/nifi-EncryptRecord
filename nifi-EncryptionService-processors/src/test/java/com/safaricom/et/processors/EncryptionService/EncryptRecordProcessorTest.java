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

import org.apache.commons.lang3.SystemUtils;
import org.apache.nifi.reporting.InitializationException;
import org.apache.nifi.serialization.record.MockRecordParser;
import org.apache.nifi.serialization.record.MockRecordWriter;
import org.apache.nifi.serialization.record.RecordFieldType;
import org.apache.nifi.util.MockFlowFile;
import org.apache.nifi.util.TestRunner;
import org.apache.nifi.util.TestRunners;
import org.junit.Assume;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.NoSuchAlgorithmException;

import static java.lang.Integer.parseInt;


public class EncryptRecordProcessorTest {

    private TestRunner testRunner;
    private MockRecordParser readerService;
    private MockRecordWriter writerService;
    private  EnecryptionTest enecryptionTest =new EnecryptionTest();

    //Apparently pretty printing is not portable as these tests fail on windows
    @BeforeClass
    public static void setUpSuite() {
        Assume.assumeTrue("Test only runs on *nix", !SystemUtils.IS_OS_WINDOWS);
    }

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
//        testRunner.setProperty("/msisdn","727399473");
        readerService.addSchemaField("name", RecordFieldType.STRING);
        readerService.addSchemaField("msisdn", RecordFieldType.STRING);

    }

    @Test
    public void testRecordPathReplacementValue() throws NoSuchAlgorithmException {
        testRunner.setProperty("/name", "/msisdn");
        testRunner.setProperty(EncryptRecordProcessor.REPLACEMENT_VALUE_STRATEGY, EncryptRecordProcessor.RECORD_PATH_VALUES.getValue());
        testRunner.setProperty(EncryptRecordProcessor.ENCRYPTION_ALGORITHM_TYPE,EncryptRecordProcessor.AES_CBC_VALUES);
        testRunner.setProperty(EncryptRecordProcessor.KEY_SIZE,EncryptRecordProcessor.KEY_SIZE_192_VALUES);
        testRunner.setProperty(EncryptRecordProcessor.SECRET_KEY,enecryptionTest.generateKey(192));


        testRunner.enqueue("");

        readerService.addRecord("John Doe", 35);
        testRunner.run();

        testRunner.assertAllFlowFilesTransferred(EncryptRecordProcessor.REL_SUCCESS, 1);
        final MockFlowFile out = testRunner.getFlowFilesForRelationship(EncryptRecordProcessor.REL_SUCCESS).get(0);
        System.out.println(out.toString());
        out.assertContentEquals("header\n35,35\n");
    }
}
