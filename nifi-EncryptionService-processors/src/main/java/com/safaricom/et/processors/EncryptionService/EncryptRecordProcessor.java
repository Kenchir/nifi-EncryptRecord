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

import com.safaricom.et.processors.EncryptionService.Utils.AbstractEncryptRecordProcessor;
import com.safaricom.et.processors.EncryptionService.Utils.Encryption;
import org.apache.nifi.components.AllowableValue;
import org.apache.nifi.components.PropertyDescriptor;
import org.apache.nifi.components.ValidationContext;
import org.apache.nifi.components.ValidationResult;
import org.apache.nifi.expression.ExpressionLanguageScope;
import org.apache.nifi.flowfile.FlowFile;
import org.apache.nifi.annotation.behavior.ReadsAttribute;
import org.apache.nifi.annotation.behavior.ReadsAttributes;
import org.apache.nifi.annotation.behavior.WritesAttribute;
import org.apache.nifi.annotation.behavior.WritesAttributes;
import org.apache.nifi.annotation.lifecycle.OnScheduled;
import org.apache.nifi.annotation.documentation.CapabilityDescription;
import org.apache.nifi.annotation.documentation.SeeAlso;
import org.apache.nifi.annotation.documentation.Tags;
import org.apache.nifi.processor.ProcessContext;
import org.apache.nifi.processor.Relationship;
import org.apache.nifi.processor.util.StandardValidators;
import org.apache.nifi.record.path.FieldValue;
import org.apache.nifi.record.path.RecordPath;
import org.apache.nifi.record.path.RecordPathResult;
import org.apache.nifi.record.path.util.RecordPathCache;
import org.apache.nifi.record.path.validation.RecordPathPropertyNameValidator;
import org.apache.nifi.serialization.SimpleRecordSchema;
import org.apache.nifi.serialization.record.MapRecord;
import org.apache.nifi.serialization.record.Record;
import org.apache.nifi.serialization.record.RecordField;
import org.apache.nifi.serialization.record.RecordSchema;
import sun.security.util.math.intpoly.IntegerPolynomial448;

import java.util.*;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static java.lang.Integer.parseInt;

@Tags({"example"})
@CapabilityDescription("Provide a description")
@SeeAlso({})
@ReadsAttributes({@ReadsAttribute(attribute="", description="")})
@WritesAttributes({@WritesAttribute(attribute="", description="")})
public class EncryptRecordProcessor extends AbstractEncryptRecordProcessor {

    Logger logger = Logger.getLogger(Logger.GLOBAL_LOGGER_NAME);
    private static final String FIELD_NAME = "field.name";
    private static final String FIELD_VALUE = "field.value";
    private static final String FIELD_TYPE = "field.type";

    private static final String RECORD_INDEX = "record.index";

    private volatile RecordPathCache recordPathCache;
    private volatile List<String> recordPaths;

    private static Encryption encryption = new Encryption();
    static final AllowableValue LITERAL_VALUES = new AllowableValue("literal-value", "Literal Value",
            "The value entered for a Property (after Expression Language has been evaluated) is the desired value to update the Record Fields with. Expression Language "
                    + "may reference variables 'field.name', 'field.type', and 'field.value' to access information about the field and the value of the field being evaluated.");
    static final AllowableValue RECORD_PATH_VALUES = new AllowableValue("record-path-value", "Record Path Value",
            "The value entered for a Property (after Expression Language has been evaluated) is not the literal value to use but rather is a Record Path "
                    + "that should be evaluated against the Record, and the result of the RecordPath will be used to update the Record. Note that if this option is selected, "
                    + "and the Record Path results in multiple values for a given Record, the input FlowFile will be routed to the 'failure' Relationship.");

    static final AllowableValue AES_ECB_VALUES= new AllowableValue("AES/ECB/PKCS5Padding","AES/ECB/PKCS5Padding");
    static final AllowableValue AES_CBC_VALUES= new AllowableValue("AES/CBC/PKCS5Padding","AES/CBC/PKCS5Padding");
    static final AllowableValue KEY_SIZE_128_VALUES =new AllowableValue("128","128 bits.");
    static final AllowableValue KEY_SIZE_192_VALUES =new AllowableValue("192","192 bits.");
    static final AllowableValue KEY_SIZE_256_VALUES =new AllowableValue("256","256 bits.");

    public static final PropertyDescriptor REPLACEMENT_VALUE_STRATEGY  = new PropertyDescriptor
            .Builder()
            .name("replacement-value-strategy")
            .displayName("Replacement Value Strategy")
            .description("Specifies how to interpret the configured replacement values")
            .allowableValues(RECORD_PATH_VALUES,LITERAL_VALUES)
            .expressionLanguageSupported(ExpressionLanguageScope.NONE)
            .defaultValue(LITERAL_VALUES.getValue())
            .required(true)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();

    public static  final PropertyDescriptor ENCRYPTION_ALGORITHM_TYPE = new PropertyDescriptor
            .Builder()
            .name("encryption-algorithm-type")
            .displayName("Encryption Algorithm")
            .description("Specifies the type of algorithm used for encryption")
            .allowableValues(AES_CBC_VALUES,AES_ECB_VALUES)
            .expressionLanguageSupported(ExpressionLanguageScope.NONE)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .required(true)
            .build();

    public static final PropertyDescriptor KEY_SIZE = new PropertyDescriptor
            .Builder()
            .name("key-size")
            .displayName("Key Size")
            .description("Specifies the key size used in AES.")
            .required(true)
            .allowableValues(KEY_SIZE_128_VALUES,KEY_SIZE_192_VALUES,KEY_SIZE_256_VALUES)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .expressionLanguageSupported(ExpressionLanguageScope.NONE)
            .dependsOn(ENCRYPTION_ALGORITHM_TYPE, "true")
            .build();

    public static final PropertyDescriptor SECRET_KEY = new PropertyDescriptor
            .Builder()
            .name("secret-key")
            .displayName("Secret Key")
            .description("Specifies key used for AES encryption")
            .required(true)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .dependsOn(KEY_SIZE, "true")
            .build();


//    @Override
//    protected void init(final ProcessorInitializationContext context) {
//        descriptors = new ArrayList<>();
//        descriptors.add(MY_PROPERTY);
//        descriptors = Collections.unmodifiableList(descriptors);
//
//        relationships = new HashSet<>();
//        relationships.add(this.getRelationships());
//        relationships = Collections.unmodifiableSet(relationships);
//    }

    @Override
    public Set<Relationship> getRelationships() {
        return super.getRelationships();
    }

    @Override
    public final List<PropertyDescriptor> getSupportedPropertyDescriptors() {
        final List<PropertyDescriptor> properties = new ArrayList<>(super.getSupportedPropertyDescriptors());
        properties.add(REPLACEMENT_VALUE_STRATEGY);
        properties.add(ENCRYPTION_ALGORITHM_TYPE);
        properties.add(KEY_SIZE);
        properties.add(SECRET_KEY);
        return properties;
    }

    @Override
    protected PropertyDescriptor getSupportedDynamicPropertyDescriptor(final String propertyDescriptorName) {
        return new PropertyDescriptor.Builder()
                .name(propertyDescriptorName)
                .description("Specifies the value to use to replace fields in the record that match the RecordPath: " + propertyDescriptorName)
                .required(false)
                .dynamic(true)
                .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
                .addValidator(new RecordPathPropertyNameValidator())
                .build();
    }
    @Override
    protected Collection<ValidationResult> customValidate(final ValidationContext validationContext) {
        final boolean containsDynamic = validationContext.getProperties().keySet().stream().anyMatch(PropertyDescriptor::isDynamic);

        if (containsDynamic) {
            String key =validationContext.getProperty(SECRET_KEY).getValue();
            logger.info("Key: " +key);
            logger.info("Key size; "+ validationContext.getProperty(KEY_SIZE).getValue());
            if(key != null){
                final  boolean isKeyValid=encryption.KEY_VALIDATOR(validationContext.getProperty(SECRET_KEY).getValue()
                        ,parseInt(validationContext.getProperty(KEY_SIZE).getValue()));

                if(isKeyValid){
                    return Collections.emptyList();
                }
            }
            return Collections.singleton(new ValidationResult.Builder()
                    .subject(" Invalid AES key length")
                    .valid(false)
                    .explanation("Key  must be 16,24 or 32 bytes for 128, 192 or 256 key sizes  respectively")
                    .build());
        }

        return Collections.singleton(new ValidationResult.Builder()
                .subject("User-defined Properties")
                .valid(false)
                .explanation("At least one RecordPath must be specified")
                .build());
    }

    @OnScheduled
    public void createRecordPaths(final ProcessContext context) {
        recordPathCache = new RecordPathCache(context.getProperties().size() * 2);

        final List<String> recordPaths = new ArrayList<>(context.getProperties().size() - 2);
        for (final PropertyDescriptor property : context.getProperties().keySet()) {
            if (property.isDynamic()) {
                logger.info("Record property: " +  property.getName() + " value: " + property.getDefaultValue());
                recordPaths.add(property.getName());
            }
        }
        this.recordPaths = recordPaths;
    }
    private Record processAbsolutePath(final RecordPath replacementRecordPath, final Stream<FieldValue> destinationFields, final Record record) {
        final RecordPathResult replacementResult = replacementRecordPath.evaluate(record);
        final List<FieldValue> selectedFields = replacementResult.getSelectedFields().collect(Collectors.toList());
        final List<FieldValue> destinationFieldValues = destinationFields.collect(Collectors.toList());

        return updateRecord(destinationFieldValues, selectedFields, record);
    }
    @Override
    protected Record process(Record record, final FlowFile flowFile, final ProcessContext context, final long count) {
//        final boolean evaluateValueAsRecordPath = context.getProperty(REPLACEMENT_VALUE_STRATEGY).getValue().equals(RECORD_PATH_VALUES.getValue());

        for (final String recordPathText : recordPaths) {
            final RecordPath recordPath = recordPathCache.getCompiled(recordPathText);
            final RecordPathResult result = recordPath.evaluate(record);
            final String replacementValue = context.getProperty(recordPathText).evaluateAttributeExpressions(flowFile).getValue();
            final RecordPath replacementRecordPath = recordPathCache.getCompiled(replacementValue);
            record = processAbsolutePath(replacementRecordPath, result.getSelectedFields(), record);
        }

        record.incorporateInactiveFields();

        return record;
    }
    private void updateFieldValue(final FieldValue fieldValue, final Object replacement) {

        if (replacement instanceof FieldValue) {
            final FieldValue replacementFieldValue = (FieldValue) replacement;
            fieldValue.updateValue(replacementFieldValue.getValue(), replacementFieldValue.getField().getDataType());
        } else {
            fieldValue.updateValue(replacement);
        }
    }
    private Record updateRecord(final List<FieldValue> destinationFields, final List<FieldValue> selectedFields, final Record record) {
        if (destinationFields.size() == 1 && !destinationFields.get(0).getParentRecord().isPresent()) {
            final Object replacement = getReplacementObject(selectedFields);
            if (replacement == null) {
                return record;
            }

            if (replacement instanceof Record) {
                return (Record) replacement;
            }

            final FieldValue replacementFieldValue = (FieldValue) replacement;

            if (replacementFieldValue.getValue() instanceof Record) {
                return (Record) replacementFieldValue.getValue();
            }

            final List<RecordField> fields = selectedFields.stream().map(FieldValue::getField).collect(Collectors.toList());
            final RecordSchema schema = new SimpleRecordSchema(fields);
            final Record mapRecord = new MapRecord(schema, new HashMap<>());
            for (final FieldValue selectedField : selectedFields) {
                mapRecord.setValue(selectedField.getField(), selectedField.getValue());
            }

            return mapRecord;
        } else {
            for (final FieldValue fieldVal : destinationFields) {
                final Object replacementObject = getReplacementObject(selectedFields);
                updateFieldValue(fieldVal, replacementObject);
            }
            return record;
        }
    }
    private Object getReplacementObject(final List<FieldValue> selectedFields) {
        if (selectedFields.size() > 1) {
            final List<RecordField> fields = selectedFields.stream().map(FieldValue::getField).collect(Collectors.toList());
            final RecordSchema schema = new SimpleRecordSchema(fields);
            final Record record = new MapRecord(schema, new HashMap<>());
            for (final FieldValue fieldVal : selectedFields) {
                record.setValue(fieldVal.getField(), fieldVal.getValue());
            }

            return record;
        }

        if (selectedFields.isEmpty()) {
            return null;
        } else {
            return selectedFields.get(0);
        }
    }
}
