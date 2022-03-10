package com.safaricom.et.processors.encryption;



import com.safaricom.et.processors.encryption.service.encryption.AesEncryption;
import com.safaricom.et.processors.encryption.service.encryption.EncryptionAlgorithm;
import com.safaricom.et.processors.encryption.service.hashing.*;
import org.apache.nifi.annotation.documentation.Tags;
import org.apache.nifi.components.AllowableValue;
import org.apache.nifi.components.ValidationContext;
import org.apache.nifi.components.ValidationResult;
import org.apache.nifi.processor.*;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.apache.nifi.components.PropertyDescriptor;
import org.apache.nifi.expression.ExpressionLanguageScope;
import org.apache.nifi.flowfile.FlowFile;
import org.apache.nifi.flowfile.attributes.CoreAttributes;
import org.apache.nifi.processor.AbstractProcessor;
import org.apache.nifi.processor.exception.ProcessException;
import org.apache.nifi.processor.io.StreamCallback;
import org.apache.nifi.processor.util.StandardValidators;
import org.apache.nifi.record.path.FieldValue;
import org.apache.nifi.record.path.RecordPath;
import org.apache.nifi.record.path.RecordPathResult;
import org.apache.nifi.record.path.util.RecordPathCache;
import org.apache.nifi.record.path.validation.RecordPathPropertyNameValidator;
import org.apache.nifi.schema.access.SchemaNotFoundException;
import org.apache.nifi.serialization.*;
import org.apache.nifi.serialization.record.*;
import org.apache.nifi.annotation.behavior.ReadsAttribute;
import org.apache.nifi.annotation.behavior.ReadsAttributes;
import org.apache.nifi.annotation.behavior.WritesAttribute;
import org.apache.nifi.annotation.behavior.WritesAttributes;
import org.apache.nifi.annotation.lifecycle.OnScheduled;
import org.apache.nifi.annotation.documentation.CapabilityDescription;
import org.apache.nifi.annotation.documentation.SeeAlso;
import org.apache.nifi.serialization.RecordReaderFactory;

import static java.lang.Integer.parseInt;
import static com.safaricom.et.processors.encryption.utils.Utils.KeyValidator;


@Tags({"encryption", "decryption", "password", "JCE", "OpenPGP", "PGP", "GPG", "KDF", "Argon2", "Bcrypt", "Scrypt", "PBKDF2", "salt", "iv"})
@CapabilityDescription("Encrypts or Decrypts a FlowFile records using  symmetric encryption with a raw key  " +
        "and randomly generated salt, or asymmetric encryption using a public and secret key.")
@SeeAlso({})
@ReadsAttributes({@ReadsAttribute(attribute = "", description = "")})
@WritesAttributes({@WritesAttribute(attribute = "", description = "")})

public class EncryptRecord extends AbstractProcessor {
    Logger logger = Logger.getLogger(Logger.GLOBAL_LOGGER_NAME);
    private EncryptionAlgorithm encryption;
    private HashingAlgorithm hashingAlgorithm;
    private volatile RecordPathCache recordPathCache;
    private volatile List<String> recordPaths;


    static final AllowableValue LITERAL_VALUES = new AllowableValue("literal-value", "Literal Value",
            "The value entered for a Property (after Expression Language has been evaluated) is the desired value to update the Record Fields with. Expression Language "
                    + "may reference variables 'field.name', 'field.type', and 'field.value' to access information about the field and the value of the field being evaluated.");
    static final AllowableValue RECORD_PATH_VALUES = new AllowableValue("record-path-value", "Record Path Value",
            "The value entered for a Property (after Expression Language has been evaluated) is not the literal value to use but rather is a Record Path "
                    + "that should be evaluated against the Record, and the result of the RecordPath will be used to update the Record. Note that if this option is selected, "
                    + "and the Record Path results in multiple values for a given Record, the input FlowFile will be routed to the 'failure' Relationship.");

    static final AllowableValue AES_ECB_VALUES= new AllowableValue("AES/ECB/PKCS5Padding","AES_ECB");
    static final AllowableValue AES_CBC_VALUES= new AllowableValue("AES/CBC/PKCS5Padding","AES_CBC");
    static final AllowableValue KEY_SIZE_128_VALUES =new AllowableValue("128","AES_128");
    static final AllowableValue KEY_SIZE_192_VALUES =new AllowableValue("192","AES_192");
    static final AllowableValue KEY_SIZE_256_VALUES =new AllowableValue("256","AES_256");
    static final AllowableValue   ENCRYPT_MODE =  new AllowableValue("Encrypt","Encrypt");
    static final AllowableValue   DECRYPT_MODE =  new AllowableValue("Decrypt","Decrypt");
    static final AllowableValue HASHING = new AllowableValue("Hash", "Hash record") ;
//    public static final String DECRYPT_MODE = "";


    public static final   PropertyDescriptor RECORD_READER = new PropertyDescriptor.Builder()
            .name("record-reader")
            .displayName("Record Reader")
            .description("Specifies the Controller Service to use for reading incoming data")
            .identifiesControllerService(RecordReaderFactory.class)
            .required(true)
            .build();

    public  static final   PropertyDescriptor RECORD_WRITER = new PropertyDescriptor.Builder()
            .name("record-writer")
            .displayName("Record Writer")
            .description("Specifies the Controller Service to use for writing out the records")
            .identifiesControllerService(RecordSetWriterFactory.class)
            .required(true)
            .build();

    public static final PropertyDescriptor MODE = new PropertyDescriptor.Builder()
            .name("Mode")
            .displayName("Mode")
            .description("Specifies whether the content should be encrypted or decrypted")
            .allowableValues(ENCRYPT_MODE, DECRYPT_MODE, HASHING)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .required(true)
            .build();



    public  static final PropertyDescriptor INCLUDE_ZERO_RECORD_FLOWFILES = new PropertyDescriptor.Builder()
            .name("include-zero-record-flowfiles")
            .displayName("Include Zero Record FlowFiles")
            .description("When converting an incoming FlowFile, if the conversion results in no data, "
                    + "this property specifies whether or not a FlowFile will be sent to the corresponding relationship")
            .expressionLanguageSupported(ExpressionLanguageScope.NONE)
            .allowableValues("true", "false")
            .defaultValue("true")
            .required(true)
            .build();

//public static final PropertyDescriptor REPLACEMENT_VALUE_STRATEGY  = new PropertyDescriptor
//            .Builder()
//            .name("replacement-value-strategy")
//            .displayName("Replacement Value Strategy")
//            .description("Specifies how to interpret the configured replacement values")
//            .allowableValues(RECORD_PATH_VALUES,LITERAL_VALUES)
//            .expressionLanguageSupported(ExpressionLanguageScope.NONE)
//            .defaultValue(RECORD_PATH_VALUES.getValue())
//            .required(true)
//            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
//            .build();

    public static  final PropertyDescriptor ENCRYPTION_ALGORITHM_TYPE = new PropertyDescriptor
            .Builder()
            .name("encryption-algorithm-type")
            .displayName("Encryption Algorithm")
            .description("Specifies the type of algorithm used for encryption")
            .allowableValues(AES_CBC_VALUES,AES_ECB_VALUES)
            .expressionLanguageSupported(ExpressionLanguageScope.NONE)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .dependsOn(MODE, ENCRYPT_MODE, DECRYPT_MODE)
            .required(true)
            .build();

    public static  final PropertyDescriptor HASHING_ALGORITHM_TYPE = new PropertyDescriptor
            .Builder()
            .name("hashing-algorithm-type")
            .displayName("Hashing Algorithm")
            .description("Specifies the type of algorithm used for hashing")
            .allowableValues(HashingEnum.values())
            .expressionLanguageSupported(ExpressionLanguageScope.NONE)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .dependsOn(MODE, "Hash")
            .required(true)
            .build();

    public static final PropertyDescriptor KEY_SIZE = new PropertyDescriptor
            .Builder()
            .name("key-size")
            .displayName("Key Size")
            .description("Specifies the key size used in AES.")
            .allowableValues(KEY_SIZE_128_VALUES,KEY_SIZE_192_VALUES,KEY_SIZE_256_VALUES)
            .expressionLanguageSupported(ExpressionLanguageScope.NONE)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
//            .dependsOn(ENCRYPTION_ALGORITHM_TYPE, "true")
            .dependsOn(MODE, ENCRYPT_MODE, DECRYPT_MODE)
            .required(true)
            .build();

    public static final PropertyDescriptor SECRET_KEY = new PropertyDescriptor
            .Builder()
            .name("secret-key")
            .displayName("Secret Key")
            .description("Specifies key used for AES encryption")
            .required(true)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
//            .dependsOn(KEY_SIZE, "true")
            .dependsOn(MODE, ENCRYPT_MODE, DECRYPT_MODE)
            .expressionLanguageSupported(ExpressionLanguageScope.FLOWFILE_ATTRIBUTES)
            .sensitive(true)
            .build();

    public static final  Relationship REL_SUCCESS = new Relationship.Builder()
            .name("success")
            .description("FlowFile that its  records are successfully encrypted or decrypted will be routed to success")
            .build();

    public static final Relationship REL_FAILURE = new Relationship.Builder()
            .name("failure")
            .description("If a FlowFile cannot be transformed from the configured input format to the configured output format, "
                    + "the unchanged FlowFile will be routed to this relationship")
            .build();

    public static final Relationship REL_ORIGINAL = new Relationship.Builder()
            .name("original")
            .description(" Unchanged FlowFile will be routed to this relationship after success transformation.")
            .build();
    private List<PropertyDescriptor> descriptors;
    private Set<Relationship> relationships;


    @Override
    protected void init(final ProcessorInitializationContext context) {
        final List<PropertyDescriptor> descriptors = new ArrayList<>();
        descriptors.add(RECORD_READER);
        descriptors.add(RECORD_WRITER);
//        descriptors.add(REPLACEMENT_VALUE_STRATEGY);
        descriptors.add(MODE);
        descriptors.add(ENCRYPTION_ALGORITHM_TYPE);
        descriptors.add(HASHING_ALGORITHM_TYPE);
        descriptors.add(KEY_SIZE);
        descriptors.add(SECRET_KEY);

        this.descriptors = Collections.unmodifiableList(descriptors);

        final Set<Relationship> relationships = new HashSet<>();
        relationships.add(REL_SUCCESS);
        relationships.add(REL_FAILURE);
//        relationships.add(REL_ORIGINAL);
        this.relationships = Collections.unmodifiableSet(relationships);
    }
    @Override
    public Set<Relationship> getRelationships() {
        return this.relationships;
    }

    @Override
    public final List<PropertyDescriptor> getSupportedPropertyDescriptors() {
        return this.descriptors;
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
            if (!validationContext.getProperty(MODE).getValue().equals("Hash")) {
                String key = validationContext.getProperty(SECRET_KEY).getValue();
                if (key.length() >= 2) {
                    final boolean isKeyValid = KeyValidator(validationContext.getProperty(SECRET_KEY).getValue()
                            , parseInt(validationContext.getProperty(KEY_SIZE).getValue()));

                    if (isKeyValid) {
                        return Collections.emptyList();
                    }
                }
                return Collections.singleton(new ValidationResult.Builder()
                        .subject(" Invalid AES key: ")
                        .valid(false)
                        .explanation("Key  must be 16,24 or 32 bytes for 128, 192 or 256 key size  respectively")
                        .build());
            } else {
                return  Collections.emptyList();
            }
        }

        return Collections.singleton(new ValidationResult.Builder()
                .subject("User-defined Properties")
                .valid(false)
                .explanation("At least one RecordPath must be specified")
                .build());
    }


    @OnScheduled
    public void createRecordPaths(final ProcessContext context) {
        if (context.getProperty(MODE).getValue().equals("Hash")) {
            HashingEnum hashingEnum = HashingEnum.valueOf(context.getProperty(HASHING_ALGORITHM_TYPE).getValue());
            switch (hashingEnum) {
                case MD5:
                    hashingAlgorithm = new Md5Hashing();
                    break;
                case SHA1:
                    hashingAlgorithm = new Sha1Hashing();
                    break;
                case SHA256:
                    hashingAlgorithm = new Sha256Hashing();
                    break;
                case SHA512:
                    hashingAlgorithm = new Sha512Hashing();
            }
        }
        encryption = new AesEncryption(getLogger());
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

    @Override
    public void onTrigger(final ProcessContext context, final ProcessSession session) throws ProcessException {
        FlowFile flowFile = session.get();
        if (flowFile == null) {
            return;
        }

        final RecordReaderFactory readerFactory = context.getProperty(RECORD_READER).asControllerService(RecordReaderFactory.class);
        final RecordSetWriterFactory writerFactory = context.getProperty(RECORD_WRITER).asControllerService(RecordSetWriterFactory.class);
        final boolean includeZeroRecordFlowFiles = context.getProperty(INCLUDE_ZERO_RECORD_FLOWFILES).isSet()? context.getProperty(INCLUDE_ZERO_RECORD_FLOWFILES).asBoolean():true;

        final Map<String, String> attributes = new HashMap<>();
        final AtomicInteger recordCount = new AtomicInteger();

        final FlowFile original = flowFile;
        final Map<String, String> originalAttributes = flowFile.getAttributes();
        try {
            flowFile = session.write(flowFile, new StreamCallback() {
                @Override
                public void process(final InputStream in, final OutputStream out) throws IOException {

                    try (final RecordReader reader = readerFactory.createRecordReader(originalAttributes, in, original.getSize(), getLogger())) {

                        // Get the first record and process it before we create the Record Writer. We do this so that if the Processor
                        // updates the Record's schema, we can provide an updated schema to the Record Writer. If there are no records,
                        // then we can simply create the Writer with the Reader's schema and begin & end the Record Set.
                        Record firstRecord = reader.nextRecord();
                        getLogger().info(firstRecord.getValue("msisdn").toString());
                        if (firstRecord == null) {
                            final RecordSchema writeSchema = writerFactory.getSchema(originalAttributes, reader.getSchema());
                            try (final RecordSetWriter writer = writerFactory.createWriter(getLogger(), writeSchema, out, originalAttributes)) {
                                writer.beginRecordSet();

                                final WriteResult writeResult = writer.finishRecordSet();
                                attributes.put("record.count", String.valueOf(writeResult.getRecordCount()));
                                attributes.put(CoreAttributes.MIME_TYPE.key(), writer.getMimeType());
                                attributes.putAll(writeResult.getAttributes());
                                attributes.put("algorithm", context.getProperty(ENCRYPTION_ALGORITHM_TYPE).getValue());
                                recordCount.set(writeResult.getRecordCount());
                            }

                            return;
                        }

                        firstRecord = processRecords(firstRecord, original, context, 1L);

                        final RecordSchema writeSchema = writerFactory.getSchema(originalAttributes, firstRecord.getSchema());
                        try (final RecordSetWriter writer = writerFactory.createWriter(getLogger(), writeSchema, out, originalAttributes)) {
                            writer.beginRecordSet();
                            writer.write(firstRecord);

                            Record record;
                            long count = 1L;
                            while ((record = reader.nextRecord()) != null) {
                                final Record processed = processRecords(record, original, context, ++count);
                                writer.write(processed);
                            }

                            final WriteResult writeResult = writer.finishRecordSet();
                            attributes.put("record.count", String.valueOf(writeResult.getRecordCount()));
                            attributes.put(CoreAttributes.MIME_TYPE.key(), writer.getMimeType());
                            attributes.putAll(writeResult.getAttributes());
                            recordCount.set(writeResult.getRecordCount());
                        }
                    } catch (final SchemaNotFoundException e) {
                        throw new ProcessException(e.getLocalizedMessage(), e);
                    } catch (final MalformedRecordException e) {
                        throw new ProcessException("Could not parse incoming data", e);
                    }
                }
            });
        } catch (final Exception e) {
            getLogger().error("Failed to process {}; will route to failure", new Object[] {flowFile, e});
            // Since we are wrapping the exceptions above there should always be a cause
            // but it's possible it might not have a message. This handles that by logging
            // the name of the class thrown.
            Throwable c = e.getCause();
            if (c != null) {
                session.putAttribute(flowFile, "record.error.message", (c.getLocalizedMessage() != null) ? c.getLocalizedMessage() : c.getClass().getCanonicalName() + " Thrown");
            } else {
                session.putAttribute(flowFile, "record.error.message", e.getClass().getCanonicalName() + " Thrown");
            }
            session.transfer(flowFile, REL_FAILURE);
            return;
        }

        flowFile = session.putAllAttributes(flowFile, attributes);
        if(!includeZeroRecordFlowFiles && recordCount.get() == 0){
            session.remove(flowFile);
        } else {
            session.transfer(flowFile, REL_SUCCESS);
        }

        final int count = recordCount.get();
        session.adjustCounter("Records Processed", count, false);
        getLogger().info("Successfully converted {} records for {}", new Object[] {count, flowFile});
    }

    protected  Record processRecords(Record record, FlowFile flowFile, ProcessContext context, long count){

        for (final String recordPathText : recordPaths) {
//            getLogger().info("recordPathText: "+recordPathText);
            final RecordPath recordPath = recordPathCache.getCompiled(recordPathText);
            final RecordPathResult result = recordPath.evaluate(record);

            final String replacementValue = context.getProperty(recordPathText).evaluateAttributeExpressions(flowFile).getValue();
//            getLogger().info("replacementValue : "+replacementValue);
            final RecordPath replacementRecordPath = recordPathCache.getCompiled(replacementValue);

            // If we have an Absolute RecordPath, we need to evaluate the RecordPath only once against the Record.
            // If the RecordPath is a Relative Path, then we have to evaluate it against each FieldValue.
            record = processAbsolutePath(replacementRecordPath, result.getSelectedFields(), record,context);
        }

        record.incorporateInactiveFields();
        return  record;
    };

    private Record processAbsolutePath(final RecordPath replacementRecordPath, final Stream<FieldValue> destinationFields, final Record record,
                                   ProcessContext context ) {
        final RecordPathResult replacementResult = replacementRecordPath.evaluate(record);
        final List<FieldValue> selectedFields = replacementResult.getSelectedFields().collect(Collectors.toList());
//        getLogger().info(selectedFields.toString());
        final List<FieldValue> destinationFieldValues = destinationFields.collect(Collectors.toList());
        return updateRecord(destinationFieldValues, selectedFields, record, context);
    }

    private Record updateRecord(final List<FieldValue> destinationFields, final List<FieldValue> selectedFields,
                                final Record record,ProcessContext context) {

        if (destinationFields.size() == 1 && !destinationFields.get(0).getParentRecord().isPresent()) {
            final Object replacement = getReplacementObject(selectedFields,context);
            logger.info(replacement.toString());
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
                final Object replacementObject = getReplacementObject(selectedFields,context);
                updateFieldValue(fieldVal, replacementObject);
            }
            return record;
        }
    }

    private Object getReplacementObject(final List<FieldValue> selectedFields, ProcessContext context) {
        if (selectedFields.size() > 1) {
            final List<RecordField> fields = selectedFields.stream().map(FieldValue::getField).collect(Collectors.toList());
            final RecordSchema schema = new SimpleRecordSchema(fields);
            final Record record = new MapRecord(schema, new HashMap<>());
            for (final FieldValue fieldVal : selectedFields) {
                record.setValue(fieldVal.getField(),getReplacementValue(fieldVal.getValue().toString(),context));
            }
            return record;
        }

        if (selectedFields.isEmpty()) {
            return null;
        } else {
            return getReplacementValue(selectedFields.get(0).toString(),context);
        }
    }

    private void updateFieldValue(final FieldValue fieldValue, final Object replacement) {
        if (replacement instanceof FieldValue) {
            final FieldValue replacementFieldValue = (FieldValue) replacement;
            fieldValue.updateValue(replacementFieldValue.getValue(), replacementFieldValue.getField().getDataType());
        } else {
            fieldValue.updateValue(replacement);
        }
    }

    private  String getReplacementValue(String input,ProcessContext context){
         final String secretKey = context.getProperty(SECRET_KEY).getValue();
         final String aes_algorithm = context.getProperty(ENCRYPTION_ALGORITHM_TYPE).getValue();

        if (context.getProperty(MODE).getValue().equals("Encrypt")){

            return  encryption.encrypt(aes_algorithm,input,secretKey);
        }else if (context.getProperty(MODE).getValue().equals("Decrypt")) {

            return  encryption.decrypt(aes_algorithm,input,secretKey);
        } else {
            return hashingAlgorithm.hash(input);
        }

    }
}

