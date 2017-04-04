


import org.bouncycastle.bcpg.ArmoredOutputStream;
import java.io.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import java.security.NoSuchProviderException;

import org.bouncycastle.openpgp.operator.jcajce.*;

import java.security.Security;
import java.util.Iterator;
import java.security.SecureRandom;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.util.io.Streams;

/**
 * Handles encryption and decryption of files
 */
public class EncryptionHandler {
    /**
     *
     * @param fileInput file to be decrypted
     * @param keyInput key collection for decrypting
     * @param pass password for keys
     * @param fileOutput file to which decryption will be output to
     * @throws IOException
     * @throws NoSuchProviderException
     */
    static void getDecrypted(
            String fileInput,
            String keyInput,
            char[] pass,
            String fileOutput)
            throws IOException, NoSuchProviderException {
        InputStream in = new BufferedInputStream(new FileInputStream(fileInput));
        InputStream keyIn = new BufferedInputStream(new FileInputStream(keyInput));
        getDecrypted(in, keyIn, pass, fileOutput);
        keyIn.close();
        in.close();
    }

    /**
     *
     * @param fileInput Stream of file to be decrypted
     * @param keyInput Stream of key collection to be used to decrypt
     * @param pass Password to keys
     * @param fileOutput output stream
     * @throws IOException
     * @throws NoSuchProviderException
     */
    private static void getDecrypted(
            InputStream fileInput,
            InputStream keyInput,
            char[] pass,
            String fileOutput)
            throws IOException, NoSuchProviderException {
        fileInput = PGPUtil.getDecoderStream(fileInput);

        try {
            JcaPGPObjectFactory objFactory = new JcaPGPObjectFactory(fileInput);
            PGPEncryptedDataList encDataList;

            // Looking for encrypted data

            Object nextFactObject = objFactory.nextObject();
            if (nextFactObject instanceof PGPEncryptedDataList) {
                encDataList = (PGPEncryptedDataList) nextFactObject;
            } else {
                encDataList = (PGPEncryptedDataList) objFactory.nextObject();
            }

            Iterator iterate = encDataList.getEncryptedDataObjects();
            PGPPrivateKey privateKey = null;
            PGPPublicKeyEncryptedData data = null;
            PGPSecretKeyRingCollection secretKeys = new PGPSecretKeyRingCollection(
                    PGPUtil.getDecoderStream(keyInput), new JcaKeyFingerprintCalculator());
            //find private key for decrypting
            while (privateKey == null && iterate.hasNext()) {
                data = (PGPPublicKeyEncryptedData) iterate.next();

                privateKey = retrieveSecretKey(secretKeys, data.getKeyID(), pass);
            }

            if (privateKey == null) {
                throw new IllegalArgumentException("Error locating key for message.");
            }

            //build decryptor
            InputStream dataIn = data.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(privateKey));
            JcaPGPObjectFactory newObjectFactory = new JcaPGPObjectFactory(dataIn);
            Object part = newObjectFactory.nextObject();

            //decompress data
            if (part instanceof PGPCompressedData) {
                PGPCompressedData compData = (PGPCompressedData) part;
                JcaPGPObjectFactory objFact = new JcaPGPObjectFactory(compData.getDataStream());

                part = objFact.nextObject();
            }
            //output data that has been decrypted
            if (part instanceof PGPLiteralData) {
                PGPLiteralData thisData = (PGPLiteralData) part;

                String outFileName = fileOutput;

                InputStream unEnc = thisData.getInputStream();
                OutputStream fileOut = new BufferedOutputStream(new FileOutputStream(outFileName));

                Streams.pipeAll(unEnc, fileOut);

                fileOut.close();
            } else if (part instanceof PGPOnePassSignatureList) {
                throw new PGPException("Error. Encrypted message contains signed message");
            } else {
                throw new PGPException("Error. Cannot determine file type.");
            }

            if (data.isIntegrityProtected()) {
                if (!data.verify()) {
                    System.err.println("Message has failed integrity check");
                } else {
                    System.err.println("Message successfully passed integrity check");
                }
            } else {
                System.err.println("Message integrity not checked");
            }
        } catch (PGPException e) {
            System.err.println(e);
            if (e.getUnderlyingException() != null) {
                e.getUnderlyingException().printStackTrace();
            }
        }
    }

    /**
     *
     * @param encryptedFile File to which encrypted output will be written
     * @param inputFile File to be encrypted
     * @param keyFile Key collection file
     * @param id Identity of recipient of e-mail
     * @throws IOException
     * @throws NoSuchProviderException
     * @throws PGPException
     */
    static void getEncrypted(
            String encryptedFile,
            String inputFile,
            String keyFile,
            String id)
            throws IOException, NoSuchProviderException, PGPException {
        InputStream inStream = new FileInputStream(keyFile);
        PGPPublicKeyRingCollection thisCollection = new PGPPublicKeyRingCollection(
                PGPUtil.getDecoderStream(inStream), new JcaKeyFingerprintCalculator());
        //find corresponding public key to identity
        Iterator<PGPPublicKeyRing> thisList = thisCollection.getKeyRings(id);
        OutputStream outStream = new BufferedOutputStream(new FileOutputStream(encryptedFile));
        PGPPublicKey key = thisList.next().getPublicKey();
        getEncrypted(outStream, inputFile, key);
        outStream.close();
    }

    /**
     *
     * @param encryptedFile Output stream of encrypted data
     * @param fileName Input stream of data to be encrypted
     * @param encKey Key to be used for encryption
     * @throws IOException
     * @throws NoSuchProviderException
     */
    private static void getEncrypted(
            OutputStream encryptedFile,
            String fileName,
            PGPPublicKey encKey)
            throws IOException, NoSuchProviderException {
        encryptedFile = new ArmoredOutputStream(encryptedFile);
        Security.addProvider(new BouncyCastleProvider());

        try {
            byte[] fileToBytes = compFile(fileName, CompressionAlgorithmTags.ZIP);
            //use data encryptor for creating encrypted data generator
            JcePGPDataEncryptorBuilder thisBuilder = new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5);
            thisBuilder.setWithIntegrityPacket(true);
            thisBuilder.setSecureRandom(new SecureRandom());
            thisBuilder.setProvider("BC");
            PGPEncryptedDataGenerator dataGen = new PGPEncryptedDataGenerator(thisBuilder);
            dataGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encKey).setProvider("BC"));
            //use encrypted data generator to write to file
            OutputStream writeToFile = dataGen.open(encryptedFile, fileToBytes.length);
            writeToFile.write(fileToBytes);
            writeToFile.close();
            encryptedFile.close();
        } catch (PGPException e) {
            System.err.println(e);
        }
    }

    // Retrieve a secret key given a key ring collection, the key's ID and password
    static PGPPrivateKey retrieveSecretKey(PGPSecretKeyRingCollection krc, long ID, char[] pw)
            throws PGPException, NoSuchProviderException {
        PGPSecretKey krcKey = krc.getSecretKey(ID);

        if (krcKey == null) {
            return null;
        }

        return krcKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(pw));
    }

    // compress file using given algorithm
    static byte[] compFile(String file, int alg) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        PGPCompressedDataGenerator compressed = new PGPCompressedDataGenerator(alg);
        char type = PGPLiteralData.BINARY;
        PGPUtil.writeFileToLiteralData(compressed.open(outputStream), type, new File(file));
        compressed.close();
        return outputStream.toByteArray();
    }
}