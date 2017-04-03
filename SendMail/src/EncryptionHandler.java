


import org.bouncycastle.bcpg.ArmoredOutputStream;
import java.io.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import java.security.NoSuchProviderException;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import java.security.Security;
import java.util.Iterator;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import java.security.SecureRandom;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.util.io.Streams;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;

/**
 * Handles encryption and decryption of files
 */
public class EncryptionHandler {
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
     * decrypt the passed in message stream
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

            while (privateKey == null && iterate.hasNext()) {
                data = (PGPPublicKeyEncryptedData) iterate.next();

                privateKey = Utilities.retrieveSecretKey(secretKeys, data.getKeyID(), pass);
            }

            if (privateKey == null) {
                throw new IllegalArgumentException("Error locating key for message.");
            }

            InputStream dataIn = data.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(privateKey));
            JcaPGPObjectFactory newObjectFactory = new JcaPGPObjectFactory(dataIn);
            Object part = newObjectFactory.nextObject();

            if (part instanceof PGPCompressedData) {
                PGPCompressedData compData = (PGPCompressedData) part;
                JcaPGPObjectFactory objFact = new JcaPGPObjectFactory(compData.getDataStream());

                part = objFact.nextObject();
            }

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

    static void getEncrypted(
            String encryptedFile,
            String inputFile,
            String keyFile,
            String id)
            throws IOException, NoSuchProviderException, PGPException {
        InputStream inStream = new FileInputStream(keyFile);
        PGPPublicKeyRingCollection thisCollection = new PGPPublicKeyRingCollection(
                PGPUtil.getDecoderStream(inStream), new JcaKeyFingerprintCalculator());
        Iterator<PGPPublicKeyRing> thisList = thisCollection.getKeyRings(id);
        OutputStream outStream = new BufferedOutputStream(new FileOutputStream(encryptedFile));
        PGPPublicKey key = thisList.next().getPublicKey();
        getEncrypted(outStream, inputFile, key);
        outStream.close();
    }

    private static void getEncrypted(
            OutputStream encryptedFile,
            String fileName,
            PGPPublicKey encKey)
            throws IOException, NoSuchProviderException {
        encryptedFile = new ArmoredOutputStream(encryptedFile);
        Security.addProvider(new BouncyCastleProvider());

        try {
            byte[] fileToBytes = Utilities.compFile(fileName, CompressionAlgorithmTags.ZIP);
            JcePGPDataEncryptorBuilder thisBuilder = new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5);
            thisBuilder.setWithIntegrityPacket(true);
            thisBuilder.setSecureRandom(new SecureRandom());
            thisBuilder.setProvider("BC");
            PGPEncryptedDataGenerator dataGen = new PGPEncryptedDataGenerator(thisBuilder);
            dataGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encKey).setProvider("BC"));
            OutputStream writeToFile = dataGen.open(encryptedFile, fileToBytes.length);
            writeToFile.write(fileToBytes);
            writeToFile.close();
            encryptedFile.close();
        } catch (PGPException e) {
            System.err.println(e);
        }
    }
}