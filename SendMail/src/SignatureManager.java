import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import java.io.OutputStream;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import java.io.FileInputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import java.security.GeneralSecurityException;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.*;
import java.io.FileOutputStream;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import java.io.IOException;
import java.io.InputStream;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import java.io.BufferedOutputStream;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import java.io.BufferedInputStream;
import java.util.Iterator;

import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;

/**
 * For checking and creating detached signatures
 */
class SignatureManager {
    /**
     *
     * @param originalFile Original file sent (encrypted using public key)
     * @param sigFile Signed file (signed with private key)
     * @param keyFile Public key file
     * @throws GeneralSecurityException
     * @throws IOException
     * @throws PGPException
     */
    static void checkSig(
            String originalFile,
            String sigFile,
            String keyFile)
            throws GeneralSecurityException, IOException, PGPException {
        InputStream key = new BufferedInputStream(new FileInputStream(keyFile));
        InputStream sigIn = new BufferedInputStream(new FileInputStream(sigFile));

        checkSig(originalFile, sigIn, key);

        key.close();
        sigIn.close();
    }

    /**
     *
     * @param originalFile Original file
     * @param sigIn Signed file stream
     * @param key Public key file stream
     * @throws GeneralSecurityException
     * @throws IOException
     * @throws PGPException
     */
    private static void checkSig(
            String originalFile,
            InputStream sigIn,
            InputStream key)
            throws GeneralSecurityException, IOException, PGPException {
        sigIn = PGPUtil.getDecoderStream(sigIn);

        PGPSignatureList sigList;
        JcaPGPObjectFactory factory = new JcaPGPObjectFactory(sigIn);


        //decompress data
        Object nextObject = factory.nextObject();
        if (nextObject instanceof PGPCompressedData) {
            PGPCompressedData comp = (PGPCompressedData) nextObject;
            factory = new JcaPGPObjectFactory(comp.getDataStream());
            sigList = (PGPSignatureList) factory.nextObject();
        } else {
            sigList = (PGPSignatureList) nextObject;
        }

        JcaKeyFingerprintCalculator thisCalc = new JcaKeyFingerprintCalculator();
        PGPPublicKeyRingCollection prc = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(key), thisCalc);


        InputStream originalFileIn = new BufferedInputStream(new FileInputStream(originalFile));

        int index = 0;
        PGPSignature sig = sigList.get(index);
        PGPPublicKey thisKey = prc.getPublicKey(sig.getKeyID());



        JcaPGPContentVerifierBuilderProvider thisProv = new JcaPGPContentVerifierBuilderProvider().setProvider("BC");
        sig.init(thisProv, thisKey);

        int character;
        while ((character = originalFileIn.read()) >= 0) {
            sig.update((byte) character);
        }

        originalFileIn.close();

        //check signature
        if (sig.verify()) {
            System.err.println("Signature is correct.");
        } else {
            System.err.println("Signature does not match.");
        }
    }

    /**
     *
     * @param fileIn File to be signed
     * @param keyFile Private key file
     * @param fileOut File for signed content to be output to
     * @param pword Key file password
     * @throws GeneralSecurityException
     * @throws IOException
     * @throws PGPException
     */
    static void createSignature(
            String fileIn,
            String keyFile,
            String fileOut,
            char[] pword)
            throws GeneralSecurityException, IOException, PGPException {
        InputStream keyIn = new BufferedInputStream(new FileInputStream(keyFile));
        OutputStream out = new BufferedOutputStream(new FileOutputStream(fileOut));

        createSignature(fileIn, keyIn, out, pword);

        out.close();
        keyIn.close();
    }

    /**
     *
     * @param fileName File to be signed (path)
     * @param keyStreamIn Input stream private key
     * @param fileStreamOut Output stream of signed content
     * @param pword Password associated with private key
     * @throws GeneralSecurityException
     * @throws IOException
     * @throws PGPException
     */
    private static void createSignature(
            String fileName,
            InputStream keyStreamIn,
            OutputStream fileStreamOut,
            char[] pword)
            throws GeneralSecurityException, IOException, PGPException {
        fileStreamOut = new ArmoredOutputStream(fileStreamOut);

        //retrieve and extract private key
        PGPSecretKey secretKey = retrieveSecretKey(keyStreamIn);
        PBESecretKeyDecryptor thisDecryptor = new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(pword);
        PGPPrivateKey privateKey = secretKey.extractPrivateKey(thisDecryptor);
        PGPContentSignerBuilder thisSigner = new JcaPGPContentSignerBuilder(secretKey.getPublicKey().getAlgorithm(), PGPUtil.SHA1).setProvider("BC");
        //use signature generator to generate a signature
        PGPSignatureGenerator sigGen = new PGPSignatureGenerator(thisSigner);


        int sigType = PGPSignature.BINARY_DOCUMENT;
        sigGen.init(sigType, privateKey);
        BCPGOutputStream outStream = new BCPGOutputStream(fileStreamOut);
        InputStream readFileIn = new BufferedInputStream(new FileInputStream(fileName));

        int character;
        while ((character = readFileIn.read()) >= 0) {
            sigGen.update((byte) character);
        }
        readFileIn.close();
        //generate signature file to output stream
        sigGen.generate().encode(outStream);
        fileStreamOut.close();
    }

    //return a secret key given its input stream
    static PGPSecretKey retrieveSecretKey(InputStream input) throws IOException, PGPException {
        PGPSecretKeyRingCollection skrc = new PGPSecretKeyRingCollection(
                PGPUtil.getDecoderStream(input), new JcaKeyFingerprintCalculator());

        Iterator ringIterator = skrc.getKeyRings();
        while (ringIterator.hasNext()) {
            PGPSecretKeyRing keyRing = (PGPSecretKeyRing) ringIterator.next();

            //returns first private key found
            Iterator keyIterator = keyRing.getSecretKeys();
            while (keyIterator.hasNext()) {
                PGPSecretKey thisKey = (PGPSecretKey) keyIterator.next();

                if (thisKey.isSigningKey()) {
                    return thisKey;
                }
            }
        }

        throw new IllegalArgumentException("Can't find key to sign with.");
    }
}

