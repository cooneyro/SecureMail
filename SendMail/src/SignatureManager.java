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
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;

/**
 * For checking and creating detached signatures
 */
class SignatureManager {
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

    private static void checkSig(
            String originalFile,
            InputStream sigIn,
            InputStream key)
            throws GeneralSecurityException, IOException, PGPException {
        sigIn = PGPUtil.getDecoderStream(sigIn);

        PGPSignatureList sigList;
        JcaPGPObjectFactory factory = new JcaPGPObjectFactory(sigIn);


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

        if (sig.verify()) {
            System.err.println("Signature is correct.");
        } else {
            System.err.println("Signature does not match.");
        }
    }

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

    private static void createSignature(
            String fileName,
            InputStream keyStreamIn,
            OutputStream fileStreamOut,
            char[] pword)
            throws GeneralSecurityException, IOException, PGPException {
        fileStreamOut = new ArmoredOutputStream(fileStreamOut);

        PGPSecretKey secretKey = Utilities.retrieveSecretKey(keyStreamIn);
        PBESecretKeyDecryptor thisDecryptor = new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(pword);
        PGPPrivateKey privateKey = secretKey.extractPrivateKey(thisDecryptor);
        PGPContentSignerBuilder thisSigner = new JcaPGPContentSignerBuilder(secretKey.getPublicKey().getAlgorithm(), PGPUtil.SHA1).setProvider("BC");
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
        sigGen.generate().encode(outStream);
        fileStreamOut.close();
    }
}

