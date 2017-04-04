import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;

import org.bouncycastle.openpgp.operator.jcajce.*;
import org.bouncycastle.openpgp.*;
import java.security.*;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import java.util.Date;
import java.util.Iterator;
import java.util.Scanner;

//Loading keys to program or creating keys for new user
public class Initialize {
    public static void main(String[] args) throws java.lang.Exception {
        Security.addProvider(new BouncyCastleProvider());

        Scanner sc = new Scanner(System.in);
        System.out.println("If you have existing public and secret keys, press 1 to load them in");
        System.out.println("Otherwise press 2 to create new keys");
        System.out.println("Note if you create new keys, your default identity is R, password is C");
        int choice = sc.nextInt();
        if (choice == 1) {
            PGPKeyPair thisPair = new PGPKeyPair(getPubKey("keys/pub.asc"), retrieveSecretKey("keys/secret.asc").extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(SendEmail.pass)));
            KeyringManager.createKeyRingCollection(thisPair, "R", "C", "keys/PubKeyCollection");
        } else {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");

            kpg.initialize(1024);

            KeyPair kp = kpg.generateKeyPair();

            FileOutputStream out1 = new FileOutputStream("keys/secret.asc");
            FileOutputStream out2 = new FileOutputStream("keys/pub.asc");

            createKeyPair(out1, out2, kp, "R", SendEmail.pass);

            PGPKeyPair thisPair = new PGPKeyPair(getPubKey("keys/pub.asc"), retrieveSecretKey("keys/secret.asc").extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(SendEmail.pass)));
            //create a new key ring collection for this user
            KeyringManager.createKeyRingCollection(thisPair, "R", "C", "keys/PubKeyCollection");
        }

    }

    /**
     *
     * @param secretKeyStream data stream of secret key to be used to create pair (holds private + public)
     * @param publicKeyStream data stream of public key
     * @param keyPairIn JcaPGPKeyPair to be converted to PGPKeyPair
     * @param name name of keypair identity
     * @param passPhrase password to access
     * @throws IOException
     * @throws InvalidKeyException
     * @throws NoSuchProviderException
     * @throws SignatureException
     * @throws PGPException
     */
    private static void createKeyPair(
            OutputStream secretKeyStream,
            OutputStream publicKeyStream,
            KeyPair keyPairIn,
            String name,
            char[] passPhrase)
            throws IOException, InvalidKeyException, NoSuchProviderException, SignatureException, PGPException {
        secretKeyStream = new ArmoredOutputStream(secretKeyStream);

        PGPDigestCalculator thisCalc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
        PGPKeyPair thisPair = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, keyPairIn, new Date());
        //use default PGP certifcation
        int sigCert = PGPSignature.DEFAULT_CERTIFICATION;
        PGPSignatureSubpacketVector v1 = null;
        PGPSignatureSubpacketVector v2 = null;
        JcaPGPContentSignerBuilder thisCSBuilder = new JcaPGPContentSignerBuilder(thisPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1);
        PBESecretKeyEncryptor thisEncryptor = new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.CAST5, thisCalc).setProvider("BC").build(passPhrase);
        //use contentsignerbuilder and encryptor created above to create secret key
        PGPSecretKey thisKey = new PGPSecretKey(sigCert, thisPair, name, thisCalc, v1, v2,thisCSBuilder ,thisEncryptor );

        //output secret key to stream
        thisKey.encode(secretKeyStream);

        secretKeyStream.close();
        //output public key
        publicKeyStream = new ArmoredOutputStream(publicKeyStream);
        PGPPublicKey key = thisKey.getPublicKey();
        key.encode(publicKeyStream);
        publicKeyStream.close();
    }

    //Get a public key from a file
    static PGPPublicKey getPubKey(String file) throws IOException, PGPException {
        InputStream key = new BufferedInputStream(new FileInputStream(file));
        PGPPublicKey publicKey = getPubKey(key);
        key.close();
        return publicKey;
    }

    //Get a public key from an input stream
    private static PGPPublicKey getPubKey(InputStream in) throws IOException, PGPException {
        JcaKeyFingerprintCalculator thisCalc = new JcaKeyFingerprintCalculator();
        PGPPublicKeyRingCollection pkrc = new PGPPublicKeyRingCollection(
                PGPUtil.getDecoderStream(in), thisCalc);


        Iterator ringIterator = pkrc.getKeyRings();
        //check for valid key
        while (ringIterator.hasNext()) {
            PGPPublicKeyRing keyRing = (PGPPublicKeyRing) ringIterator.next();
            Iterator keyIterator = keyRing.getPublicKeys();
            while (keyIterator.hasNext()) {
                PGPPublicKey key = (PGPPublicKey) keyIterator.next();
                if (key.isEncryptionKey()) {
                    return key;
                }
            }
        }

        throw new IllegalArgumentException("Couldn't find encryption key in key ring.");
    }

    //return a secret key given its file name
    static PGPSecretKey retrieveSecretKey(String file) throws IOException, PGPException {
        InputStream key = new BufferedInputStream(new FileInputStream(file));
        PGPSecretKey secretKey = SignatureManager.retrieveSecretKey(key);
        key.close();
        return secretKey;
    }
}
