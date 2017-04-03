import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import javax.mail.*;
import com.sun.mail.imap.IMAPFolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class GetMail {

    public static void main(String[] args) throws IllegalArgumentException, MessagingException, IOException, java.security.NoSuchProviderException, java.lang.InterruptedException {
        Security.addProvider(new BouncyCastleProvider());
        IMAPFolder thisFold = null;
        Store thisStore = null;
        String thisSubject;
        try {
            Properties properties = System.getProperties();
            String protocol = "mail.store.protocol";
            String store = "imaps";
            String hostname = "imap.googlemail.com";
            String desiredFolder = "inbox";
            properties.setProperty(protocol, store);

            Session thisSession = Session.getDefaultInstance(properties, null);

            thisStore = thisSession.getStore(store);
            String username = "redacted";
            String pw = "redacted";
            thisStore.connect(hostname, username,pw);

            thisFold = (IMAPFolder) thisStore.getFolder(desiredFolder);


            if (!thisFold.isOpen()) {
                thisFold.open(Folder.READ_WRITE);
            }
            Message[] allMessages = thisFold.getMessages();
            System.out.println("Total number of messages : " + thisFold.getMessageCount());
            for (int i = allMessages.length - 1; i >= 0; i--) {
                System.out.println("-----------------------------------------------------------------------------");
                System.out.println("Email number " + (i + 1) + ":");
                Message thisMessage = allMessages[i];
                thisSubject = thisMessage.getSubject();
                System.out.println("Date: " + thisMessage.getReceivedDate());
                System.out.println("Subject: " + thisSubject);
                System.out.println("From: " + thisMessage.getFrom()[0]);
                String content = thisMessage.getContent().toString();

                Object thisObj = thisMessage.getContent();
                if (thisObj instanceof Multipart) {
                    Multipart thisContent = (Multipart) thisMessage.getContent();
                    int count = thisContent.getCount();
                    int iterate = 0;
                    while (iterate < count) {

                        Part thisPart = thisContent.getBodyPart(iterate);
                        content = thisPart.getContent().toString();
                        if (!content.contains("<!DOCTYPE html")) {
                            if (content.contains("-----BEGIN PGP SIGNATURE-----")) {
                                String publicKeyCollection = "keys/PubKeyCollection.pkr";
                                PrintWriter out = new PrintWriter("misc/sigtest.txt");
                                out.println(content);
                                out.close();
                                try {
                                    SignatureManager.checkSig("misc/decodemail.txt", "misc/sigtest.txt", publicKeyCollection);
                                } catch (java.security.GeneralSecurityException e) {
                                    e.printStackTrace();
                                } catch (org.bouncycastle.openpgp.PGPException p) {
                                    p.printStackTrace();
                                }

                            } else if (content.contains("-----BEGIN PGP MESSAGE-----")) {
                                try{
                                    decryptPGP(content);
                                }catch(IllegalArgumentException e){
                                    System.out.println("Couldn't find key");
                                    break;
                                }

                            }else{
                                System.out.println("Body: \n" + content);
                            }
                        }
                        iterate++;

                    }
                } else if (content.contains("-----BEGIN PGP MESSAGE-----")) {
                    decryptPGP(content);
                }


                Thread.sleep(100);
            }
        } finally

        {
            if (thisFold != null && thisFold.isOpen()) {
                thisFold.close(true);
            }
            if (thisStore != null) {
                thisStore.close();
            }
        }

    }

    private static void decryptPGP(String content) throws java.io.IOException, java.security.NoSuchProviderException {
        String secretPath = "keys/secret.asc";
        PrintWriter out = new PrintWriter("misc/decodemail.txt");
        out.println(content);
        out.close();
        EncryptionHandler.getDecrypted("misc/decodemail.txt", secretPath, SendEmail.pass, "misc/decodemail.txt");
        System.out.println(Utilities.readFile("misc/decodemail.txt", StandardCharsets.US_ASCII));
    }

}