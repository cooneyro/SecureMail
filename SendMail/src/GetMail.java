import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import javax.mail.*;

import com.sun.mail.imap.IMAPFolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class FolderFetchIMAP {

    public static void main(String[] args) throws MessagingException, IOException, java.security.NoSuchProviderException {
        IMAPFolder folder = null;
        Security.addProvider(new BouncyCastleProvider());
        Store store = null;
        String subject;
        try {
            Properties props = System.getProperties();
            props.setProperty("mail.store.protocol", "imaps");

            Session session = Session.getDefaultInstance(props, null);

            store = session.getStore("imaps");
            store.connect("imap.googlemail.com", "testaccrc@gmail.com", "testingaccount");

            //folder = (IMAPFolder) store.getFolder("[Gmail]/Spam"); // This doesn't work for other email account
            folder = (IMAPFolder) store.getFolder("inbox"); //This works for both email account


            if (!folder.isOpen())
                folder.open(Folder.READ_WRITE);
            Message[] messages = folder.getMessages();
            System.out.println("No of Messages : " + folder.getMessageCount());
            System.out.println("No of Unread Messages : " + folder.getUnreadMessageCount());
            System.out.println(messages.length);
            for (int i = messages.length - 1; i >= 0; i--) {

                System.out.println("*****************************************************************************");
                System.out.println("MESSAGE " + (i + 1) + ":");
                Message msg = messages[i];

                subject = msg.getSubject();

                System.out.println("Subject: " + subject);
                System.out.println("From: " + msg.getFrom()[0]);
                System.out.println("To: " + msg.getAllRecipients()[0]);
                System.out.println("Date: " + msg.getReceivedDate());
                String content = msg.getContent().toString();

                Object thisObj = msg.getContent();
                if (thisObj instanceof Multipart) {
                    Multipart thisContent = (Multipart) msg.getContent();
                    int count = thisContent.getCount();
                    int iterate = 0;
                    while (iterate < count) {

                        Part thisPart = thisContent.getBodyPart(iterate);
                        content = thisPart.getContent().toString();
                        if (!content.contains("<!DOCTYPE html")) {
                            if (content.contains("-----BEGIN PGP SIGNATURE-----")) {
                                String publicKeyCollection = "PubKeyCollection.pkr";
                                PrintWriter out = new PrintWriter("sigtest.txt");
                                out.println(content);
                                out.close();
                                try {
                                    SignatureManager.checkSig("decodemail.txt", "sigtest.txt", publicKeyCollection);
                                } catch (java.security.GeneralSecurityException e) {
                                    e.printStackTrace();
                                } catch (org.bouncycastle.openpgp.PGPException p) {
                                    p.printStackTrace();
                                }

                            } else if (content.contains("-----BEGIN PGP MESSAGE-----")) {
                                decryptPGP(content);
                            }else{
                                System.out.println("Body: \n" + content);
                            }
                        }
                        iterate++;

                    }
                } else if (content.contains("-----BEGIN PGP MESSAGE-----")) {
                    decryptPGP(content);
                }



            }
        } finally

        {
            if (folder != null && folder.isOpen()) {
                folder.close(true);
            }
            if (store != null) {
                store.close();
            }
        }

    }

    private static void decryptPGP(String content) throws java.io.FileNotFoundException, java.io.IOException, java.security.NoSuchProviderException {
        String secretPath = "secret.asc";
        PrintWriter out = new PrintWriter("decodemail.txt");
        out.println(content);
        out.close();
        KeyBasedFileProcessor.decryptFile("decodemail.txt", secretPath, SendEmail.pass, "decodemail.txt");
        System.out.println(Utils.readFile("decodemail.txt", StandardCharsets.US_ASCII));
    }


}