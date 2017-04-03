import com.sun.mail.smtp.SMTPTransport;
import com.sun.xml.internal.messaging.saaj.packaging.mime.MessagingException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.activation.DataHandler;
import javax.activation.DataSource;
import javax.activation.FileDataSource;
import javax.mail.*;
import javax.mail.internet.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Date;
import java.util.Properties;

import static java.nio.charset.StandardCharsets.US_ASCII;

public class SendEmail {
    static char[] pass = {'C'};

    private SendEmail() {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws java.lang.Exception {

        Security.addProvider(new BouncyCastleProvider());



        Security.addProvider(new BouncyCastleProvider());
        String fileName = "sendmail/SendingMail.txt";
        String sigOutputFileName = "misc/sig.txt";
        //String outputFileName = "output.txt";
        String secretPath = "keys/secret.asc";
        File output = new File(sigOutputFileName);
        File secret = new File(secretPath);
        output.createNewFile();
        String id = "H";
        //InputStream streamIn = new FileInputStream(secret);
        //OutputStream streamOut = new FileOutputStream(output,false);


        SignatureManager.createSignature(fileName,secretPath,sigOutputFileName,pass);


        String publicPath = "keys/PubKeyCollection.pkr";


        String encryptedOutputFileName = "misc/output.txt";
        File output2 = new File(encryptedOutputFileName);
        output2.createNewFile();
        EncryptionHandler.getEncrypted(encryptedOutputFileName, fileName, publicPath,id);

        Thread.sleep(500);

        String message = Utilities.readFile(encryptedOutputFileName,US_ASCII);

        try{
            Send("redacted","redacted","testaccrc@gmail.com","Example title",message);
        }catch(javax.mail.internet.AddressException e){
            e.printStackTrace();
        }catch (MessagingException c){
            c.printStackTrace();
        }


    }



    private static void Send(final String user, final String pw, String recipient, String emailTitle, String body) throws AddressException, MessagingException, javax.mail.MessagingException{
        SendEmail.Send(user, pw, recipient, "", emailTitle, body);
    }

    private static void Send(final String username, final String password, String recipientEmail, String ccEmail, String title, String message) throws AddressException, MessagingException, javax.mail.MessagingException {
        Security.addProvider(new com.sun.net.ssl.internal.ssl.Provider());
        final String FACTORY = "javax.net.ssl.SSLSocketFactory";

        Properties properties = System.getProperties();
        properties.setProperty("mail.smtps.host", "smtp.gmail.com");
        properties.setProperty("mail.smtp.socketFactory.class", FACTORY);
        properties.setProperty("mail.smtp.socketFactory.fallback", "false");
        properties.setProperty("mail.smtp.port", "465");
        properties.setProperty("mail.smtp.socketFactory.port", "465");
        properties.setProperty("mail.smtps.auth", "true");
        properties.put("mail.smtps.quitwait", "false");

        Session session = Session.getInstance(properties, null);

        // -- Create a new message --
        Multipart multipart = new MimeMultipart();

        final MimeMessage msg = new MimeMessage(session);

        try {

            // -- Set the FROM and TO fields --
            msg.setFrom(new InternetAddress(username + "@gmail.com"));
            msg.setRecipients(Message.RecipientType.TO, InternetAddress.parse(recipientEmail, false));

            if (ccEmail.length() > 0) {
                msg.setRecipients(Message.RecipientType.CC, InternetAddress.parse(ccEmail, false));
            }

            msg.setSubject(title);
            BodyPart messageBodyPart = new MimeBodyPart();
            messageBodyPart.setText(message);
            multipart.addBodyPart(messageBodyPart);

            BodyPart attachmentPart = new MimeBodyPart();
            String filename = "misc/sig.txt";
            DataSource source = new FileDataSource(filename);
            attachmentPart.setDataHandler(new DataHandler(source));
            attachmentPart.setFileName(filename);
            multipart.addBodyPart(attachmentPart);

            //msg.setText(message, "utf-8");
            msg.setSentDate(new Date());

            msg.setContent(multipart);
            SMTPTransport t = (SMTPTransport) session.getTransport("smtps");

            t.connect("smtp.gmail.com", username, password);
            t.sendMessage(msg, msg.getAllRecipients());
            t.close();
        } catch (javax.mail.MessagingException e) {
            e.printStackTrace();
        }
    }



}
