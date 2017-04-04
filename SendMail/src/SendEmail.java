import com.sun.mail.smtp.SMTPTransport;
import com.sun.xml.internal.messaging.saaj.packaging.mime.MessagingException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.activation.DataHandler;
import javax.activation.DataSource;
import javax.activation.FileDataSource;
import javax.mail.*;
import javax.mail.internet.*;
import java.io.*;
import java.security.Security;
import java.util.Date;
import java.util.Properties;

import static java.nio.charset.StandardCharsets.US_ASCII;

//for sending emails
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
        String secretPath = "keys/secret.asc";
        File output = new File(sigOutputFileName);
        output.createNewFile();
        String id = "R";

        //create signature to be attached to email
        SignatureManager.createSignature(fileName,secretPath,sigOutputFileName,pass);


        String publicPath = "keys/PubKeyCollection.pkr";

        //encrypt body of message
        String encryptedOutputFileName = "misc/output.txt";
        File output2 = new File(encryptedOutputFileName);
        output2.createNewFile();
        EncryptionHandler.getEncrypted(encryptedOutputFileName, fileName, publicPath,id);

        Thread.sleep(500);

        String message = Utilities.readFile(encryptedOutputFileName,US_ASCII);

        try{ //enter sender's google username and password below
            send("redacted","redacted","testaccrc@gmail.com","Example title",message);
        }catch(javax.mail.internet.AddressException e){
            e.printStackTrace();
        }catch (MessagingException c){
            c.printStackTrace();
        }


    }


    private static void send(final String user, final String pw, String recipient, String emailTitle, String body) throws AddressException, MessagingException, javax.mail.MessagingException{
        SendEmail.send(user, pw, recipient, "", emailTitle, body);
    }

    /**
     *
     * @param user User's google username
     * @param pw User's google password
     * @param recipient Recipient of email
     * @param cc Extra recipients to be emailed carbon copies
     * @param emailTitle Title of email
     * @param body Body of email
     * @throws AddressException
     * @throws MessagingException
     * @throws javax.mail.MessagingException
     */
    private static void send(final String user, final String pw, String recipient, String cc, String emailTitle, String body) throws AddressException, MessagingException, javax.mail.MessagingException {
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

        //create multipart message
        Multipart multipart = new MimeMultipart();

        final MimeMessage msg = new MimeMessage(session);

        try {

            // set sender and recipient of email
            msg.setFrom(new InternetAddress(user + "@gmail.com"));
            msg.setRecipients(Message.RecipientType.TO, InternetAddress.parse(recipient, false));

            if (cc.length() > 0) {
                msg.setRecipients(Message.RecipientType.CC, InternetAddress.parse(cc, false));
            }

            msg.setSubject(emailTitle);
            BodyPart messageBodyPart = new MimeBodyPart();
            messageBodyPart.setText(body);
            multipart.addBodyPart(messageBodyPart);

            BodyPart attachmentPart = new MimeBodyPart();
            String filename = "misc/sig.txt";
            DataSource source = new FileDataSource(filename);
            attachmentPart.setDataHandler(new DataHandler(source));
            attachmentPart.setFileName(filename);
            multipart.addBodyPart(attachmentPart);

            msg.setSentDate(new Date());

            msg.setContent(multipart);
            SMTPTransport transporter = (SMTPTransport) session.getTransport("smtps");

            transporter.connect("smtp.gmail.com", user, pw);
            transporter.sendMessage(msg, msg.getAllRecipients());
            transporter.close();
        } catch (javax.mail.MessagingException e) {
            e.printStackTrace();
        }
    }



}
