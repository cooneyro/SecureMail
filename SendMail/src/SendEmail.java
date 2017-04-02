import com.sun.mail.smtp.SMTPTransport;
import com.sun.xml.internal.messaging.saaj.packaging.mime.MessagingException;

import javax.mail.*;
import javax.mail.internet.*;
import java.security.Security;
import java.util.Date;
import java.util.Properties;

public class SendEmail {
    private SendEmail() {
    }

    public static void main(String [] args) {
        /*
        String recipient = "roberttcooney@gmail.com";
        String sender = "roberttcooney@gmail.com";
        String host = "localhost";

        Properties myProperties = new Properties();
        //myProperties.("mail.smtp.host",host);

        Session thisSession = Session.getInstance(myProperties);

        try{

            MimeMessage thisMessage = new MimeMessage(thisSession);
            thisMessage.setFrom(new InternetAddress(sender));
            thisMessage.addRecipient(Message.RecipientType.TO, new InternetAddress(recipient));

            thisMessage.setSubject("Test message");
            thisMessage.setText("This is the contents of the message");

            Transport.send(thisMessage);

            System.out.println("Sent message successfully");

        }catch (javax.mail.MessagingException e){
            e.printStackTrace();
        }*/

        try{
            Send("roberttcooney","5rGmC5xzEs","roberttcooney@gmail.com","Example title","Example Message Body");
        }catch(javax.mail.internet.AddressException e){
            e.printStackTrace();
        }catch (MessagingException c){
            c.printStackTrace();
        }

    }

    public static void Send(final String username, final String password, String recipientEmail, String title, String message) throws AddressException, MessagingException {
        SendEmail.Send(username, password, recipientEmail, "", title, message);
    }

    /**
     * Send email using GMail SMTP server.
     *
     * @param username       GMail username
     * @param password       GMail password
     * @param recipientEmail TO recipient
     * @param ccEmail        CC recipient. Can be empty if there is no CC recipient
     * @param title          title of the message
     * @param message        message to be sent
     * @throws AddressException   if the email address parse failed
     * @throws MessagingException if the connection is dead or not in the connected state or if the message is not a MimeMessage
     */
    public static void Send(final String username, final String password, String recipientEmail, String ccEmail, String title, String message) throws AddressException, MessagingException {
        Security.addProvider(new com.sun.net.ssl.internal.ssl.Provider());
        final String SSL_FACTORY = "javax.net.ssl.SSLSocketFactory";

        // Get a Properties object
        Properties props = System.getProperties();
        props.setProperty("mail.smtps.host", "smtp.gmail.com");
        props.setProperty("mail.smtp.socketFactory.class", SSL_FACTORY);
        props.setProperty("mail.smtp.socketFactory.fallback", "false");
        props.setProperty("mail.smtp.port", "465");
        props.setProperty("mail.smtp.socketFactory.port", "465");
        props.setProperty("mail.smtps.auth", "true");

        /*
        If set to false, the QUIT command is sent and the connection is immediately closed. If set
        to true (the default), causes the transport to wait for the response to the QUIT command.

        ref :   http://java.sun.com/products/javamail/javadocs/com/sun/mail/smtp/package-summary.html
                http://forum.java.sun.com/thread.jspa?threadID=5205249
                smtpsend.java - demo program from javamail
        */
        props.put("mail.smtps.quitwait", "false");

        Session session = Session.getInstance(props, null);

        // -- Create a new message --
        final MimeMessage msg = new MimeMessage(session);

        try {

            // -- Set the FROM and TO fields --
            msg.setFrom(new InternetAddress(username + "@gmail.com"));
            msg.setRecipients(Message.RecipientType.TO, InternetAddress.parse(recipientEmail, false));

            if (ccEmail.length() > 0) {
                msg.setRecipients(Message.RecipientType.CC, InternetAddress.parse(ccEmail, false));
            }

            msg.setSubject(title);
            msg.setText(message, "utf-8");
            msg.setSentDate(new Date());

            SMTPTransport t = (SMTPTransport) session.getTransport("smtps");

            t.connect("smtp.gmail.com", username, password);
            t.sendMessage(msg, msg.getAllRecipients());
            t.close();
        } catch (javax.mail.MessagingException e) {
            e.printStackTrace();
        }
    }
}
