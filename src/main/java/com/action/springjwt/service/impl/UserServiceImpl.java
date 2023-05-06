package com.action.springjwt.service.impl;

import com.action.springjwt.models.PasswordResetToken;
import com.action.springjwt.models.User;
import com.action.springjwt.payload.request.EmailDetails;
import com.action.springjwt.repository.PasswordResetTokenRepository;
import com.action.springjwt.repository.UserRepository;
import com.action.springjwt.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.mail.Message;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import java.util.Calendar;
import java.util.Optional;
import java.util.Properties;

@Service
public class UserServiceImpl implements UserService {

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private UserRepository userRepo;

    @Autowired
    private PasswordResetTokenRepository passwordResetTokenRepo;

    @Value(value = "${spring.mail.username}")
    private String username;
    @Value(value = "${spring.mail.password}")
    private String password;

    @Override
    public Boolean checkIfValidOldPasswordForUser(User user, String password) {
        return password.equalsIgnoreCase(user.getPassword());
    }

    @Override
    public void changePassword(User user, String newPassword) {
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepo.save(user);
    }

    @Override
    public void createPasswordResetTokenForUser(User user, String token) {
        PasswordResetToken passwordResetToken = new PasswordResetToken(user, token);
        passwordResetTokenRepo.save(passwordResetToken);
    }

    @Override
    public Optional<User> getUserByPasswordResetToken(String token) {
        return Optional.ofNullable(passwordResetTokenRepo.findByToken(token).getUser());
    }

    @Override
    public String validatePasswordResetToken(String token) {
        PasswordResetToken passwordResetToken = passwordResetTokenRepo.findByToken(token);

        if (passwordResetToken == null) {
            return "invalid";
        }
        Calendar cal = Calendar.getInstance();

        if ((passwordResetToken.getExpirationTime().getTime() - cal.getTime().getTime()) <= 0) {
            passwordResetTokenRepo.delete(passwordResetToken);
            return "expired";
        }

        return "Verified";
    }

    @Override
    public String sendEmail(EmailDetails details) {

        // Try block to check for exceptions
        Properties props = new Properties();
        props.put("mail.smtp.auth", true);
        props.put("mail.smtp.starttls.enable", true);
        props.put("mail.smtp.host", "smtp.gmail.com");
        props.put("mail.smtp.port", "587");
        props.put("mail.smtp.ssl.trust", "smtp.gmail.com");

        Session session = Session.getInstance(props, new javax.mail.Authenticator() {
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(username, password);
            }
        });

        try {
            Message message = new MimeMessage(session);
            message.setFrom(new InternetAddress(username));
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(details.getRecipient()));
            message.setSubject(details.getSubject());
            message.setText(details.getMsgBody());
            Transport.send(message);
            System.out.println("Done");
            return "Mail Sent Successfully to the respective client's id => " + details.getRecipient();
        }

        // Catch block to handle the exceptions
        catch (Exception e) {
            return "Error while Sending Mail" + e;
        }
    }
}
