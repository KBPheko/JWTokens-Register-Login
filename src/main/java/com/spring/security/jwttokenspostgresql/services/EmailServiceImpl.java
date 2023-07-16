package com.spring.security.jwttokenspostgresql.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailServiceImpl implements EmailService{
    @Value("${spring.mail.username}")
    private String senderEmail;

    @Autowired
    private JavaMailSender mailSender;

    @Override
    public void sendPasswordResetEmail(String recipientEmail, String resetToken) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setFrom(senderEmail);
        message.setTo(recipientEmail);
        message.setSubject("Password Reset");
        message.setText("To reset your password, please click the following link: " +
                "http://your-domain.com/reset-password?token=" + resetToken);

        mailSender.send(message);
    }
}
