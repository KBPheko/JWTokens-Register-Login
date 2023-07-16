package com.spring.security.jwttokenspostgresql.services;

public interface EmailService {
    void sendPasswordResetEmail(String recipientEmail, String resetToken);
}
