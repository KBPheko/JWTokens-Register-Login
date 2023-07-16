package com.spring.security.jwttokenspostgresql.services;

import com.spring.security.jwttokenspostgresql.logindto.LoginDto;
import com.spring.security.jwttokenspostgresql.registerdto.RegistrationDto;

public interface AuthService {
    //Login DTO
    String login(LoginDto loginDto);

    //Register DTO
    void register(RegistrationDto registrationDto);

    //Forgot Password / Reset Password
    void initiatePasswordReset(String email);

    void resetPassword(String resetToken, String newPassword);
}
