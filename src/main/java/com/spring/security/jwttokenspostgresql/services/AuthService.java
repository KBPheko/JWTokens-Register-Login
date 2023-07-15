package com.spring.security.jwttokenspostgresql.services;

import com.spring.security.jwttokenspostgresql.logindto.LoginDto;
import com.spring.security.jwttokenspostgresql.registerdto.RegistrationDto;

public interface AuthService {
    String login(LoginDto loginDto);
    void register(RegistrationDto registrationDto);
}
