package com.spring.security.jwttokenspostgresql.controller;

import com.spring.security.jwttokenspostgresql.logindto.LoginDto;
import com.spring.security.jwttokenspostgresql.models.User;
import com.spring.security.jwttokenspostgresql.registerdto.RegistrationDto;
import com.spring.security.jwttokenspostgresql.repositories.UserRepository;
import com.spring.security.jwttokenspostgresql.security.JWTAuthResponse;
import com.spring.security.jwttokenspostgresql.services.AuthService;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@AllArgsConstructor
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private AuthService authService;

    @Autowired
    UserRepository userRepository;

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegistrationDto registrationDto){
        authService.register(registrationDto);
        return ResponseEntity.ok("Registration successful");
    }

    // Build Login REST API
    @PostMapping("/login")
    public ResponseEntity<JWTAuthResponse> authenticate(@RequestBody LoginDto loginDto){
        String token = authService.login(loginDto);

        JWTAuthResponse jwtAuthResponse = new JWTAuthResponse();
        jwtAuthResponse.setAccessToken(token);

        return ResponseEntity.ok(jwtAuthResponse);
    }

    //Forgot Password
    @PostMapping("/forgot-password")
    public ResponseEntity<?> forgotPassword(@RequestParam("email") String email) {
        authService.initiatePasswordReset(email);
        return ResponseEntity.ok("Password reset initiated");
    }

    @PostMapping("/reset-password")
    public ResponseEntity<?> resetPassword(@RequestParam("resetToken") String resetToken,
                                           @RequestParam("newPassword") String newPassword) {
        authService.resetPassword(resetToken, newPassword);
        return ResponseEntity.ok("Password reset successfully");
    }
}