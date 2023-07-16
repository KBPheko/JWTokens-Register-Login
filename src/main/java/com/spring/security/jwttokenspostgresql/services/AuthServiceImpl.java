package com.spring.security.jwttokenspostgresql.services;

import com.spring.security.jwttokenspostgresql.component.JwtTokenProvider;
import com.spring.security.jwttokenspostgresql.logindto.LoginDto;
import com.spring.security.jwttokenspostgresql.models.Role;
import com.spring.security.jwttokenspostgresql.models.User;
import com.spring.security.jwttokenspostgresql.registerdto.RegistrationDto;
import com.spring.security.jwttokenspostgresql.repositories.RoleRepository;
import com.spring.security.jwttokenspostgresql.repositories.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
public class AuthServiceImpl implements AuthService{

    private AuthenticationManager authenticationManager;
    private UserRepository userRepository;
    private RoleRepository roleRepository;
    private PasswordEncoder passwordEncoder;
    private JwtTokenProvider jwtTokenProvider;
    private final EmailService emailService;



    public AuthServiceImpl(
            JwtTokenProvider jwtTokenProvider,
            UserRepository userRepository,
            RoleRepository roleRepository,
            PasswordEncoder passwordEncoder,
            AuthenticationManager authenticationManager,
            EmailService emailService) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenProvider = jwtTokenProvider;
        this.emailService = emailService;
    }

    @Override
    public String login(LoginDto loginDto) {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                loginDto.getUsernameOrEmail(), loginDto.getPassword()));

        SecurityContextHolder.getContext().setAuthentication(authentication);

        String token = jwtTokenProvider.generateToken(authentication);

        return token;
    }

    @Override
    public void register(RegistrationDto registrationDto) {
        // Create a new user entity and set the necessary details
        User user = new User();
        user.setUsername(registrationDto.getUsername());
        user.setEmail(registrationDto.getEmail());
        user.setName(registrationDto.getName());
        // Encode the password before saving
        String encodedPassword = passwordEncoder.encode(registrationDto.getPassword());
        user.setPassword(encodedPassword);

        // Assign the role "ROLE_USER"
        Optional<Role> optionalRole = roleRepository.findByName("ROLE_USER");
        Role userRole = optionalRole.orElseThrow(() -> new IllegalStateException("Role not found"));
        Set<Role> roles = new HashSet<>();
        roles.add(userRole);
        user.setRoles(roles);

        // Save the new user to the database
        userRepository.save(user);
    }

    @Override
    public void initiatePasswordReset(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("Email Not Found"));

        // Generate a password reset token (e.g., UUID)
        String resetToken = UUID.randomUUID().toString();

        // Save the reset token to the user entity
        user.setResetToken(resetToken);
        userRepository.save(user);

        // Send the password reset email to the user with the reset token
        emailService.sendPasswordResetEmail(user.getEmail(), resetToken);
    }

    @Override
    public void resetPassword(String resetToken, String newPassword) {
        User user = userRepository.findByResetToken(resetToken)
                .orElseThrow(() -> new IllegalArgumentException("Invalid reset token"));

        // Set the new password and clear the reset token
        String encodedPassword = passwordEncoder.encode(newPassword);
        user.setPassword(encodedPassword);
        user.setResetToken(null);
        userRepository.save(user);
    }
}
