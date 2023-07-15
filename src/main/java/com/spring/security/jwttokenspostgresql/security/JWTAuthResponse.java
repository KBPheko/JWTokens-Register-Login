package com.spring.security.jwttokenspostgresql.security;

public class JWTAuthResponse {
    private String token;

    public JWTAuthResponse() {
        this.token = token;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public void setAccessToken(String token) {
        this.token = token;
    }
}
