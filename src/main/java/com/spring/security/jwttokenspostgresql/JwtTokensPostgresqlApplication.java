package com.spring.security.jwttokenspostgresql;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class JwtTokensPostgresqlApplication {

	public static void main(String[] args) {
		SpringApplication.run(JwtTokensPostgresqlApplication.class, args);
		System.out.print("Server running on port 8001");
	}
}
