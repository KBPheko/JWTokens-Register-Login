package com.spring.security.jwttokenspostgresql.repositories;

import com.spring.security.jwttokenspostgresql.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<Role, Long> {

    Optional<Role> findByName(String name);

}
