package com.spring.security.jwttokenspostgresql.repositories;

import com.spring.security.jwttokenspostgresql.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
@EnableJpaRepositories("com.spring.security.jwttokenspostgresql.repositories")
public interface RoleRepository extends JpaRepository<Role, Long> {

    Optional<Role> findByName(String name);

}
