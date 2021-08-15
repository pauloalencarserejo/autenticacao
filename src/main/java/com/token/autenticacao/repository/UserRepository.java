package com.token.autenticacao.repository;

import java.util.Optional;
import java.util.UUID;

import com.token.autenticacao.model.User;

import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, UUID> {

    Optional<User> findByUsername(String username);
}
