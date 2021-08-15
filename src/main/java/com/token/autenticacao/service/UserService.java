package com.token.autenticacao.service;

import com.token.autenticacao.repository.UserRepository;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService implements UserDetailsService {

    private final UserRepository repo;

    @Override
    public UserDetails loadUserByUsername(String username) {
        log.info("Buscando usuario");
        return repo.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Nenhum usuario encontrado"));
    }

}
