package com.token.autenticacao.config;

import org.springframework.context.annotation.Configuration;

import lombok.Getter;

@Configuration
@Getter
public class JwtConfiguration {

    private String urlLogin = "/login";
    private String prefix = "Bearer ";
    private String header = "Authorization";
    private Long exp = 3600000L;
    private String key = "cX4VBx88Fd7GOuDnxmFurig5pIi7lcOX";
    private String type = "encrypted";
}
