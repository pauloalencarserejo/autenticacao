package com.token.autenticacao.config;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.UUID;
import java.util.stream.Collectors;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.token.autenticacao.model.User;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class TokenService {

    private final JwtConfiguration jwtConfiguration;

    @SneakyThrows
    public String createToken(Authentication auth) {
        SignedJWT signedJwt = createSignedJWT(auth);
        return encryptedToken(signedJwt);
    }

    @SneakyThrows
    private SignedJWT createSignedJWT(Authentication auth) {
        User user = (User) auth.getPrincipal();

        JWTClaimsSet claimsSet = createClaims(auth, user);
        KeyPair keyPair = generateKeyPair();

        JWK jwk = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic()).keyID(UUID.randomUUID().toString()).build();

        SignedJWT signedJWT = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).jwk(jwk).type(JOSEObjectType.JWT).build(), claimsSet);

        RSASSASigner signer = new RSASSASigner(keyPair.getPrivate());

        signedJWT.sign(signer);

        log.info("Token serializado assinado {} ", signedJWT.serialize());

        return signedJWT;
    }

    private JWTClaimsSet createClaims(Authentication auth, User user) {
        return new JWTClaimsSet.Builder().subject(user.getUsername())
                .claim("authorities",
                        auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList()))
                .issueTime(new Date()).expirationTime(new Date(System.currentTimeMillis() + jwtConfiguration.getExp()))
                .build();
    }

    @SneakyThrows
    private KeyPair generateKeyPair() {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.genKeyPair();
    }

    private String encryptedToken(SignedJWT signedJWT) throws JOSEException {

        DirectEncrypter encrypter = new DirectEncrypter(jwtConfiguration.getKey().getBytes());

        JWEObject jweObject = new JWEObject(
                new JWEHeader.Builder(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256).contentType("JWT").build(),
                new Payload(signedJWT));

        jweObject.encrypt(encrypter);
        return jweObject.serialize();
    }

}
