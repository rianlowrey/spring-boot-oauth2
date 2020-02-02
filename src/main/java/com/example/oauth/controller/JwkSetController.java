package com.example.oauth.controller;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.provider.endpoint.FrameworkEndpoint;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@FrameworkEndpoint
public class JwkSetController {

    @Autowired
    private KeyPair keyPair;

    @GetMapping("/.well-known/jwks.json")
    @ResponseBody
    public Map<String, Object> getJWKs() {
        RSAPublicKey publicKey = (RSAPublicKey) this.keyPair.getPublic();

        RSAKey rsaKey = new RSAKey.Builder(publicKey).build();

        return new JWKSet(rsaKey).toJSONObject();
    }
}
